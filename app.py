from bottle import Bottle, run, static_file, request, response, template
import os
import json
import asyncio
import sys
import logging
from db.repository import SSLResultRepository
from db.models import Database
from services.ssl_checker import SSLCheckerService
from services.batch_service import BatchService

# Konfiguration für den Logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('app')

# Überprüfe, ob asyncio auf Windows läuft und konfiguriere den Event-Loop entsprechend
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

app = Bottle()

# Initialisiere Datenbank und Repositories
db = Database('ssl_checks.db')
ssl_result_repository = SSLResultRepository(db)

# Initialisiere Services
ssl_checker_service = SSLCheckerService(ssl_result_repository)
batch_service = BatchService(ssl_result_repository, ssl_checker_service)

# Statische Dateien (CSS, JS)
@app.route('/static/<filename:path>')
def serve_static(filename):
    return static_file(filename, root='./static')

# Hauptseite
@app.route('/')
def index():
    return template('views/index.html')

# Batch-Seite
@app.route('/batch')
def batch_page():
    return template('views/batch.html')

# API-Endpunkt für einzelne SSL-Prüfung
@app.route('/api/check-ssl', method='POST')
def check_ssl():
    try:
        data = request.json
        if not data or 'url' not in data:
            response.status = 400
            return json.dumps({
                'success': False,
                'error': 'URL not provided'
            })
        
        url = data['url']
        result = ssl_checker_service.check_domain(url)
        
        # Content-Type setzen
        response.content_type = 'application/json'
        return json.dumps({
            'success': True,
            'data': result
        })
        
    except Exception as e:
        logger.error(f"Fehler bei der API-Anfrage für check-ssl: {str(e)}")
        response.status = 500
        return json.dumps({
            'success': False,
            'error': str(e)
        })

# API-Endpunkt für Batch-Prüfung starten
@app.route('/api/batch', method='POST')
def start_batch():
    try:
        data = request.json
        if not data or not data.get('domains'):
            response.status = 400
            return json.dumps({
                'success': False,
                'error': 'Keine Domains angegeben'
            })
        
        domains = data['domains']
        if isinstance(domains, str):
            # Wenn Domains als String übergeben wurden, teile sie nach Zeilen auf
            domains = [d.strip() for d in domains.splitlines() if d.strip()]
        
        batch_job = batch_service.create_batch_job(domains)
        
        response.content_type = 'application/json'
        return json.dumps({
            'success': True,
            'batch_id': batch_job['batch_id'],
            'count': batch_job['count'],
            'domains': batch_job['domains']
        })
        
    except Exception as e:
        logger.error(f"Fehler bei der API-Anfrage für batch: {str(e)}")
        response.status = 500
        return json.dumps({
            'success': False,
            'error': str(e)
        })

# API-Endpunkt für Batch-Status abrufen
@app.route('/api/batch/<batch_id>', method='GET')
def get_batch_status(batch_id):
    try:
        batch_status = batch_service.get_batch_status(batch_id)
        
        if not batch_status:
            response.status = 404
            return json.dumps({
                'success': False,
                'error': 'Batch nicht gefunden'
            })
        
        response.content_type = 'application/json'
        return json.dumps({
            'success': True,
            'data': batch_status
        })
        
    except Exception as e:
        logger.error(f"Fehler bei der API-Anfrage für batch/{batch_id}: {str(e)}")
        response.status = 500
        return json.dumps({
            'success': False,
            'error': str(e)
        })

# API-Endpunkt für CSV-Export eines Batches
@app.route('/api/batch/<batch_id>/export/csv', method='GET')
def export_batch_csv(batch_id):
    try:
        batch_status = batch_service.get_batch_status(batch_id)
        
        if not batch_status or not batch_status.get('results'):
            response.status = 404
            return json.dumps({
                'success': False,
                'error': 'Batch nicht gefunden oder keine Ergebnisse vorhanden'
            })
        
        # CSV-Header
        csv_data = "Domain,Erfolg,Hostname-Gültig,Chain-Gültig,Verbleibende Tage,Common Name,Ablaufstatus\n"
        
        # CSV-Zeilen für jedes Ergebnis
        for result in batch_status['results']:
            result_json = json.loads(result['result_json'])
            
            csv_data += f"{result['domain']},"
            csv_data += f"{result['success']},"
            csv_data += f"{result['hostname_valid']},"
            csv_data += f"{result['chain_valid']},"
            csv_data += f"{result_json.get('days_left', 'N/A')},"
            csv_data += f"\"{result_json.get('common_name', 'N/A')}\","
            csv_data += f"{result_json.get('expiry_status', 'UNBEKANNT')}\n"
        
        # Response als CSV-Download
        response.content_type = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename="ssl_check_batch_{batch_id}.csv"'
        return csv_data
        
    except Exception as e:
        logger.error(f"Fehler bei der API-Anfrage für batch/{batch_id}/export/csv: {str(e)}")
        response.status = 500
        return json.dumps({
            'success': False,
            'error': str(e)
        })

# Health-Check Endpunkt
@app.route('/health')
def health():
    response.content_type = 'application/json'
    return json.dumps({'status': 'ok'})

# Server starten (wenn direkt ausgeführt)
if __name__ == '__main__':
    # Host und Port aus Umgebungsvariablen oder Standardwerte
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 8080))
    
    run(app, host=host, port=port, reloader=True)