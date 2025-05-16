from bottle import Bottle, run, static_file, request, response, template
import os
import json
from ssl_checker import get_cert_info

app = Bottle()

# Statische Dateien (CSS, JS)
@app.route('/static/<filename:path>')
def serve_static(filename):
    return static_file(filename, root='./static')

# Hauptseite
@app.route('/')
def index():
    return template('views/index.html')

# API-Endpunkt für SSL-Prüfung
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
        result = get_cert_info(url)
        
        # Content-Type setzen
        response.content_type = 'application/json'
        return json.dumps(result)
        
    except Exception as e:
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

