import json
import uuid
from datetime import datetime
from db.models import Database

class SSLResultRepository:
    def __init__(self, database=None):
        self.db = database or Database()
    
    def save_result(self, domain, success, result_data, batch_id=None):
        """Speichert ein SSL-Prüfungsergebnis in der Datenbank"""
        with self.db.get_connection() as conn:
            # Extrahiere relevante Werte aus dem Ergebnis
            hostname_valid = 1 if result_data.get('hostname_valid', False) else 0
            chain_valid = 1 if result_data.get('chain_valid', False) else 0
            days_left = result_data.get('days_left')
            
            # Als JSON speichern
            result_json = json.dumps(result_data)
            
            # In DB einfügen oder aktualisieren
            conn.execute(
                '''
                INSERT OR REPLACE INTO ssl_results 
                (domain, batch_id, timestamp, success, hostname_valid, chain_valid, days_left, result_json) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    domain, 
                    batch_id, 
                    datetime.now().isoformat(), 
                    1 if success else 0,
                    hostname_valid,
                    chain_valid,
                    days_left,
                    result_json
                )
            )
            
            # Wenn Teil eines Batches, aktualisiere den Zähler
            if batch_id:
                conn.execute(
                    'UPDATE batch_jobs SET completed_domains = completed_domains + 1 WHERE id = ?',
                    (batch_id,)
                )
                
                # Prüfe, ob alle Domains im Batch verarbeitet wurden
                cursor = conn.execute(
                    'SELECT completed_domains, total_domains FROM batch_jobs WHERE id = ?',
                    (batch_id,)
                )
                batch_data = cursor.fetchone()
                
                if batch_data and batch_data['completed_domains'] >= batch_data['total_domains']:
                    conn.execute(
                        'UPDATE batch_jobs SET status = ? WHERE id = ?',
                        ('completed', batch_id)
                    )
    
    def get_result(self, domain, batch_id=None):
        """Ruft ein einzelnes Ergebnis ab"""
        with self.db.get_connection() as conn:
            query = 'SELECT * FROM ssl_results WHERE domain = ?'
            params = [domain]
            
            if batch_id:
                query += ' AND batch_id = ?'
                params.append(batch_id)
            
            cursor = conn.execute(query, params)
            return cursor.fetchone()
    
    def get_batch_results(self, batch_id):
        """Ruft alle Ergebnisse für einen Batch-Job ab"""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                'SELECT * FROM ssl_results WHERE batch_id = ? ORDER BY domain',
                (batch_id,)
            )
            return cursor.fetchall()
    
    def get_batch_info(self, batch_id):
        """Ruft Informationen über einen Batch-Job ab"""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                'SELECT * FROM batch_jobs WHERE id = ?',
                (batch_id,)
            )
            return cursor.fetchone()
    
    def create_batch_job(self, domains):
        """Erstellt einen neuen Batch-Job"""
        batch_id = str(uuid.uuid4())
        
        with self.db.get_connection() as conn:
            conn.execute(
                'INSERT INTO batch_jobs (id, created_at, total_domains, status) VALUES (?, ?, ?, ?)',
                (batch_id, datetime.now().isoformat(), len(domains), 'pending')
            )
        
        return batch_id
    
    def get_summary_stats(self):
        """Ruft zusammenfassende Statistiken aller Prüfungen ab"""
        with self.db.get_connection() as conn:
            stats = {}
            
            # Gesamtzahl geprüfter Domains
            cursor = conn.execute('SELECT COUNT(DISTINCT domain) as total FROM ssl_results')
            stats['total_domains'] = cursor.fetchone()['total']
            
            # Anzahl erfolgreicher Prüfungen
            cursor = conn.execute('SELECT COUNT(*) as count FROM ssl_results WHERE success = 1')
            stats['successful_checks'] = cursor.fetchone()['count']
            
            # Anzahl gültiger Hostname-Validierungen
            cursor = conn.execute('SELECT COUNT(*) as count FROM ssl_results WHERE hostname_valid = 1')
            stats['valid_hostnames'] = cursor.fetchone()['count']
            
            # Anzahl gültiger Zertifikatsketten
            cursor = conn.execute('SELECT COUNT(*) as count FROM ssl_results WHERE chain_valid = 1')
            stats['valid_chains'] = cursor.fetchone()['count']
            
            # Domains mit kritischer Ablaufzeit (< 30 Tage)
            cursor = conn.execute('SELECT COUNT(*) as count FROM ssl_results WHERE days_left < 30 AND days_left >= 0')
            stats['critical_expiry'] = cursor.fetchone()['count']
            
            # Abgelaufene Zertifikate
            cursor = conn.execute('SELECT COUNT(*) as count FROM ssl_results WHERE days_left < 0')
            stats['expired'] = cursor.fetchone()['count']
            
            return stats