import asyncio
import concurrent.futures
import datetime
import json
import uuid
import logging
import time
from services.ssl_checker import SSLCheckerService

# Konfiguration für den Logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('batch_service')

class BatchService:
    def __init__(self, repository, ssl_checker=None, max_workers=10):
        self.repository = repository
        self.ssl_checker = ssl_checker or SSLCheckerService(repository)
        self.max_workers = max_workers
    
    def create_batch_job(self, domains):
        """Erstellt einen neuen Batch-Job und gibt die Batch-ID zurück"""
        # Bereinige die Domains-Liste (entferne Duplikate und leere Einträge)
        unique_domains = list(set(domain.strip() for domain in domains if domain.strip()))
        
        if not unique_domains:
            raise ValueError("Keine gültigen Domains in der Liste")
        
        # Erstelle einen neuen Batch-Job in der Datenbank
        batch_id = self.repository.create_batch_job(unique_domains)
        
        # Starte asynchrone Verarbeitung des Batches
        asyncio.create_task(self._process_batch_async(unique_domains, batch_id))
        
        return {
            'batch_id': batch_id,
            'domains': unique_domains,
            'count': len(unique_domains)
        }
    
    async def _process_batch_async(self, domains, batch_id):
        """Verarbeitet einen Batch von Domains asynchron"""
        logger.info(f"Starte Batch-Verarbeitung für {len(domains)} Domains (Batch-ID: {batch_id})")
        
        # Verwende einen ThreadPoolExecutor für die parallele Verarbeitung
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Erstelle Future-Objekte für alle Domains
            loop = asyncio.get_event_loop()
            futures = [
                loop.run_in_executor(
                    executor,
                    self.ssl_checker.check_domain,
                    domain,
                    batch_id
                )
                for domain in domains
            ]
            
            # Warte auf Abschluss aller Futures
            for future in asyncio.as_completed(futures):
                try:
                    result = await future
                    logger.debug(f"Domain verarbeitet: {result.get('hostname', 'Unbekannt')}")
                except Exception as e:
                    logger.error(f"Fehler bei der Batch-Verarbeitung: {str(e)}")
        
        logger.info(f"Batch-Verarbeitung abgeschlossen für Batch-ID: {batch_id}")
    
    def get_batch_status(self, batch_id):
        """Ruft den Status eines Batch-Jobs ab"""
        # Hole Batch-Informationen aus der Datenbank
        batch_info = self.repository.get_batch_info(batch_id)
        
        if not batch_info:
            return None
        
        # Berechne Fortschritt
        progress = 0
        if batch_info['total_domains'] > 0:
            progress = (batch_info['completed_domains'] / batch_info['total_domains']) * 100
        
        # Hole Ergebnisse, falls der Batch abgeschlossen ist
        results = []
        summary = None
        
        if batch_info['status'] == 'completed':
            results = self.repository.get_batch_results(batch_id)
            summary = self._generate_summary(results)
        
        return {
            'batch_id': batch_id,
            'created_at': batch_info['created_at'],
            'status': batch_info['status'],
            'total_domains': batch_info['total_domains'],
            'completed_domains': batch_info['completed_domains'],
            'progress': progress,
            'results': results,
            'summary': summary
        }
    
    def _generate_summary(self, results):
        """Generiert eine Zusammenfassung aus den Batch-Ergebnissen"""
        if not results:
            return None
        
        summary = {
            'total': len(results),
            'success': sum(1 for r in results if r.get('success', 0) == 1),
            'hostname_valid': sum(1 for r in results if r.get('hostname_valid', 0) == 1),
            'chain_valid': sum(1 for r in results if r.get('chain_valid', 0) == 1),
            'expiry_status': {
                'ok': 0,
                'warning': 0,
                'critical': 0,
                'expired': 0,
                'unknown': 0
            }
        }
        
        # Zähle Ablaufstatus
        for result in results:
            days_left = result.get('days_left')
            if days_left is None:
                summary['expiry_status']['unknown'] += 1
            elif days_left < 0:
                summary['expiry_status']['expired'] += 1
            elif days_left <= 30:
                summary['expiry_status']['critical'] += 1
            elif days_left <= 90:
                summary['expiry_status']['warning'] += 1
            else:
                summary['expiry_status']['ok'] += 1
        
        return summary