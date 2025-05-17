import asyncio
import functools
import concurrent.futures
import logging

# Konfiguration für den Logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('async_utils')

def to_async(func):
    """
    Dekorator zum Ausführen einer synchronen Funktion in einem Executor.
    Nützlich zum Konvertieren blockierender Operationen für asynchronen Kontext.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, 
            functools.partial(func, *args, **kwargs)
        )
    return wrapper

async def run_in_batches(iterable, batch_size, func, *args, **kwargs):
    """
    Führt eine Funktion für Batches von Elementen in einem Iterable aus.
    Hilfreich für die Verarbeitung großer Listen mit begrenzter Parallelität.
    
    Args:
        iterable: Iterable mit zu verarbeitenden Elementen
        batch_size: Anzahl gleichzeitig zu verarbeitender Elemente
        func: Asynchrone Funktion, die auf jedes Element angewendet wird
        *args, **kwargs: Zusätzliche Argumente für die Funktion
        
    Returns:
        Liste der Ergebnisse
    """
    tasks = []
    results = []
    
    for i, item in enumerate(iterable):
        task = asyncio.create_task(func(item, *args, **kwargs))
        tasks.append(task)
        
        # Wenn der aktuelle Batch voll ist oder wir am Ende der Liste sind
        if len(tasks) >= batch_size or i == len(iterable) - 1:
            # Warte auf Abschluss aller Tasks im aktuellen Batch
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            results.extend(batch_results)
            tasks = []  # Leere die Task-Liste für den nächsten Batch
    
    return results

async def run_with_semaphore(iterable, func, max_concurrent=10, *args, **kwargs):
    """
    Führt eine Funktion für jedes Element in einem Iterable aus,
    begrenzt durch ein Semaphore für maximale Gleichzeitigkeit.
    
    Args:
        iterable: Iterable mit zu verarbeitenden Elementen
        func: Asynchrone Funktion, die auf jedes Element angewendet wird
        max_concurrent: Maximale Anzahl gleichzeitiger Ausführungen
        *args, **kwargs: Zusätzliche Argumente für die Funktion
        
    Returns:
        Liste der Ergebnisse
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def limited_func(item):
        async with semaphore:
            return await func(item, *args, **kwargs)
    
    tasks = [limited_func(item) for item in iterable]
    return await asyncio.gather(*tasks, return_exceptions=True)