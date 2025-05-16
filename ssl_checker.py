import ssl
import socket
import datetime
import OpenSSL.crypto as crypto
from urllib.parse import urlparse
import re

def get_cert_info(url):
    """
    Extrahiert Informationen zum SSL-Zertifikat einer gegebenen URL.
    Gibt ein strukturiertes Wörterbuch mit allen relevanten Informationen zurück.
    """
    # URL parsen und Host extrahieren
    if not url.startswith('http'):
        url = f'https://{url}'
    
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    
    # Port extrahieren oder Standard-Port verwenden
    if ':' in hostname:
        hostname, port = hostname.split(':')
        port = int(port)
    else:
        port = 443
    
    chain_valid = False
    chain_error = None
    cert = None
    sans = []
    common_name = ''
    serial = ''
    fingerprint = ''
    not_before = None
    not_after = None
    days_left = 0
    
    try:
        # Verbindung herstellen und Zertifikat abrufen
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_binary = ssock.getpeercert(binary_form=True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_binary)
                cert_info = ssock.getpeercert()
        
                # Grundlegende Zertifikatsinformationen extrahieren
                subject = cert.get_subject()
                issuer = cert.get_issuer()
                
                # Serial Number
                serial = format(cert.get_serial_number(), 'X')
                
                # Fingerprint
                fingerprint = cert.digest('sha256').decode('utf-8')
                
                # Common Name
                for item in subject.get_components():
                    if item[0] == b'CN':
                        common_name = item[1].decode('utf-8')
                        break
                
                # Subject Alternative Names (SANs)
                sans = []
                for item in cert_info.get('subjectAltName', []):
                    if item[0] == 'DNS':
                        sans.append(item[1])
                
                # Gültigkeitszeitraum
                not_before = datetime.datetime.strptime(
                    cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.datetime.strptime(
                    cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
                
                days_left = (not_after - datetime.datetime.now()).days
        
        # Hostname-Validierung
        hostname_valid = is_hostname_valid(hostname, common_name, sans)
        
        # Chain-Validierung - wird separate ausgeführt und fängt Fehler ab
        try:
            chain_valid, chain_error = validate_cert_chain(cert, hostname)
        except Exception as e:
            chain_valid = False
            chain_error = str(e)
        
        # Statuswerte bestimmen
        expiry_status = get_expiry_status(days_left)
        
        # Ergebnis zusammenstellen
        result = {
            'url': url,
            'hostname': hostname,
            'port': port,
            'serial': serial,
            'fingerprint': fingerprint,
            'common_name': common_name,
            'sans': sans,
            'not_before': not_before.strftime('%d.%m.%Y') if not_before else '',
            'not_after': not_after.strftime('%d.%m.%Y') if not_after else '',
            'days_left': days_left,
            'hostname_valid': hostname_valid,
            'chain_valid': chain_valid,
            'chain_error': chain_error,
            'expiry_status': expiry_status,
            'wildcard_cert': any('*.' in san for san in sans) or '*.' in common_name,
            'timestamp': datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')
        }
        
        return {
            'success': True,
            'data': result
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }


def is_hostname_valid(hostname, common_name, sans):
    """
    Überprüft, ob der Hostname im CN oder in den SANs enthalten ist, 
    inklusive Wildcard-Unterstützung.
    """
    # Direkter Treffer?
    if hostname == common_name or hostname in sans:
        return True
    
    # Wildcard-Prüfung
    hostname_parts = hostname.split('.')
    
    # Prüfe alle Wildcard-Einträge
    wildcard_patterns = [s for s in sans if s.startswith('*.')]
    wildcard_patterns.append(common_name if common_name.startswith('*.') else None)
    
    for pattern in wildcard_patterns:
        if not pattern:
            continue
            
        # Entferne * und prüfe, ob die Domain übereinstimmt
        pattern_parts = pattern.split('.')
        
        # Wildcard gilt nur für eine Ebene, daher müssen beide gleich viele Teile haben
        if len(hostname_parts) != len(pattern_parts):
            continue
            
        # Ersetze den Stern durch den ersten Teil des Hostnamens
        pattern_parts[0] = pattern_parts[0].replace('*', hostname_parts[0])
        
        # Vergleiche alle Teile
        if '.'.join(pattern_parts) == hostname:
            return True
    
    return False


def validate_cert_chain(cert, hostname):
    """
    Validiert die Certificate Chain.
    """
    try:
        # Erstelle einen Store mit den System-Zertifikaten
        store = crypto.X509Store()
        
        # Lade die Standard-CA-Zertifikate
        for file in ssl.get_default_verify_paths().capath.split(':'):
            try:
                with open(file, 'rb') as f:
                    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
                    store.add_cert(ca_cert)
            except:
                pass
        
        # Erstelle einen Kontext für die Validierung
        store_ctx = crypto.X509StoreContext(store, cert)
        
        # Validiere das Zertifikat
        store_ctx.verify_certificate()
        
        return True, None
    except Exception as e:
        return False, str(e)


def get_expiry_status(days_left):
    """
    Bestimmt den Status basierend auf den verbleibenden Tagen.
    """
    if days_left <= 0:
        return "ABGELAUFEN"
    elif days_left <= 30:
        return "KRITISCH"
    elif days_left <= 90:
        return "WARNUNG"
    else:
        return "OK"

