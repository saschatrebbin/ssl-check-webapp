import ssl
import socket
import datetime
import OpenSSL.crypto as crypto
from urllib.parse import urlparse
import requests
from requests.exceptions import RequestException
import re

def get_cert_info(url):
    """
    Extrahiert Informationen zum SSL-Zertifikat einer gegebenen URL.
    Gibt ein strukturiertes Wörterbuch mit allen relevanten Informationen zurück.
    """
    # Ergebnisstruktur mit Standardwerten
    result = {
        'url': url,
        'hostname': '',
        'port': 443,
        'serial': '',
        'fingerprint': '',
        'common_name': '',
        'sans': [],
        'not_before': '',
        'not_after': '',
        'days_left': 0,
        'hostname_valid': False,
        'chain_valid': False,
        'chain_error': None,
        'expiry_status': 'UNBEKANNT',
        'wildcard_cert': False,
        'timestamp': datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
        'redirects': []
    }
    
    # Prüfe auf Redirects bevor wir weitergehen
    redirect_info = check_redirects(url)
    if redirect_info['redirects']:
        result['redirects'] = redirect_info['redirects']
        if redirect_info['final_url'] != url:
            # Aktualisiere URL für den SSL-Check
            url = redirect_info['final_url']
            result['url'] = url
    
    # URL parsen und Host extrahieren
    if not url.startswith('http'):
        url = f'https://{url}'
        result['url'] = url
    
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    
    # Port extrahieren oder Standard-Port verwenden
    if ':' in hostname:
        hostname, port = hostname.split(':')
        port = int(port)
    else:
        port = 443
    
    result['hostname'] = hostname
    result['port'] = port
    
    # Zertifikat abrufen - mit reduzierter Verifikation
    cert = None
    cert_info = None
    
    try:
        # Verbindung herstellen und Zertifikat abrufen
        context = ssl._create_unverified_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_binary = ssock.getpeercert(binary_form=True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_binary)
                cert_info = ssock.getpeercert()
                
                # Grundlegende Zertifikatsinformationen extrahieren
                if cert:
                    # Serial Number
                    result['serial'] = format(cert.get_serial_number(), 'X')
                    
                    # Fingerprint
                    result['fingerprint'] = cert.digest('sha256').decode('utf-8')
                    
                    # Subject-Informationen
                    subject = cert.get_subject()
                    for item in subject.get_components():
                        if item[0] == b'CN':
                            result['common_name'] = item[1].decode('utf-8')
                            break
                    
                    # KRITISCHE ÄNDERUNG: SANs direkt aus dem X509-Zertifikat auslesen
                    # Suche nach SANs über Extensions
                    sans = []
                    for i in range(cert.get_extension_count()):
                        ext = cert.get_extension(i)
                        if ext.get_short_name() == b'subjectAltName':
                            sans_text = str(ext)
                            # Extrahiere DNS-Namen aus dem Format: DNS:example.com, DNS:www.example.com
                            import re
                            sans = re.findall(r'DNS:([\w\*\.-]+)', sans_text)
                            break
                    
                    # Nur wenn keine SANs gefunden wurden, versuche sie aus cert_info zu extrahieren
                    if not sans and cert_info and 'subjectAltName' in cert_info:
                        for item in cert_info['subjectAltName']:
                            if item[0] == 'DNS':
                                sans.append(item[1])
                    
                    result['sans'] = sans
                    
                    # KRITISCHE ÄNDERUNG: Gültigkeit direkt aus dem X509-Zertifikat extrahieren
                    try:
                        # Gültigkeit direkt aus dem X509-Zertifikat extrahieren
                        not_before = datetime.datetime.strptime(
                            cert.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')
                        not_after = datetime.datetime.strptime(
                            cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
                        
                        result['not_before'] = not_before.strftime('%d.%m.%Y')
                        result['not_after'] = not_after.strftime('%d.%m.%Y')
                        result['days_left'] = (not_after - datetime.datetime.now()).days
                        result['expiry_status'] = get_expiry_status(result['days_left'])
                    except Exception as e:
                        # Falls dieser Ansatz fehlschlägt, versuchen wir es mit cert_info
                        result['cert_errors'] = result.get('cert_errors', []) + [f"Fehler beim Auslesen der Gültigkeit: {str(e)}"]
                        if cert_info and 'notBefore' in cert_info and 'notAfter' in cert_info:
                            not_before = datetime.datetime.strptime(
                                cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
                            not_after = datetime.datetime.strptime(
                                cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            
                            result['not_before'] = not_before.strftime('%d.%m.%Y')
                            result['not_after'] = not_after.strftime('%d.%m.%Y')
                            result['days_left'] = (not_after - datetime.datetime.now()).days
                            result['expiry_status'] = get_expiry_status(result['days_left'])
                
    except Exception as e:
        # Füge detaillierte Fehlerinfos hinzu
        result['cert_errors'] = result.get('cert_errors', []) + [f"Verbindungsfehler: {str(e)}"]
        
    # Ergänze Fehlerlog mit allen aufgetretenen Fehlern
    if 'chain_error' in result and result['chain_error']:
        result['cert_errors'] = result.get('cert_errors', []) + [f"Chain-Validierungsfehler: {result['chain_error']}"]
        
    return {
        'success': True,
        'data': result
    }

def check_redirects(url):
    """
    Überprüft, ob eine URL Weiterleitungen aufweist und gibt die Redirect-Kette zurück.
    """
    if not url.startswith('http'):
        url = f'https://{url}'
    
    redirects = []
    final_url = url
    
    try:
        # Manuelle Weiterleitungsverfolgung deaktivieren, um sie selbst zu protokollieren
        session = requests.Session()
        session.max_redirects = 10
        
        response = session.get(url, allow_redirects=False, timeout=10)
        current_url = url
        
        # Verfolge Weiterleitungen manuell
        while response.is_redirect and len(redirects) < 10:
            redirect_url = response.headers['Location']
            
            # Relative URLs zu absoluten machen
            if redirect_url.startswith('/'):
                parsed_url = urlparse(current_url)
                redirect_url = f"{parsed_url.scheme}://{parsed_url.netloc}{redirect_url}"
            
            # Weiterleitung protokollieren
            redirects.append({
                'from': current_url,
                'to': redirect_url,
                'status': response.status_code,
                'reason': response.reason
            })
            
            # Auf die neue URL umschalten
            current_url = redirect_url
            response = session.get(current_url, allow_redirects=False, timeout=10)
        
        final_url = current_url
        
    except RequestException as e:
        # Bei Netzwerkfehlern die verfügbaren Informationen zurückgeben
        pass
    except Exception as e:
        # Andere Fehler ignorieren
        pass
    
    return {
        'redirects': redirects,
        'final_url': final_url
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
    if common_name and common_name.startswith('*.'):
        wildcard_patterns.append(common_name)
    
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