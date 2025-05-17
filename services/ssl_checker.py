import ssl
import socket
import datetime
import OpenSSL.crypto as crypto
from urllib.parse import urlparse
import requests
from requests.exceptions import RequestException, Timeout
import re
import json
import logging

# Konfiguration für den Logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ssl_checker')

class SSLCheckerService:
    def __init__(self, repository=None):
        self.repository = repository
    
    def check_domain(self, domain, batch_id=None, timeout=10, retries=2):
        """
        Prüft das SSL-Zertifikat einer Domain mit verbesserter Fehlerbehandlung.
        
        Args:
            domain: Die zu prüfende Domain
            batch_id: Optional, ID eines Batch-Jobs
            timeout: Timeout für Verbindungen in Sekunden
            retries: Anzahl der Wiederholungsversuche bei Fehlern
            
        Returns:
            Dictionary mit dem Prüfungsergebnis
        """
        logger.info(f"Prüfe Domain: {domain} (Batch-ID: {batch_id})")
        
        # Standardergebnisstruktur
        result = {
            'url': domain,
            'hostname': '',
            'port': 443,
            'timestamp': datetime.datetime.now().isoformat(),
            'success': False,
            'errors': []
        }
        
        # Bereinige die Domain/URL
        try:
            normalized_url = self._normalize_url(domain)
            result['url'] = normalized_url
            
            parsed_url = urlparse(normalized_url)
            hostname = parsed_url.netloc
            
            # Port extrahieren oder Standard-Port verwenden
            if ':' in hostname:
                hostname, port = hostname.split(':')
                port = int(port)
            else:
                port = 443
            
            result['hostname'] = hostname
            result['port'] = port
            
            # Weiterleitungen prüfen
            try:
                redirect_info = self._check_redirects(normalized_url, timeout)
                if redirect_info['redirects']:
                    result['redirects'] = redirect_info['redirects']
                    if redirect_info['final_url'] != normalized_url:
                        # Aktualisiere URL für den SSL-Check
                        final_url = redirect_info['final_url']
                        result['final_url'] = final_url
                        
                        # Aktualisiere Hostname, wenn sich die Ziel-URL geändert hat
                        parsed_final = urlparse(final_url)
                        final_hostname = parsed_final.netloc
                        if ':' in final_hostname:
                            final_hostname = final_hostname.split(':')[0]
                        
                        if final_hostname != hostname:
                            result['original_hostname'] = hostname
                            result['hostname'] = final_hostname
                            hostname = final_hostname
                
                logger.info(f"Weiterleitungscheck für {domain} abgeschlossen")
            except Exception as e:
                logger.warning(f"Fehler beim Weiterleitungscheck für {domain}: {str(e)}")
                result['errors'].append(f"Weiterleitungsfehler: {str(e)}")
            
            # SSL-Zertifikat abrufen mit Wiederholungsversuchen
            cert = None
            cert_info = None
            last_error = None
            
            for attempt in range(retries + 1):
                try:
                    logger.info(f"SSL-Verbindungsversuch {attempt+1}/{retries+1} für {hostname}:{port}")
                    
                    context = ssl._create_unverified_context()
                    with socket.create_connection((hostname, port), timeout=timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert_binary = ssock.getpeercert(binary_form=True)
                            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_binary)
                            cert_info = ssock.getpeercert()
                            
                            # Wenn wir hierher kommen, war die Verbindung erfolgreich
                            last_error = None
                            break
                except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
                    last_error = f"Verbindungsfehler (Versuch {attempt+1}): {str(e)}"
                    logger.warning(last_error)
                    if attempt < retries:
                        continue
                except Exception as e:
                    last_error = f"Unerwarteter Fehler (Versuch {attempt+1}): {str(e)}"
                    logger.warning(last_error)
                    if attempt < retries:
                        continue
            
            if last_error:
                result['errors'].append(last_error)
                
                # Speichere das Fehlerergebnis, wenn ein Repository angegeben wurde
                if self.repository:
                    self.repository.save_result(domain, False, result, batch_id)
                
                return result
            
            # Wenn wir hierher kommen, haben wir ein gültiges Zertifikat
            if cert:
                try:
                    self._extract_cert_info(cert, cert_info, result)
                    logger.info(f"Zertifikatsinformationen für {domain} extrahiert")
                except Exception as e:
                    logger.error(f"Fehler beim Extrahieren der Zertifikatsinformationen: {str(e)}")
                    result['errors'].append(f"Fehler bei der Zertifikatsanalyse: {str(e)}")
                
                # Hostname-Validierung durchführen
                hostname_valid = self._is_hostname_valid(hostname, result.get('common_name', ''), result.get('sans', []))
                result['hostname_valid'] = hostname_valid
                
                # Certificate Chain validieren
                try:
                    chain_valid, chain_error = self._validate_cert_chain(cert, hostname)
                    result['chain_valid'] = chain_valid
                    if not chain_valid and chain_error:
                        result['chain_error'] = chain_error
                        result['errors'].append(f"Chain-Validierungsfehler: {chain_error}")
                except Exception as e:
                    logger.error(f"Fehler bei der Chain-Validierung: {str(e)}")
                    result['chain_valid'] = False
                    result['chain_error'] = str(e)
                    result['errors'].append(f"Chain-Validierungsfehler: {str(e)}")
                
                # Setze Erfolgsmarkierung, wenn keine schwerwiegenden Fehler aufgetreten sind
                result['success'] = True
            
            # Speichere das Ergebnis, wenn ein Repository angegeben wurde
            if self.repository:
                self.repository.save_result(domain, result['success'], result, batch_id)
            
            return result
            
        except Exception as e:
            logger.error(f"Unbehandelte Ausnahme für {domain}: {str(e)}")
            result['errors'].append(f"Unbehandelte Ausnahme: {str(e)}")
            
            # Speichere das Fehlerergebnis, wenn ein Repository angegeben wurde
            if self.repository:
                self.repository.save_result(domain, False, result, batch_id)
            
            return result
    
    def _normalize_url(self, url):
        """Normalisiert eine URL für konsistente Verarbeitung"""
        if not url.startswith('http'):
            url = f'https://{url}'
        return url
    
    def _check_redirects(self, url, timeout=10):
        """Überprüft HTTP-Weiterleitungen"""
        redirects = []
        final_url = url
        
        try:
            # Verfolge Weiterleitungen manuell
            session = requests.Session()
            response = session.get(url, allow_redirects=False, timeout=timeout)
            current_url = url
            
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
                response = session.get(current_url, allow_redirects=False, timeout=timeout)
            
            final_url = current_url
            
        except (RequestException, Timeout) as e:
            # Bei Netzwerkfehlern die verfügbaren Informationen zurückgeben
            logger.warning(f"Netzwerkfehler beim Redirect-Check: {str(e)}")
        except Exception as e:
            # Andere Fehler protokollieren
            logger.warning(f"Unerwarteter Fehler beim Redirect-Check: {str(e)}")
        
        return {
            'redirects': redirects,
            'final_url': final_url
        }
    
    def _extract_cert_info(self, cert, cert_info, result):
        """Extrahiert relevante Informationen aus einem X.509-Zertifikat"""
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
        
        # SANs extrahieren
        sans = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                sans_text = str(ext)
                # Extrahiere DNS-Namen aus dem Format: DNS:example.com, DNS:www.example.com
                sans = re.findall(r'DNS:([\w\*\.-]+)', sans_text)
                break
        
        # Nur wenn keine SANs gefunden wurden, versuche sie aus cert_info zu extrahieren
        if not sans and cert_info and 'subjectAltName' in cert_info:
            for item in cert_info['subjectAltName']:
                if item[0] == 'DNS':
                    sans.append(item[1])
        
        result['sans'] = sans
        
        # Prüfe auf Wildcard-Zertifikat
        result['wildcard_cert'] = any('*' in san for san in sans) or (
            'common_name' in result and '*' in result['common_name']
        )
        
        # Gültigkeit extrahieren
        try:
            not_before = datetime.datetime.strptime(
                cert.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')
            not_after = datetime.datetime.strptime(
                cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
            
            result['not_before'] = not_before.strftime('%d.%m.%Y')
            result['not_after'] = not_after.strftime('%d.%m.%Y')
            
            # Verbleibende Tage berechnen
            days_left = (not_after - datetime.datetime.now()).days
            result['days_left'] = days_left
            
            # Ablaufstatus bestimmen
            if days_left <= 0:
                result['expiry_status'] = "ABGELAUFEN"
            elif days_left <= 30:
                result['expiry_status'] = "KRITISCH"
            elif days_left <= 90:
                result['expiry_status'] = "WARNUNG"
            else:
                result['expiry_status'] = "OK"
                
        except Exception as e:
            # Fallback für cert_info
            result['errors'].append(f"Fehler beim Auslesen der Gültigkeit: {str(e)}")
            if cert_info and 'notBefore' in cert_info and 'notAfter' in cert_info:
                not_before = datetime.datetime.strptime(
                    cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.datetime.strptime(
                    cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
                
                result['not_before'] = not_before.strftime('%d.%m.%Y')
                result['not_after'] = not_after.strftime('%d.%m.%Y')
                result['days_left'] = (not_after - datetime.datetime.now()).days
                
                # Ablaufstatus bestimmen
                days_left = result['days_left']
                if days_left <= 0:
                    result['expiry_status'] = "ABGELAUFEN"
                elif days_left <= 30:
                    result['expiry_status'] = "KRITISCH"
                elif days_left <= 90:
                    result['expiry_status'] = "WARNUNG"
                else:
                    result['expiry_status'] = "OK"
    
    def _is_hostname_valid(self, hostname, common_name, sans):
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
    
    def _validate_cert_chain(self, cert, hostname):
        """Validiert die Certificate Chain mit verbesserter Fehlerbehandlung"""
        try:
            # Erstelle einen Store mit den System-Zertifikaten
            store = crypto.X509Store()
            
            # Lade die Standard-CA-Zertifikate (mit Fehlerbehandlung)
            try:
                default_certs = ssl.get_default_verify_paths()
                if hasattr(default_certs, 'capath') and default_certs.capath:
                    for path in default_certs.capath.split(':'):
                        if not path:
                            continue
                            
                        try:
                            with open(path, 'rb') as f:
                                ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
                                store.add_cert(ca_cert)
                        except Exception as e:
                            logger.debug(f"Fehler beim Laden des CA-Zertifikats aus {path}: {str(e)}")
            except Exception as e:
                logger.warning(f"Fehler beim Laden der Standard-CA-Zertifikate: {str(e)}")
            
            # Erstelle einen Kontext für die Validierung
            store_ctx = crypto.X509StoreContext(store, cert)
            
            # Validiere das Zertifikat
            store_ctx.verify_certificate()
            
            return True, None
        except Exception as e:
            return False, str(e)