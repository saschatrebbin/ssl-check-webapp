document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('check-form');
    const urlInput = document.getElementById('url-input');
    const loadingIndicator = document.getElementById('loading');
    const resultContainer = document.getElementById('result-container');
    const errorContainer = document.getElementById('error-container');
    const errorMessage = document.getElementById('error-message');
    
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        checkSSL();
    });
    
    async function checkSSL() {
        // Eingabe validieren
        let url = urlInput.value.trim();
        if (!url) {
            showError('Bitte geben Sie eine URL ein.');
            return;
        }
        
        // UI zurücksetzen und Ladeindikator anzeigen
        loadingIndicator.classList.remove('hidden');
        resultContainer.classList.add('hidden');
        errorContainer.classList.add('hidden');
        
        // Alle Ergebnisfelder zurücksetzen
        resetResults();
        
        try {
            // API-Aufruf
            const response = await fetch('/api/check-ssl', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });
            
            const result = await response.json();
            
            // Überprüfen, ob die Anfrage erfolgreich war
            if (!result.success) {
                throw new Error(result.error || 'Unbekannter Fehler bei der SSL-Prüfung.');
            }
            
            // Ergebnisse anzeigen
            displayResults(result.data);
            
        } catch (error) {
            showError(error.message);
        } finally {
            loadingIndicator.classList.add('hidden');
        }
    }
    
    function resetResults() {
        // Alle Ergebnisfelder zurücksetzen
        document.getElementById('result-url').textContent = '';
        document.getElementById('result-url').innerHTML = '';
        document.getElementById('result-hostname').textContent = '';
        document.getElementById('result-port').textContent = '';
        document.getElementById('result-timestamp').textContent = '';
        document.getElementById('result-serial').textContent = '';
        document.getElementById('result-fingerprint').textContent = '';
        document.getElementById('result-cn').textContent = '';
        document.getElementById('result-sans').innerHTML = '';
        
        const hostnameValidation = document.getElementById('hostname-validation');
        hostnameValidation.className = 'validation-item';
        hostnameValidation.querySelector('.validation-text').textContent = '';
        
        const chainValidation = document.getElementById('chain-validation');
        chainValidation.className = 'validation-item';
        chainValidation.querySelector('.validation-text').textContent = '';
        
        const expiryValidation = document.getElementById('expiry-validation');
        expiryValidation.className = 'validation-item';
        expiryValidation.querySelector('.validation-text').textContent = '';
        
        document.getElementById('result-expiry').textContent = '';
        document.getElementById('result-days-left').textContent = '';
        document.getElementById('result-days-left').className = 'value';
    }
    
    function displayResults(data) {
        // Grundinformationen
        // URL als klickbaren Link darstellen
        const urlElement = document.getElementById('result-url');
        const urlLink = document.createElement('a');
        urlLink.href = data.url;
        urlLink.target = '_blank';
        urlLink.textContent = data.url;
        urlElement.innerHTML = '';
        urlElement.appendChild(urlLink);
        
        document.getElementById('result-hostname').textContent = data.hostname;
        document.getElementById('result-port').textContent = data.port;
        document.getElementById('result-timestamp').textContent = `Geprüft am: ${data.timestamp}`;
        
        // Zertifikatsinformationen
        document.getElementById('result-serial').textContent = data.serial;
        document.getElementById('result-fingerprint').textContent = data.fingerprint;
        document.getElementById('result-cn').textContent = data.common_name;
        
        // Subject Alternative Names
        const sansContainer = document.getElementById('result-sans');
        sansContainer.innerHTML = '';
        
        if (data.sans.length === 0) {
            sansContainer.innerHTML = '<div class="sans-item">Keine SANs vorhanden</div>';
        } else {
            data.sans.forEach(san => {
                const sanElement = document.createElement('div');
                sanElement.className = 'sans-item';
                sanElement.textContent = san;
                sansContainer.appendChild(sanElement);
            });
        }
        
        // Hostname-Validierung
        const hostnameValidation = document.getElementById('hostname-validation');
        hostnameValidation.className = 'validation-item';
        
        if (data.hostname_valid) {
            hostnameValidation.classList.add('validation-success');
            hostnameValidation.querySelector('.validation-text').innerHTML = 
                `Hostname ist gültig für dieses Zertifikat` + 
                (data.wildcard_cert ? ' (Wildcard-Zertifikat)' : '');
        } else {
            hostnameValidation.classList.add('validation-error');
            hostnameValidation.querySelector('.validation-text').textContent = 
                'Hostname ist NICHT gültig für dieses Zertifikat';
        }
        
        // Chain-Validierung
        const chainValidation = document.getElementById('chain-validation');
        chainValidation.className = 'validation-item';
        
        if (data.chain_valid) {
            chainValidation.classList.add('validation-success');
            chainValidation.querySelector('.validation-text').textContent = 
                'Certificate Chain ist vollständig und gültig';
        } else {
            chainValidation.classList.add('validation-error');
            chainValidation.querySelector('.validation-text').innerHTML = 
                `Certificate Chain ist ungültig<br><small>${data.chain_error || 'Unbekannter Fehler'}</small>`;
        }
        
        // Ablaufdatum
        document.getElementById('result-expiry').textContent = data.not_after;
        
        // Verbleibende Tage und Status
        const daysLeftElement = document.getElementById('result-days-left');
        const expiryValidation = document.getElementById('expiry-validation');
        expiryValidation.className = 'validation-item';
        
        let statusClass, statusText;
        
        switch (data.expiry_status) {
            case 'ABGELAUFEN':
                statusClass = 'expired';
                statusText = 'Zertifikat ist abgelaufen!';
                break;
            case 'KRITISCH':
                statusClass = 'critical';
                statusText = 'Zertifikat läuft bald ab (weniger als 30 Tage)!';
                break;
            case 'WARNUNG':
                statusClass = 'warning';
                statusText = 'Zertifikat läuft in weniger als 90 Tagen ab.';
                break;
            default:
                statusClass = 'ok';
                statusText = 'Zertifikat ist gültig.';
        }
        
        daysLeftElement.textContent = `${data.days_left} Tage (${data.expiry_status})`;
        daysLeftElement.className = `value ${statusClass}`;
        
        expiryValidation.classList.add(`validation-${statusClass}`);
        expiryValidation.querySelector('.validation-text').textContent = statusText;
        
        // Ergebniscontainer anzeigen
        resultContainer.classList.remove('hidden');
    }
    
    function showError(message) {
        errorMessage.textContent = message;
        errorContainer.classList.remove('hidden');
        resultContainer.classList.remove('hidden');
        loadingIndicator.classList.add('hidden');
    }
});