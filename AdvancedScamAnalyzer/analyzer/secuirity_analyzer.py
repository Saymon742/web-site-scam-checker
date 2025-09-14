import requests
import ssl
import socket
from datetime import datetime
from config import VIRUS_TOTAL_API_KEY, HEADERS

class SecurityAnalyzer:
    def __init__(self):
        self.virus_total_api_key = VIRUS_TOTAL_API_KEY
        self.headers = HEADERS

    def check_ssl(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_ssl_expiry = (cert_expires - datetime.now()).days
            
            return {
                'has_ssl': True,
                'ssl_valid': True,
                'ssl_days_until_expiry': days_until_ssl_expiry
            }
        except Exception:
            return {'has_ssl': False, 'ssl_valid': False}

    def check_virus_total(self, domain):
        try:
            if not self.virus_total_api_key or self.virus_total_api_key == "YOUR_ACTUAL_API_KEY_HERE":
                return {'error': 'API ключ не настроен'}
            
            url = f'https://www.virustotal.com/api/v3/domains/{domain}'
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                return {
                    'malicious': stats['malicious'],
                    'suspicious': stats['suspicious'],
                    'harmless': stats['harmless'],
                    'undetected': stats['undetected'],
                    'total_engines': sum(stats.values()),
                    'reputation': data['data']['attributes'].get('reputation', 0),
                    'categories': data['data']['attributes'].get('categories', {})
                }
            elif response.status_code == 404:
                return {'error': 'Домен не найден в базе VirusTotal'}
            else:
                return {'error': f'Ошибка API: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'Ошибка проверки VirusTotal: {str(e)}'}

    def analyze_redirects(self, original_url, final_url):
        try:
            response = requests.get(original_url, headers=self.headers, timeout=10, allow_redirects=True)
            return {
                'original_url': original_url,
                'final_url': final_url,
                'redirected': original_url != final_url,
                'redirect_count': len(response.history)
            }
        except Exception:
            return {
                'original_url': original_url,
                'final_url': final_url,
                'redirected': original_url != final_url,
                'redirect_count': 0
            }