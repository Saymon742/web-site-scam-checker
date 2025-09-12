import requests
import whois
from bs4 import BeautifulSoup
import re
import time
from datetime import datetime
import ssl
import socket
from urllib.parse import urlparse

class AdvancedScamReporter:
    def __init__(self):
        self.scam_patterns = [
            r'крипто.*инвест', r'бесплатный.*доход', r'гарантированная.*прибыль', 
            r'100%.*заработок', r'быстр(ый|ая).*деньги', r'пассивн(ый|ая).*доход',
            r'вложи.*получи', r'секретн(ый|ая).*метод', r'эксклюзивн(ый|ая).*предложение',
            r'регистрация.*бонус', r'(купи|покупай).*(сейчас|дешево)', r'акция.*только.*сегодня',
            r'заработок.*(в день|в неделю)', r'(инвест|вклад).*(под.*процент)', r'без.*риск',
            r'проверенн(ый|ая).*схем', r'тайный.*способ', r'легк(ий|ая).*деньги'
        ]
        
        self.contact_patterns = [
            r'8\d{10}', r'\+7\d{10}', r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ]
        
        self.virus_total_api_key = "e8817f7355fd30d1c8b95522e3cfac2d5fa9b8407fcf21dadc264b72d5c25c90"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'x-apikey': self.virus_total_api_key
        }

    def print_progress(self, message, delay=0.2):
        print(f"🔄 {message}")
        time.sleep(delay)

    def print_success(self, message):
        print(f"✅ {message}")

    def print_warning(self, message):
        print(f"⚠️  {message}")

    def print_error(self, message):
        print(f"❌ {message}")

    def print_critical(self, message):
        print(f"🚨 {message}")

    def analyze_website(self, url):
        results = {}
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            self.print_progress("Проверяем доступность сайта...")
            response = requests.get(url, timeout=15, headers=self.headers, allow_redirects=True)
            response.raise_for_status()
            self.print_success("Сайт доступен для анализа")
            
            final_url = response.url
            content = response.text.lower()
            
            results['content_analysis'] = self._analyze_content(content)
            self.print_success("Анализ контента завершен")
            
            results['contacts'] = self._find_contacts(content)
            self.print_success("Поиск контактов завершен")
            
            results['domain_info'] = self._analyze_domain(domain)
            self.print_success("Анализ домена завершен")
            
            results['ssl_info'] = self._check_ssl(domain)
            self.print_success("Проверка SSL завершена")
            
            self.print_progress("Проверяем сайт через VirusTotal...")
            results['virus_total'] = self._check_virus_total(domain)
            self.print_success("Проверка VirusTotal завершена")
            
            results['redirect_info'] = self._analyze_redirects(url, final_url)
            
            results['risk_assessment'] = self._assess_risk(results)
            self.print_success("Оценка риска завершена")
            
            results['final_verdict'] = self._get_final_verdict(results['risk_assessment'])
            
            return results
            
        except requests.RequestException as e:
            self.print_error(f"Ошибка доступа к сайту: {e}")
            return {'error': f'Ошибка доступа: {e}'}
        except Exception as e:
            self.print_error(f"Неожиданная ошибка: {e}")
            return {'error': str(e)}

    def _analyze_content(self, content):
        soup = BeautifulSoup(content, 'html.parser')
        
        for script in soup(["script", "style", "meta", "link"]):
            script.decompose()
        
        text = soup.get_text()
        text = re.sub(r'\s+', ' ', text).strip()
        
        scam_indicators = 0
        detected_patterns = []
        
        for pattern in self.scam_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                scam_indicators += len(matches)
                detected_patterns.extend([pattern] * len(matches))
        
        return {
            'scam_indicators_count': scam_indicators,
            'detected_patterns': list(set(detected_patterns)),
            'has_urgent_calls': bool(re.search(r'срочно|ограниченно|последн(ий|яя)|успей', text, re.IGNORECASE)),
            'has_guarantees': bool(re.search(r'гарантия|гарантирован|100%|вернем.*деньги', text, re.IGNORECASE)),
            'has_crypto_mentions': bool(re.search(r'биткоин|криптовалют|blockchain|эфириум', text, re.IGNORECASE)),
            'has_free_offers': bool(re.search(r'бесплатно|даром|подарок|бонус', text, re.IGNORECASE)),
            'text_length': len(text),
            'unique_words': len(set(text.split()))
        }

    def _find_contacts(self, content):
        contacts = {'phones': [], 'emails': [], 'social_media': []}
        
        phone_matches = re.findall(r'8\d{10}|\+7\d{10}|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', content)
        contacts['phones'] = list(set(phone_matches))
        
        email_matches = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content, re.IGNORECASE)
        contacts['emails'] = list(set(email_matches))
        
        social_matches = re.findall(r'(vk\.com|telegram|t\.me|whatsapp|instagram)', content, re.IGNORECASE)
        contacts['social_media'] = list(set(social_matches))
        
        return contacts

    def _analyze_domain(self, domain):
        try:
            domain_info = whois.whois(domain)
            
            creation_date = domain_info.creation_date
            expiration_date = domain_info.expiration_date
            
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                domain_age = (datetime.now() - creation_date).days
            else:
                domain_age = None
            
            if expiration_date:
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                days_until_expiry = (expiration_date - datetime.now()).days
            else:
                days_until_expiry = None
            
            return {
                'domain_name': domain_info.domain_name,
                'creation_date': creation_date,
                'expiration_date': expiration_date,
                'domain_age_days': domain_age,
                'days_until_expiry': days_until_expiry,
                'registrar': domain_info.registrar,
                'country': domain_info.country,
                'name_servers': domain_info.name_servers
            }
        except Exception as e:
            return {'error': f'Ошибка whois: {str(e)}'}

    def _check_ssl(self, domain):
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

    def _check_virus_total(self, domain):
        try:
            if not self.virus_total_api_key or self.virus_total_api_key == "YOUR_ACTUAL_API_KEY_HERE":
                return {'error': 'API ключ не настроен. Замените YOUR_ACTUAL_API_KEY_HERE на ваш ключ VirusTotal'}
            
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

    def _analyze_redirects(self, original_url, final_url):
        return {
            'original_url': original_url,
            'final_url': final_url,
            'redirected': original_url != final_url,
            'redirect_count': len(requests.get(original_url, headers=self.headers, timeout=10, allow_redirects=True).history)
        }

    def _assess_risk(self, results):
        risk_score = 0
        warnings = []
        
        content = results.get('content_analysis', {})
        risk_score += content.get('scam_indicators_count', 0) * 3
        
        if content.get('has_urgent_calls'):
            risk_score += 4
            warnings.append("Обнаружены срочные призывы к действию")
        if content.get('has_guarantees'):
            risk_score += 3
            warnings.append("Обнаружены гарантии доходности")
        if content.get('has_free_offers'):
            risk_score += 2
            warnings.append("Обнаружены предложения 'бесплатных' услуг")
        
        domain = results.get('domain_info', {})
        if domain.get('domain_age_days') and domain['domain_age_days'] < 30:
            risk_score += 5
            warnings.append("Домен создан недавно (менее 30 дней)")
        if domain.get('days_until_expiry') and domain['days_until_expiry'] < 30:
            risk_score += 3
            warnings.append("Домен скоро истекает (менее 30 дней)")
        
        ssl_info = results.get('ssl_info', {})
        if not ssl_info.get('has_ssl'):
            risk_score += 4
            warnings.append("SSL-сертификат отсутствует")
        elif ssl_info.get('ssl_days_until_expiry') and ssl_info['ssl_days_until_expiry'] < 30:
            risk_score += 2
            warnings.append("SSL-сертификат скоро истекает")
        
        vt_data = results.get('virus_total', {})
        if vt_data.get('malicious', 0) > 0:
            risk_score += vt_data['malicious'] * 5
            warnings.append(f"VirusTotal обнаружил {vt_data['malicious']} угроз")
        if vt_data.get('suspicious', 0) > 0:
            risk_score += vt_data['suspicious'] * 3
            warnings.append(f"VirusTotal обнаружил {vt_data['suspicious']} подозрительных сигнатур")
        
        redirects = results.get('redirect_info', {})
        if redirects.get('redirected'):
            risk_score += 2
            warnings.append("Обнаружены редиректы")
        
        return {
            'risk_score': risk_score,
            'warnings': warnings,
            'factors_considered': len(warnings)
        }

    def _get_final_verdict(self, risk_assessment):
        risk_score = risk_assessment['risk_score']
        
        if risk_score >= 20:
            return {
                'verdict': '🚨 ОЧЕНЬ ОПАСНЫЙ САЙТ',
                'description': 'Высокая вероятность мошенничества! Никогда не вводите здесь личные данные и не совершайте платежи.',
                'color': 'red',
                'risk_level': 'CRITICAL'
            }
        elif risk_score >= 15:
            return {
                'verdict': '⚠️ ОПАСНЫЙ САЙТ',
                'description': 'Обнаружены многочисленные признаки мошенничества. Будьте крайне осторожны.',
                'color': 'orange',
                'risk_level': 'HIGH'
            }
        elif risk_score >= 10:
            return {
                'verdict': '🔸 ПОТЕНЦИАЛЬНО ОПАСНЫЙ САЙТ',
                'description': 'Есть некоторые подозрительные признаки. Рекомендуется проявить осторожность.',
                'color': 'yellow',
                'risk_level': 'MEDIUM'
            }
        elif risk_score >= 5:
            return {
                'verdict': '🔹 МАЛОРИСКОВАННЫЙ САЙТ',
                'description': 'Минимальные риски, но рекомендуется оставаться внимательным.',
                'color': 'blue',
                'risk_level': 'LOW'
            }
        else:
            return {
                'verdict': '✅ НЕ ОПАСНЫЙ САЙТ',
                'description': 'Сайт выглядит безопасно. Риски минимальны.',
                'color': 'green',
                'risk_level': 'SAFE'
            }

    def generate_report(self, url, results):
        print("\n" + "="*70)
        print("🔍 ПРОДВИНУТЫЙ ОТЧЕТ ОБ АНАЛИЗЕ БЕЗОПАСНОСТИ")
        print("="*70)
        
        print(f"\n🌐 Анализируемый сайт: {url}")
        print(f"📅 Дата анализа: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if 'error' in results:
            print(f"\n❌ Ошибка: {results['error']}")
            return
        
        verdict = results['final_verdict']
        risk = results['risk_assessment']
        
        print(f"\n{'='*50}")
        print(f"🏁 ИТОГОВЫЙ ВЕРДИКТ: {verdict['verdict']}")
        print(f"{'='*50}")
        print(f"📝 {verdict['description']}")
        print(f"📊 Суммарный балл риска: {risk['risk_score']}")
        print(f"🔍 Учтено факторов: {risk['factors_considered']}")
        print(f"{'='*50}")
        
        if risk['warnings']:
            print("\n🚨 ОБНАРУЖЕННЫЕ ПРЕДУПРЕЖДЕНИЯ:")
            for warning in risk['warnings']:
                print(f"   • {warning}")
        
        domain = results['domain_info']
        if 'error' not in domain:
            print(f"\n🔍 ИНФОРМАЦИЯ О ДОМЕНЕ:")
            print(f"   • Домен: {domain.get('domain_name', 'Неизвестно')}")
            print(f"   • Регистратор: {domain.get('registrar', 'Неизвестно')}")
            print(f"   • Дата создания: {domain.get('creation_date', 'Неизвестно')}")
            if domain.get('domain_age_days'):
                print(f"   • Возраст домена: {domain['domain_age_days']} дней")
        
        vt_data = results.get('virus_total', {})
        if 'error' not in vt_data:
            print(f"\n🛡️  VIRUSTOTAL РЕЗУЛЬТАТЫ:")
            print(f"   • Вредоносные сигнатуры: {vt_data.get('malicious', 0)}")
            print(f"   • Подозрительные сигнатуры: {vt_data.get('suspicious', 0)}")
            print(f"   • Безопасные сигнатуры: {vt_data.get('harmless', 0)}")
        else:
            print(f"\n❌ VirusTotal: {vt_data['error']}")
        
        ssl_info = results.get('ssl_info', {})
        print(f"\n🔐 SSL-СЕРТИФИКАТ: {'✅ Присутствует' if ssl_info.get('has_ssl') else '❌ Отсутствует'}")
        
        content = results['content_analysis']
        print(f"\n📝 АНАЛИЗ КОНТЕНТА:")
        print(f"   • Обнаружено шаблонов мошенничества: {content['scam_indicators_count']}")
        
        print(f"\n{'='*70}")
        
        if verdict['risk_level'] in ['CRITICAL', 'HIGH']:
            print("\n🚨 РЕКОМЕНДАЦИИ:")
            print("   • НЕ вводите личные данные")
            print("   • НЕ совершайте платежи")
            print("   • НЕ скачивайте файлы")
            print("   • Закройте сайт и не возвращайтесь")
        
        print(f"\n💡 Для подробного отчета посетите:")
        print(f"   https://www.virustotal.com/gui/domain/{urlparse(url).netloc}")

def main():
    print("🔍 ПРОДВИНУТЫЙ АНАЛИЗАТОР БЕЗОПАСНОСТИ САЙТОВ")
    print("="*65)
    print("⚡ Автоматическая проверка через VirusTotal API")
    print("="*65)
    
    url = input("Введите URL сайта для анализа: ").strip()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"\nНачинаем расширенный анализ сайта: {url}")
    print("Это может занять несколько минут...\n")
    
    reporter = AdvancedScamReporter()
    results = reporter.analyze_website(url)
    reporter.generate_report(url, results)

if __name__ == "__main__":
    main()
    input()