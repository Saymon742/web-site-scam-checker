import requests
from urllib.parse import urlparse

from config import HEADERS
from utils.printers import print_progress, print_success, print_error
from .content_analyzer import ContentAnalyzer
from .domain_analyzer import DomainAnalyzer
from .security_analyzer import SecurityAnalyzer
from .risk_assessor import RiskAssessor
from .report_generator import ReportGenerator

class AdvancedScamReporter:
    def __init__(self):
        self.headers = HEADERS
        self.content_analyzer = ContentAnalyzer()
        self.domain_analyzer = DomainAnalyzer()
        self.security_analyzer = SecurityAnalyzer()
        self.risk_assessor = RiskAssessor()
        self.report_generator = ReportGenerator()

    def analyze_website(self, url):
        results = {}
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            print_progress("Проверяем доступность сайта...")
            response = requests.get(url, timeout=15, headers=self.headers, allow_redirects=True)
            response.raise_for_status()
            print_success("Сайт доступен для анализа")
            
            final_url = response.url
            content = response.text.lower()
            
            # Анализ контента
            results['content_analysis'] = self.content_analyzer.analyze(content)
            print_success("Анализ контента завершен")
            
            # Поиск контактов
            results['contacts'] = self.content_analyzer.find_contacts(content)
            print_success("Поиск контактов завершен")
            
            # Анализ домена
            results['domain_info'] = self.domain_analyzer.analyze(domain)
            print_success("Анализ домена завершен")
            
            # Проверка SSL
            results['ssl_info'] = self.security_analyzer.check_ssl(domain)
            print_success("Проверка SSL завершена")
            
            # Проверка VirusTotal
            print_progress("Проверяем сайт через VirusTotal...")
            results['virus_total'] = self.security_analyzer.check_virus_total(domain)
            print_success("Проверка VirusTotal завершена")
            
            # Анализ редиректов
            results['redirect_info'] = self.security_analyzer.analyze_redirects(url, final_url)
            
            # Оценка риска
            results['risk_assessment'] = self.risk_assessor.assess(results)
            print_success("Оценка риска завершена")
            
            # Финальный вердикт
            results['final_verdict'] = self.risk_assessor.get_final_verdict(results['risk_assessment'])
            
            return results
            
        except requests.RequestException as e:
            print_error(f"Ошибка доступа к сайту: {e}")
            return {'error': f'Ошибка доступа: {e}'}
        except Exception as e:
            print_error(f"Неожиданная ошибка: {e}")
            return {'error': str(e)}

    def generate_report(self, url, results):
        self.report_generator.generate(url, results)