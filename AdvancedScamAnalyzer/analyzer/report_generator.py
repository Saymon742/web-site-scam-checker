from datetime import datetime
from urllib.parse import urlparse
from utils.printers import print_success, print_error

class ReportGenerator:
    def generate(self, url, results):
        print("\n" + "="*70)
        print("🔍 ПРОДВИНУТЫЙ ОТЧЕТ ОБ АНАЛИЗЕ БЕЗОПАСНОСТИ")
        print("="*70)
        
        print(f"\n🌐 Анализируемый сайт: {url}")
        print(f"📅 Дата анализа: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if 'error' in results:
            print_error(f"Ошибка: {results['error']}")
            return
        
        self._print_verdict(results)
        self._print_domain_info(results)
        self._print_virus_total(results)
        self._print_ssl_info(results)
        self._print_content_analysis(results)
        self._print_contacts(results)
        self._print_redirects(results)
        self._print_recommendations(results)

    def _print_verdict(self, results):
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

    def _print_domain_info(self, results):
        domain = results['domain_info']
        if 'error' not in domain:
            print(f"\n🔍 ИНФОРМАЦИЯ О ДОМЕНЕ:")
            print(f"   • Домен: {domain.get('domain_name', 'Неизвестно')}")
            print(f"   • Регистратор: {domain.get('registrar', 'Неизвестно')}")
            if domain.get('creation_date'):
                print(f"   • Дата создания: {domain['creation_date']}")
            if domain.get('domain_age_days'):
                print(f"   • Возраст домена: {domain['domain_age_days']} дней")
            if domain.get('days_until_expiry'):
                print(f"   • Дней до истечения: {domain['days_until_expiry']}")

    # ... остальные методы _print_* для разных разделов отчета