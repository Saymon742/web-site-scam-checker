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
        self._print_recommendations(results, url)

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

    def _print_virus_total(self, results):
        vt_data = results.get('virus_total', {})
        if 'error' not in vt_data:
            print(f"\n🛡️  VIRUSTOTAL РЕЗУЛЬТАТЫ:")
            print(f"   • Вредоносные сигнатуры: {vt_data.get('malicious', 0)}")
            print(f"   • Подозрительные сигнатуры: {vt_data.get('suspicious', 0)}")
            print(f"   • Безопасные сигнатуры: {vt_data.get('harmless', 0)}")
            print(f"   • Всего проверок: {vt_data.get('total_engines', 0)}")
        elif vt_data.get('error'):
            print(f"\n❌ VirusTotal: {vt_data['error']}")

    def _print_ssl_info(self, results):
        ssl_info = results.get('ssl_info', {})
        print(f"\n🔐 SSL-СЕРТИФИКАТ: {'✅ Присутствует' if ssl_info.get('has_ssl') else '❌ Отсутствует'}")
        if ssl_info.get('ssl_days_until_expiry'):
            print(f"   • Дней до истечения SSL: {ssl_info['ssl_days_until_expiry']}")

    def _print_content_analysis(self, results):
        content = results['content_analysis']
        print(f"\n📝 АНАЛИЗ КОНТЕНТА:")
        print(f"   • Обнаружено шаблонов мошенничества: {content['scam_indicators_count']}")
        if content['detected_patterns']:
            print(f"   • Обнаруженные паттерны: {', '.join(content['detected_patterns'][:3])}...")

    def _print_contacts(self, results):
        contacts = results.get('contacts', {})
        if contacts.get('phones') or contacts.get('emails'):
            print(f"\n📞 КОНТАКТНЫЕ ДАННЫЕ:")
            if contacts['phones']:
                print(f"   • Телефоны: {', '.join(contacts['phones'][:2])}")
            if contacts['emails']:
                print(f"   • Emails: {', '.join(contacts['emails'][:2])}")

    def _print_redirects(self, results):
        redirects = results.get('redirect_info', {})
        if redirects.get('redirected'):
            print(f"\n🔄 РЕДИРЕКТЫ:")
            print(f"   • Перенаправлено с: {redirects['original_url']}")
            print(f"   • Перенаправлено на: {redirects['final_url']}")
            print(f"   • Количество редиректов: {redirects['redirect_count']}")

    def _print_recommendations(self, results, url):
        verdict = results['final_verdict']
        
        print(f"\n{'='*70}")
        
        if verdict['risk_level'] in ['CRITICAL', 'HIGH']:
            print("\n🚨 РЕКОМЕНДАЦИИ:")
            print("   • НЕ вводите личные данные")
            print("   • НЕ совершайте платежи")
            print("   • НЕ скачивайте файлы")
            print("   • Закройте сайт и не возвращайтесь")
        elif verdict['risk_level'] == 'MEDIUM':
            print("\n⚠️  РЕКОМЕНДАЦИИ:")
            print("   • Будьте осторожны с личными данными")
            print("   • Проверяйте отзывы о сайте")
            print("   • Используйте двухфакторную аутентификацию")
        
        # Получаем домен из результатов или из исходного URL
        final_url = results.get('redirect_info', {}).get('final_url', url)
        domain_name = urlparse(final_url).netloc
        
        print(f"\n💡 Для подробного отчета посетите:")
        print(f"   https://www.virustotal.com/gui/domain/{domain_name}")
        print(f"   https://www.whois.com/whois/{domain_name}")