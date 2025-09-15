from analyzer.core import AdvancedScamReporter
from utils.printers import print_progress, print_success, print_error

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
    
    try:
        reporter = AdvancedScamReporter()
        results = reporter.analyze_website(url)
        reporter.generate_report(url, results)
    except KeyboardInterrupt:
        print_error("\nАнализ прерван пользователем")
    except Exception as e:
        print_error(f"Критическая ошибка: {e}")
    
    input("\nНажмите Enter для выхода...")

if __name__ == "__main__":
    main()