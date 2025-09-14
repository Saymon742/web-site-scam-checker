from analyzer import AdvancedScamReporter

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