@echo off
echo Очистка предыдущих сборок...
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
del /q ScamChecker.spec 2>nul

echo.
echo Создание оптимизированного EXE файла...
pyinstaller --onefile --console ^
--name "ScamChecker" ^
--add-data "AdvancedScamAnalyzer\config.py;." ^
--add-data "AdvancedScamAnalyzer\utils\printers.py;utils" ^
--add-data "AdvancedScamAnalyzer\utils\helpers.py;utils" ^
--add-data "AdvancedScamAnalyzer\utils\__init__.py;utils" ^
--add-data "AdvancedScamAnalyzer\analyzer\core.py;analyzer" ^
--add-data "AdvancedScamAnalyzer\analyzer\content_analyzer.py;analyzer" ^
--add-data "AdvancedScamAnalyzer\analyzer\domain_analyzer.py;analyzer" ^
--add-data "AdvancedScamAnalyzer\analyzer\security_analyzer.py;analyzer" ^
--add-data "AdvancedScamAnalyzer\analyzer\risk_assessor.py;analyzer" ^
--add-data "AdvancedScamAnalyzer\analyzer\report_generator.py;analyzer" ^
--add-data "AdvancedScamAnalyzer\analyzer\__init__.py;analyzer" ^
--hidden-import=requests ^
--hidden-import=bs4 ^
--hidden-import=whois ^
--hidden-import=urllib3 ^
--hidden-import=chardet ^
--hidden-import=idna ^
--hidden-import=ssl ^
--hidden-import=socket ^
--hidden-import=re ^
--hidden-import=datetime ^
--hidden-import=time ^
--hidden-import=BeautifulSoup ^
--hidden-import=soupsieve ^
main.py

echo.
if exist dist\ScamChecker.exe (
    echo ✅ EXE файл успешно создан!
    echo 📁 Файл: dist\ScamChecker.exe
    echo.
    echo Размер файла: 
    for %%I in (dist\ScamChecker.exe) do echo %%~zI байt
    
    echo.
    echo Очистка временных файлов...
    rmdir /s /q build 2>nul
    del /q ScamChecker.spec 2>nul
    
) else (
    echo ❌ Ошибка при создании EXE файла
)

echo.
pause