@echo off
echo Очистка предыдущих сборок...
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
del /q ScamChecker.spec 2>nul

echo.
echo Создание оптимизированного EXE файла...
pyinstaller --onefile --console ^
--name "ScamChecker" ^
--add-data ".;." ^
--hidden-import requests ^
--hidden-import bs4 ^
--hidden-import whois ^
--hidden-import urllib3 ^
--hidden-import chardet ^
--hidden-import idna ^
--icon=image.ico ^
scam_checker.py

echo.
if exist dist\ScamChecker.exe (
    echo ✅ EXE файл успешно создан!
    echo 📁 Файл: dist\ScamChecker.exe
    echo.
    echo Размер файла: 
    for %%I in (dist\ScamChecker.exe) do echo %%~zI байт
) else (
    echo ❌ Ошибка при создании EXE файла
)

echo.
pause