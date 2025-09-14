import re
from urllib.parse import urlparse, urljoin
from datetime import datetime
import ipaddress
import tldextract

def is_valid_url(url):
    """
    Проверяет, является ли строка валидным URL
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def normalize_url(url):
    """
    Нормализует URL: добавляет схему если отсутствует, убирает лишние слеши
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    if parsed.fragment:
        normalized += f"#{parsed.fragment}"
    
    return normalized.rstrip('/')

def extract_domain(url):
    """
    Извлекает домен из URL с помощью tldextract
    """
    try:
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"
    except:
        parsed = urlparse(url)
        return parsed.netloc

def is_ip_address(domain):
    """
    Проверяет, является ли домен IP-адресом
    """
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def calculate_domain_age(creation_date):
    """
    Вычисляет возраст домена в днях
    """
    if not creation_date:
        return None
    
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    
    if isinstance(creation_date, str):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
        except:
            try:
                creation_date = datetime.strptime(creation_date, '%d-%b-%Y')
            except:
                return None
    
    return (datetime.now() - creation_date).days

def days_until_expiry(expiration_date):
    """
    Вычисляет количество дней до истечения срока регистрации
    """
    if not expiration_date:
        return None
    
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]
    
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S')
        except:
            try:
                expiration_date = datetime.strptime(expiration_date, '%d-%b-%Y')
            except:
                return None
    
    return (expiration_date - datetime.now()).days

def extract_meta_tags(html_content):
    """
    Извлекает мета-теги из HTML контента
    """
    from bs4 import BeautifulSoup
    
    soup = BeautifulSoup(html_content, 'html.parser')
    meta_tags = {}
    
    for meta in soup.find_all('meta'):
        name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
        content = meta.get('content')
        if name and content:
            meta_tags[name.lower()] = content
    
    return meta_tags

def detect_language(text):
    """
    Простая детекция языка текста (русский/английский)
    """
    cyrillic_count = len(re.findall(r'[а-яА-ЯёЁ]', text))
    latin_count = len(re.findall(r'[a-zA-Z]', text))
    
    total_chars = cyrillic_count + latin_count
    if total_chars == 0:
        return 'unknown'
    
    cyrillic_ratio = cyrillic_count / total_chars
    return 'russian' if cyrillic_ratio > 0.5 else 'english'

def sanitize_filename(filename):
    """
    Очищает строку для использования в качестве имени файла
    """
    return re.sub(r'[<>:"/\\|?*]', '_', filename)

def format_file_size(size_bytes):
    """
    Форматирует размер файла в читаемом виде
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

def generate_timestamp():
    """
    Генерирует timestamp для именования файлов
    """
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def is_suspicious_domain(domain):
    """
    Проверяет домен на подозрительные признаки
    """
    suspicious_patterns = [
        r'\d{4,}',  # Много цифр
        r'[a-z]{12,}',  # Очень длинные имена
        r'([a-z])\1{3,}',  # Повторяющиеся символы
        r'free-?|bonus-?|win-?|prize-?',  # Подозрительные слова
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, domain, re.IGNORECASE):
            return True
    
    return False

def validate_email(email):
    """
    Проверяет валидность email адреса
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_phone(phone):
    """
    Проверяет валидность телефонного номера
    """
    pattern = r'^(\+7|8)[\d]{10}$'
    return bool(re.match(pattern, phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')))

def get_website_favicon_url(domain):
    """
    Возвращает URL фавиконки сайта
    """
    return f"https://{domain}/favicon.ico"

def chunk_text(text, max_length=2000):
    """
    Разбивает текст на чанки максимальной длины
    """
    if len(text) <= max_length:
        return [text]
    
    chunks = []
    for i in range(0, len(text), max_length):
        chunks.append(text[i:i + max_length])
    
    return chunks

def calculate_entropy(text):
    """
    Вычисляет энтропию текста (мера случайности)
    """
    from collections import Counter
    import math
    
    if not text:
        return 0
    
    counter = Counter(text)
    text_length = len(text)
    entropy = 0.0
    
    for count in counter.values():
        probability = count / text_length
        entropy -= probability * math.log2(probability)
    
    return entropy