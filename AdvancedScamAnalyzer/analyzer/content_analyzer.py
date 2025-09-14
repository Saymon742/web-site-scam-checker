from bs4 import BeautifulSoup
import re
from config import SCAM_PATTERNS, CONTACT_PATTERNS

class ContentAnalyzer:
    def __init__(self):
        self.scam_patterns = SCAM_PATTERNS
        self.contact_patterns = CONTACT_PATTERNS

    def analyze(self, content):
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

    def find_contacts(self, content):
        contacts = {'phones': [], 'emails': [], 'social_media': []}
        
        phone_matches = re.findall(r'8\d{10}|\+7\d{10}|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', content)
        contacts['phones'] = list(set(phone_matches))
        
        email_matches = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content, re.IGNORECASE)
        contacts['emails'] = list(set(email_matches))
        
        social_matches = re.findall(r'(vk\.com|telegram|t\.me|whatsapp|instagram)', content, re.IGNORECASE)
        contacts['social_media'] = list(set(social_matches))
        
        return contacts