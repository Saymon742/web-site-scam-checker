import whois
from datetime import datetime

class DomainAnalyzer:
    def analyze(self, domain):
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