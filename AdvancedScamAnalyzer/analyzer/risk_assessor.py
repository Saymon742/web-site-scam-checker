class RiskAssessor:
    def assess(self, results):
        risk_score = 0
        warnings = []
        
        content = results.get('content_analysis', {})
        risk_score += content.get('scam_indicators_count', 0) * 3
        
        if content.get('has_urgent_calls'):
            risk_score += 4
            warnings.append("Обнаружены срочные призывы к действию")
        if content.get('has_guarantees'):
            risk_score += 3
            warnings.append("Обнаружены гарантии доходности")
        if content.get('has_free_offers'):
            risk_score += 2
            warnings.append("Обнаружены предложения 'бесплатных' услуг")
        
        domain = results.get('domain_info', {})
        if domain.get('domain_age_days') and domain['domain_age_days'] < 30:
            risk_score += 5
            warnings.append("Домен создан недавно (менее 30 дней)")
        if domain.get('days_until_expiry') and domain['days_until_expiry'] < 30:
            risk_score += 3
            warnings.append("Домен скоро истекает (менее 30 дней)")
        
        ssl_info = results.get('ssl_info', {})
        if not ssl_info.get('has_ssl'):
            risk_score += 4
            warnings.append("SSL-сертификат отсутствует")
        elif ssl_info.get('ssl_days_until_expiry') and ssl_info['ssl_days_until_expiry'] < 30:
            risk_score += 2
            warnings.append("SSL-сертификат скоро истекает")
        
        vt_data = results.get('virus_total', {})
        if vt_data.get('malicious', 0) > 0:
            risk_score += vt_data['malicious'] * 5
            warnings.append(f"VirusTotal обнаружил {vt_data['malicious']} угроз")
        if vt_data.get('suspicious', 0) > 0:
            risk_score += vt_data['suspicious'] * 3
            warnings.append(f"VirusTotal обнаружил {vt_data['suspicious']} подозрительных сигнатур")
        
        redirects = results.get('redirect_info', {})
        if redirects.get('redirected'):
            risk_score += 2
            warnings.append("Обнаружены редиректы")
        
        return {
            'risk_score': risk_score,
            'warnings': warnings,
            'factors_considered': len(warnings)
        }

    def get_final_verdict(self, risk_assessment):
        risk_score = risk_assessment['risk_score']
        
        if risk_score >= 20:
            return {
                'verdict': '🚨 ОЧЕНЬ ОПАСНЫЙ САЙТ',
                'description': 'Высокая вероятность мошенничества!',
                'color': 'red',
                'risk_level': 'CRITICAL'
            }
        elif risk_score >= 15:
            return {
                'verdict': '⚠️ ОПАСНЫЙ САЙТ',
                'description': 'Обнаружены многочисленные признаки мошенничества.',
                'color': 'orange',
                'risk_level': 'HIGH'
            }
        elif risk_score >= 10:
            return {
                'verdict': '🔸 ПОТЕНЦИАЛЬНО ОПАСНЫЙ САЙТ',
                'description': 'Есть некоторые подозрительные признаки.',
                'color': 'yellow',
                'risk_level': 'MEDIUM'
            }
        elif risk_score >= 5:
            return {
                'verdict': '🔹 МАЛОРИСКОВАННЫЙ САЙТ',
                'description': 'Минимальные риски.',
                'color': 'blue',
                'risk_level': 'LOW'
            }
        else:
            return {
                'verdict': '✅ НЕ ОПАСНЫЙ САЙТ',
                'description': 'Сайт выглядит безопасно.',
                'color': 'green',
                'risk_level': 'SAFE'
            }