import re
from cryptography.fernet import Fernet

class DataPrivacyCompliance:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def encrypt_data(self, data):
        return self.cipher_suite.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data):
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()

    def check_for_pii(self, text):
        pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
        }
        
        found_pii = {}
        for pii_type, pattern in pii_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                found_pii[pii_type] = matches
        
        return found_pii

    def anonymize_data(self, text):
        pii = self.check_for_pii(text)
        anonymized_text = text
        for pii_type, matches in pii.items():
            for match in matches:
                anonymized_text = anonymized_text.replace(match, f"[REDACTED {pii_type.upper()}]")
        return anonymized_text

    def generate_privacy_policy(self, company_name, data_collection_purposes):
        policy = f"""
        Privacy Policy for {company_name}

        1. Data Collection:
           We collect personal information for the following purposes:
           {', '.join(data_collection_purposes)}

        2. Data Usage:
           We use the collected data solely for the purposes stated above.

        3. Data Protection:
           We implement strong security measures to protect your data, including encryption and access controls.

        4. Data Sharing:
           We do not sell your personal information. We may share data with service providers who help us operate our business.

        5. Your Rights:
           You have the right to access, correct, or delete your personal information. Contact us for any privacy-related requests.

        6. Changes to This Policy:
           We may update this policy from time to time. Check back regularly for any changes.

        Last updated: {datetime.now().strftime('%Y-%m-%d')}
        """
        return policy

    def check_gdpr_compliance(self, website_url):
        response = requests.get(website_url)
        content = response.text.lower()
        
        compliance_checks = {
            'privacy_policy': 'privacy policy' in content,
            'cookie_consent': 'cookie' in content and 'consent' in content,
            'data_protection': 'data protection' in content,
            'right_to_access': 'right to access' in content,
            'right_to_be_forgotten': 'right to be forgotten' in content or 'right to erasure' in content,
            'data_portability': 'data portability' in content,
            'breach_notification': 'data breach' in content and 'notification' in content
        }
        
        return compliance_checks

class FinalExpandedAIWithPrivacy(FinalExpandedAI):
    def __init__(self):
        super().__init__()
        self.privacy_compliance = DataPrivacyCompliance()

    def process_query(self, query):
        if "encrypt data" in query.lower():
            data = query.split("encrypt data")[-1].strip()
            return self.privacy_compliance.encrypt_data(data)
        elif "decrypt data" in query.lower():
            data = query.split("decrypt data")[-1].strip()
            return self.privacy_compliance.decrypt_data(data)
        elif "check for pii" in query.lower():
            text = query.split("check for pii")[-1].strip()
            return self.privacy_compliance.check_for_pii(text)
        elif "anonymize data" in query.lower():
            text = query.split("anonymize data")[-1].strip()
            return self.privacy_compliance.anonymize_data(text)
        elif "generate privacy policy" in query.lower():
            company_name = input("Enter company name: ")
            purposes = input("Enter data collection purposes (comma-separated): ").split(',')
            return self.privacy_compliance.generate_privacy_policy(company_name, purposes)
        elif "check gdpr compliance" in query.lower():
            url = query.split("check gdpr compliance")[-1].strip()
            return self.privacy_compliance.check_gdpr_compliance(url)
        else:
            return super().process_query(query)

ai_assistant = FinalExpandedAIWithPrivacy()
