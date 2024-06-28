import re
import random

class CybersecurityModule:
    def __init__(self):
        self.common_vulnerabilities = [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Broken Authentication",
            "Sensitive Data Exposure",
            "XML External Entities (XXE)",
            "Broken Access Control",
            "Security Misconfiguration",
            "Insecure Deserialization",
            "Using Components with Known Vulnerabilities",
            "Insufficient Logging & Monitoring"
        ]

    def simulate_network_scan(self, target):
        # This is a simulated scan, not a real one
        open_ports = [random.randint(1, 65535) for _ in range(random.randint(1, 10))]
        return f"Simulated scan of {target} complete. Open ports: {', '.join(map(str, open_ports))}"

    def check_password_strength(self, password):
        score = 0
        if len(password) >= 8:
            score += 1
        if re.search(r"\d", password):
            score += 1
        if re.search(r"[A-Z]", password):
            score += 1
        if re.search(r"[a-z]", password):
            score += 1
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        
        if score == 5:
            return "Strong password"
        elif score >= 3:
            return "Moderate password"
        else:
            return "Weak password"

    def generate_security_tip(self):
        tips = [
            "Use strong, unique passwords for each account.",
            "Enable two-factor authentication whenever possible.",
            "Keep your software and operating systems up to date.",
            "Be cautious when clicking on links or downloading attachments from unknown sources.",
            "Use a reputable antivirus software and keep it updated.",
            "Regularly backup your important data.",
            "Use a VPN when connecting to public Wi-Fi networks.",
            "Be mindful of the information you share on social media.",
            "Use encryption for sensitive data.",
            "Regularly review your account permissions and revoke unnecessary access."
        ]
        return random.choice(tips)

    def simulate_vulnerability_assessment(self):
        vulnerabilities = random.sample(self.common_vulnerabilities, random.randint(1, 5))
        return f"Simulated vulnerability assessment complete. Potential vulnerabilities found: {', '.join(vulnerabilities)}"

# Integration with AIAssistant
def integrate_cybersecurity(ai_assistant):
    cybersec = CybersecurityModule()
    
    def cybersec_query(query):
        query_lower = query.lower()
        if "scan network" in query_lower:
            target = input("Enter target IP or hostname: ")
            return cybersec.simulate_network_scan(target)
        elif "check password" in query_lower:
            password = input("Enter password to check: ")
            return cybersec.check_password_strength(password)
        elif "security tip" in query_lower:
            return cybersec.generate_security_tip()
        elif "vulnerability assessment" in query_lower:
            return cybersec.simulate_vulnerability_assessment()
        else:
            return ai_assistant.process_query(query)
    
    ai_assistant.process_query = cybersec_query
