import requests

class SecurityHeaderAnalyzer:
    def __init__(self, url):
        self.url = url
        self.headers = self.get_headers()
        self.recommendations = []

    def get_headers(self):
        try:
            response = requests.get(self.url)
            return response.headers
        except requests.RequestException as e:
            print(f"Error fetching headers: {e}")
            return {}

    def analyze_headers(self):
        self.check_content_security_policy()
        self.check_x_frame_options()
        self.check_x_content_type_options()
        self.check_x_xss_protection()
        self.check_strict_transport_security()
        self.check_referrer_policy()

    def check_content_security_policy(self):
        if 'Content-Security-Policy' not in self.headers:
            self.recommendations.append("Missing Content-Security-Policy header. ")
        else:
            csp = self.headers['Content-Security-Policy']
            # Add additional analysis of the CSP value if needed

    def check_x_frame_options(self):
        if 'X-Frame-Options' not in self.headers:
            self.recommendations.append("Missing X-Frame-Options header.")
        else:
            xfo = self.headers['X-Frame-Options']
            if xfo not in ['DENY', 'SAMEORIGIN']:
                self.recommendations.append("X-Frame-Options header is misconfigured. Recommended values are 'DENY' or 'SAMEORIGIN'.")

    def check_x_content_type_options(self):
        if 'X-Content-Type-Options' not in self.headers:
            self.recommendations.append("Missing X-Content-Type-Options header.")
        else:
            xcto = self.headers['X-Content-Type-Options']
            if xcto != 'nosniff':
                self.recommendations.append("X-Content-Type-Options header is misconfigured. The recommended value is 'nosniff'.")

    def check_x_xss_protection(self):
        if 'X-XSS-Protection' not in self.headers:
            self.recommendations.append("Missing X-XSS-Protection header. ")
        else:
            xxp = self.headers['X-XSS-Protection']
            if xxp != '1; mode=block':
                self.recommendations.append("X-XSS-Protection header is misconfigured. The recommended value is '1; mode=block'.")

    def check_strict_transport_security(self):
        if 'Strict-Transport-Security' not in self.headers:
            self.recommendations.append("Missing Strict-Transport-Security header.")
        else:
            hsts = self.headers['Strict-Transport-Security']
            # Add additional analysis of the HSTS value if needed

    def check_referrer_policy(self):
        if 'Referrer-Policy' not in self.headers:
            self.recommendations.append("Missing Referrer-Policy header. .")
        else:
            rp = self.headers['Referrer-Policy']
            # Add additional analysis of the Referrer-Policy value if needed

    def generate_report(self):
        if not self.recommendations:
            return "All security headers are properly configured."
        else:

            return self.recommendations

if __name__ == "__main__":
    url = input("The Url: ")
    analyzer = SecurityHeaderAnalyzer(url)
    analyzer.analyze_headers()
    report = analyzer.generate_report()
    print(report)
