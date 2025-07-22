import requests
from bs4 import BeautifulSoup
import urllib.parse
import re

def normalize_url(url):
    parsed = urllib.parse.urlparse(url)
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return normalized.rstrip('/')

class WebSecurityScanner:
    def __init__(self, target_url, max_depth=1):
        self.target_url = normalize_url(target_url)
        self.max_depth = max_depth
        self.visited_urls = set()
        self.vulnerabilities = []
        self.session = requests.Session()

    def crawl(self, url, depth=0):
        if (depth > self.max_depth or len(self.visited_urls) > 20 or
                url in self.visited_urls or not url.startswith(self.target_url)):
            return
        try:
            resp = self.session.get(url, timeout=10)
            self.visited_urls.add(url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = urllib.parse.urljoin(url, link['href'])
                href = normalize_url(href)
                self.crawl(href, depth + 1)
        except Exception as e:
            print(f"[ERROR] Crawl failed for {url}: {e}")

    def scan(self):
        self.crawl(self.target_url)
        print(f"\n[CRAWL DONE] URLs found: {self.visited_urls}\n")
        for url in self.visited_urls:
            self.check_sql_injection(url)
            self.check_xss(url)
            self.check_csrf(url)
        return self.vulnerabilities

    def report_vulnerability(self, vuln):
        print(f"[VULNERABILITY FOUND] {vuln}")
        self.vulnerabilities.append(vuln)

    def check_sql_injection(self, url):
        try:
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            sqli_payload = "' OR '1'='1"
            for form in forms:
                data = {}
                action = urllib.parse.urljoin(url, form.get('action') or '')
                method = form.get('method', 'get').lower()
                input_tags = form.find_all('input')
                for input_tag in input_tags:
                    name = input_tag.get('name')
                    if name: data[name] = sqli_payload
                if not data:
                    continue
                if method == 'post':
                    res = self.session.post(action, data=data)
                else:
                    res = self.session.get(action, params=data)
                if re.search(r"sql|syntax|mysql|error|warning", res.text, re.IGNORECASE):
                    self.report_vulnerability({
                        'type': 'SQL Injection',
                        'url': url,
                        'severity': 'High',
                        'evidence': 'Typical SQL error message detected in response.'
                    })
        except Exception as e:
            print(f"[ERROR] SQLi test failed for {url}: {e}")

    def check_xss(self, url):
        try:
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            xss_payload = "<script>alert('XSS')</script>"
            for form in forms:
                data = {}
                action = urllib.parse.urljoin(url, form.get('action') or '')
                method = form.get('method', 'get').lower()
                input_tags = form.find_all('input')
                for input_tag in input_tags:
                    name = input_tag.get('name')
                    if name: data[name] = xss_payload
                if not data:
                    continue
                if method == 'post':
                    res = self.session.post(action, data=data)
                else:
                    res = self.session.get(action, params=data)
                if xss_payload in res.text:
                    self.report_vulnerability({
                        'type': 'Cross-Site Scripting (XSS)',
                        'url': url,
                        'severity': 'High',
                        'evidence': "XSS payload reflected in response."
                    })
        except Exception as e:
            print(f"[ERROR] XSS test failed for {url}: {e}")

    def check_csrf(self, url):
        try:
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                has_csrf = any('csrf' in (i.get('name') or '').lower() for i in inputs)
                if not has_csrf:
                    self.report_vulnerability({
                        'type': 'Possible CSRF',
                        'url': url,
                        'severity': 'Medium',
                        'evidence': 'No CSRF token found in form inputs.'
                    })
        except Exception as e:
            print(f"[ERROR] CSRF test failed for {url}: {e}")
