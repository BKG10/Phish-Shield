# filename: url_feature_extractor.py

import re
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from tld import get_tld

class URLFeatureExtractor:
    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        self.parsed_url = self.safe_parse(url)
        self.domain = self.parsed_url.netloc if self.parsed_url else ''
        self.soup = None
        self.page_content = None
        self.response = None
        self.error = None

        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            self.response = requests.get(url, headers=headers, timeout=self.timeout)
            self.page_content = self.response.text
            self.soup = BeautifulSoup(self.page_content, 'html.parser')
        except Exception as e:
            self.error = str(e)

    def safe_parse(self, url):
        try:
            return urlparse(url)
        except:
            return None

    def get_url_length(self):
        return len(self.url) if self.url else 0

    def get_domain_length(self):
        return len(self.domain) if self.domain else 0

    def get_tld_length(self):
        try:
            tld = get_tld(self.url, fail_silently=True)
            return len(tld) if tld else 0
        except:
            return 0

    def get_letter_ratio_in_url(self):
        letters = sum(c.isalpha() for c in self.url)
        return letters / len(self.url) if self.url else 0

    def get_digit_ratio_in_url(self):
        digits = sum(c.isdigit() for c in self.url)
        return digits / len(self.url) if self.url else 0

    def get_no_of_images(self):
        return len(self.soup.find_all('img')) if self.soup else 0

    def get_no_of_js(self):
        return len(self.soup.find_all('script')) if self.soup else 0

    def get_no_of_css(self):
        return len(self.soup.find_all('link', {'rel': 'stylesheet'})) if self.soup else 0

    def get_no_of_self_ref(self):
        if not self.soup or not self.parsed_url:
            return 0
        base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        count = 0
        for tag in self.soup.find_all(['a', 'link', 'script', 'img']):
            url = tag.get('href') or tag.get('src')
            if url:
                full = urljoin(base_url, url)
                if full.startswith(base_url):
                    count += 1
        return count

    def get_no_of_external_ref(self):
        if not self.soup or not self.parsed_url:
            return 0
        base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        count = 0
        for tag in self.soup.find_all(['a', 'link', 'script', 'img']):
            url = tag.get('href') or tag.get('src')
            if url:
                full = urljoin(base_url, url)
                if not full.startswith(base_url) and urlparse(full).netloc:
                    count += 1
        return count

    def is_https(self):
        return 1 if self.parsed_url and self.parsed_url.scheme == 'https' else 0

    def has_obfuscation(self):
        if not self.page_content:
            return 0
        patterns = [
            r'%[0-9a-fA-F]{2}', r'\\x[0-9a-fA-F]{2}', r'&#x[0-9a-fA-F]+;',
            r'javascript:', r'eval\(', r'document\.write', r'fromCharCode'
        ]
        return 1 if any(re.search(p, self.page_content) for p in patterns) else 0

    def has_title(self):
        return 1 if self.soup and self.soup.title and self.soup.title.string.strip() else 0

    def has_description(self):
        tag = self.soup.find('meta', attrs={'name': 'description'}) if self.soup else None
        return 1 if tag and tag.get('content', '').strip() else 0

    def has_submit_button(self):
        if not self.soup:
            return 0
        return 1 if self.soup.find('input', {'type': 'submit'}) or self.soup.find('button') else 0

    def has_social_net(self):
        if not self.soup:
            return 0
        return 1 if re.search(r'facebook|twitter|linkedin|instagram|youtube|pinterest', self.soup.decode(), re.I) else 0

    def has_favicon(self):
        return 1 if self.soup and self.soup.find('link', rel=re.compile('icon', re.I)) else 0

    def has_copyright_info(self):
        if not self.soup:
            return 0
        return 1 if re.search(r'copyright|©', self.soup.get_text(), re.I) else 0

    def has_popup_window(self):
        return 1 if self.page_content and re.search(r'window\.open\s*\(', self.page_content) else 0

    def has_iframe(self):
        return 1 if self.soup and self.soup.find('iframe') else 0

    def is_abnormal_url(self):
        if not self.url:
            return 0
        patterns = [r'@', r'//\w+@', r'\d+\.\d+\.\d+\.\d+', r'\.(exe|zip|rar|dll|js)$']
        return 1 if any(re.search(p, self.url) for p in patterns) else 0

    def get_redirect_value(self):
        if not self.response:
            return 0
        return 1 if len(self.response.history)>0 else -1
        

    def extract_model_features(self):
        if self.error:
            return {"error": self.error}

        redirect_value = self.get_redirect_value()

        # Map according to your rule
        if redirect_value == -1:
            redirect_0 = 0
            redirect_1 = 0
        elif redirect_value == 0:
            redirect_0 = 1
            redirect_1 = 0
        elif redirect_value == 1:
            redirect_0 = 0
            redirect_1 = 1

        return {
            'URLLength': self.get_url_length(),
            'DomainLength': self.get_domain_length(),
            'TLDLength': self.get_tld_length(),
            'NoOfImage': self.get_no_of_images(),
            'NoOfJS': self.get_no_of_js(),
            'NoOfCSS': self.get_no_of_css(),
            'NoOfSelfRef': self.get_no_of_self_ref(),
            'NoOfExternalRef': self.get_no_of_external_ref(),
            'IsHTTPS': self.is_https(),
            'HasObfuscation': self.has_obfuscation(),
            'HasTitle': self.has_title(),
            'HasDescription': self.has_description(),
            'HasSubmitButton': self.has_submit_button(),
            'HasSocialNet': self.has_social_net(),
            'HasFavicon': self.has_favicon(),
            'HasCopyrightInfo': self.has_copyright_info(),
            'popUpWindow': self.has_popup_window(),
            'Iframe': self.has_iframe(),
            'Abnormal_URL': self.is_abnormal_url(),
            'LetterToDigitRatio': self.get_letter_ratio_in_url() / (self.get_digit_ratio_in_url() + 1e-5),
            'Redirect_0': redirect_0,
            'Redirect_1': redirect_1
        }