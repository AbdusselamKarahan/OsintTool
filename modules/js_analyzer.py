import requests
from bs4 import BeautifulSoup
import re
import json
from typing import List, Dict
from urllib.parse import urljoin
import logging

class JSAnalyzer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.js_files = []
        self.analysis_results = []
        self.logger = logging.getLogger(__name__)

    def extract_js_files(self) -> List[str]:
        """Find inline and external JavaScript files"""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Inline and external JavaScript files
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    # External JavaScript file
                    full_url = urljoin(self.target_url, src)
                    self.js_files.append(full_url)
                elif script.string:
                    # Inline JavaScript
                    self.analysis_results.append({
                        'file_url': 'inline_script',
                        'content': script.string,
                        'endpoints': self._extract_endpoints(script.string),
                        'sensitive_data': self._find_sensitive_data(script.string)
                    })

            return self.js_files
        except requests.RequestException as e:
            self.logger.error(f"Error occurred while extracting JavaScript files: {str(e)}")
            return []

    def analyze_js_content(self) -> List[Dict]:
        """Analyze JavaScript files"""
        for js_url in self.js_files:
            try:
                response = self.session.get(js_url)
                content = response.text
                
                self.analysis_results.append({
                    'file_url': js_url,
                    'endpoints': self._extract_endpoints(content),
                    'sensitive_data': self._find_sensitive_data(content)
                })
            except requests.RequestException as e:
                self.logger.error(f"Error occurred during JavaScript analysis ({js_url}): {str(e)}")

        return self.analysis_results

    def _extract_endpoints(self, content: str) -> List[str]:
        """Extract endpoints from JavaScript code"""
        endpoints = set()
        
        # URL patterns
        url_patterns = [
            r'https?://[^\s<>"]+|www\.[^\s<>"]+',
            r'"/[^"]+"|\'\/[^\']+\'',
            r'`/[^`]+`'
        ]

        # API endpoint patterns
        api_patterns = [
            r'api/[a-zA-Z0-9-_/]+',
            r'v[0-9]+/[a-zA-Z0-9-_/]+',
            r'endpoints?/[a-zA-Z0-9-_/]+'
        ]

        for pattern in url_patterns + api_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                endpoint = match.group()
                # Clean quotation marks
                endpoint = endpoint.strip('"\'`')
                if endpoint:
                    endpoints.add(endpoint)

        return sorted(list(endpoints))

    def _find_sensitive_data(self, content: str) -> List[str]:
        """Find sensitive data in JavaScript code"""
        sensitive_data = set()
        
        patterns = {
            'API Key': r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'Access Token': r'access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'Secret Key': r'secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'Password': r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'Private Key': r'-----BEGIN PRIVATE KEY-----[^-]+-----END PRIVATE KEY-----',
            'JWT Token': r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
        }

        for key, pattern in patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                if match.groups():
                    value = match.group(1)
                else:
                    value = match.group()
                sensitive_data.add(f"{key}: {value}")

        return sorted(list(sensitive_data))

    def save_results(self, output_file: str):
        """Save analysis results to file"""
        with open(output_file, 'w') as f:
            json.dump({
                'target': self.target_url,
                'js_files': self.js_files,
                'analysis': self.analysis_results
            }, f, indent=4) 