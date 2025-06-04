import dns.resolver
import concurrent.futures
import json
from typing import List, Dict
import socket
import requests
from tqdm import tqdm

class SubdomainScanner:
    def __init__(self, target_domain: str, wordlist_path: str, threads: int = 10):
        self.target_domain = target_domain
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.results: List[str] = []
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1
        self.resolver.lifetime = 1

    def check_subdomain(self, subdomain: str) -> str:
        """Bir subdomain'in varlığını kontrol eder"""
        domain = f"{subdomain}.{self.target_domain}"
        try:
            # DNS query
            answers = self.resolver.resolve(domain, 'A')
            if answers:
                # HTTP accessibility check
                try:
                    response = requests.get(f"http://{domain}", timeout=2)
                    if response.status_code < 500:
                        return domain
                except requests.RequestException:
                    # Add even if DNS record exists but HTTP is not accessible
                    return domain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, 
                dns.resolver.Timeout, socket.gaierror):
            pass
        return ""

    def brute_force_subdomains(self) -> List[str]:
        """Wordlist kullanarak subdomain taraması yapar"""
        try:
            with open(self.wordlist_path, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Wordlist bulunamadı: {self.wordlist_path}")
            return []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = []
            with tqdm(total=len(subdomains), desc="Subdomain taraması") as pbar:
                futures = [executor.submit(self.check_subdomain, subdomain) for subdomain in subdomains]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                    pbar.update(1)

        self.results = sorted(list(set(results)))
        return self.results

    def save_results(self, output_file: str):
        """Sonuçları dosyaya kaydeder"""
        with open(output_file, 'w') as f:
            json.dump({
                'target': self.target_domain,
                'subdomains': self.results
            }, f, indent=4)

    def get_ip_addresses(self) -> Dict[str, str]:
        """Bulunan subdomain'lerin IP adreslerini döndürür"""
        ip_addresses = {}
        for subdomain in self.results:
            try:
                ip = socket.gethostbyname(subdomain)
                ip_addresses[subdomain] = ip
            except socket.gaierror:
                ip_addresses[subdomain] = "Çözümlenemedi"
        return ip_addresses 