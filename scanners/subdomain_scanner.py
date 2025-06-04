import subprocess
import json
import os
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import requests
from urllib.parse import urlparse
import urllib3
import warnings
from tqdm import tqdm
import sys
import threading

# SSL uyarılarını kapat
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SubdomainScanner:
    def __init__(self):
        self.is_windows = platform.system().lower() == 'windows'
        self.tools = {
            'subfinder': self._check_tool_exists('subfinder')
        }
        self.timeout = 300  # 5 dakika timeout
        self.session = requests.Session()
        self.session.verify = False
        self.current_tool = None
        self.progress = 0
        
        if not self.tools['subfinder']:
            print("Uyarı: Subfinder bulunamadı! Lütfen subfinder'ı yükleyin.")

    def _update_progress(self, tool_name, progress):
        """İlerleme durumunu günceller"""
        self.current_tool = tool_name
        self.progress = progress

    def _check_tool_exists(self, tool_name):
        """Aracın sistemde yüklü olup olmadığını kontrol eder"""
        try:
            if self.is_windows:
                tool_name = f"{tool_name}.exe"
            
            result = subprocess.run([tool_name, '-version'], 
                                 capture_output=True, 
                                 text=True,
                                 shell=True if self.is_windows else False,
                                 timeout=10)
            return True
        except subprocess.TimeoutExpired:
            print(f"Uyarı: {tool_name} zaman aşımına uğradı")
            return False
        except Exception as e:
            print(f"Uyarı: {tool_name} yüklü değil veya PATH'te bulunamadı. Hata: {str(e)}")
            return False

    def _run_subfinder(self, domain):
        if not self.tools['subfinder']:
            return set()
        
        try:
            self._update_progress("Subfinder", 0)
            print(f"\nSubfinder taraması başlatılıyor: {domain}")
            
            cmd = f"subfinder -d {domain} -silent"
            print(f"Çalıştırılan komut: {cmd}")
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            output_lines = []
            start_time = time.time()
            
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    line = line.strip()
                    if line:  # Boş satırları filtrele
                        print(f"Bulunan subdomain: {line}")  # Debug log
                        output_lines.append(line)
                
                # İlerlemeyi güncelle
                elapsed = time.time() - start_time
                progress = min(95, int((elapsed / 30) * 100))
                self._update_progress("Subfinder", progress)
            
            # Hata çıktısını kontrol et
            _, stderr = process.communicate()
            if stderr:
                print(f"Subfinder hata çıktısı: {stderr}")
            
            subdomains = set(line for line in output_lines if line)
            self._update_progress("Subfinder", 100)
            print(f"Subfinder {len(subdomains)} subdomain buldu")
            return subdomains
            
        except Exception as e:
            print(f"Subfinder çalıştırılırken hata: {str(e)}")
            return set()

    def _validate_domain(self, domain):
        """Subdomain'in geçerli olup olmadığını kontrol eder"""
        try:
            response = self.session.get(f"http://{domain}", timeout=5)
            return True
        except:
            try:
                response = self.session.get(f"https://{domain}", timeout=5)
                return True
            except:
                return False

    async def get_total_steps(self, domain):
        """Toplam adım sayısını döndürür"""
        return 200  # Subfinder için 100 + aktif domain kontrolü için 100

    async def scan_with_progress(self, domain):
        """İlerleme durumunu raporlayarak tarama yapar"""
        start_time = time.time()
        all_subdomains = set()
        used_tools = []
        
        try:
            # Subfinder taraması
            if self.tools['subfinder']:
                self._update_progress("Subfinder", 0)
                subfinder_results = self._run_subfinder(domain)
                if subfinder_results:
                    all_subdomains.update(subfinder_results)
                    used_tools.append('Subfinder')
                    yield {
                        'tool': 'Subfinder',
                        'found': len(subfinder_results),
                        'subdomains': list(subfinder_results)
                    }
            
            # Aktif domain kontrolü
            self._update_progress("Aktif Domain Kontrolü", 0)
            cleaned_subdomains = {s for s in all_subdomains if s and s.strip()}
            active_subdomains = set()
            total_domains = len(cleaned_subdomains)
            
            if total_domains == 0:
                print("Hiç subdomain bulunamadı!")  # Debug log
                yield {
                    'tool': 'Complete',
                    'active_subdomains': [],
                    'subdomains': [],
                    'total_count': 0,
                    'active_count': 0,
                    'elapsed_time': time.time() - start_time,
                    'tools_used': used_tools
                }
                return
            
            print(f"Toplam {total_domains} subdomain bulundu, aktif kontrol başlıyor...")  # Debug log
            
            for i, subdomain in enumerate(cleaned_subdomains):
                print(f"Kontrol ediliyor: {subdomain}")  # Debug log
                if self._validate_domain(subdomain):
                    print(f"Aktif subdomain bulundu: {subdomain}")  # Debug log
                    active_subdomains.add(subdomain)
                progress = ((i + 1) / total_domains) * 100
                self._update_progress("Aktif Domain Kontrolü", progress)
                
                if (i + 1) % 5 == 0 or (i + 1) == total_domains:
                    yield {
                        'tool': 'Validation',
                        'active_count': len(active_subdomains),
                        'total_count': total_domains,
                        'progress': progress
                    }
            
            # Final sonuçları
            final_results = {
                'tool': 'Complete',
                'active_subdomains': list(active_subdomains),
                'subdomains': list(cleaned_subdomains),
                'total_count': len(cleaned_subdomains),
                'active_count': len(active_subdomains),
                'elapsed_time': time.time() - start_time,
                'tools_used': used_tools
            }
            print(f"Tarama tamamlandı: {final_results}")  # Debug log
            yield final_results
            
        except Exception as e:
            print(f"Tarama hatası: {str(e)}")
            yield {
                'tool': 'Error',
                'error': str(e),
                'tools_used': used_tools
            }

    async def scan(self, domain):
        """Subdomain taraması yapar"""
        start_time = time.time()
        all_subdomains = set()
        active_tools = []
        
        print(f"\nTarama başlatılıyor: {domain}")
        
        # İlerleme monitörünü başlat
        progress_thread = threading.Thread(
            target=self._progress_monitor,
            args=(self.timeout,)
        )
        progress_thread.daemon = True
        progress_thread.start()
        
        # Subfinder ile tarama
        if self.tools['subfinder']:
            subfinder_results = self._run_subfinder(domain)
            if subfinder_results:
                active_tools.append("Subfinder")
                all_subdomains.update(subfinder_results)

        # Sonuçları temizle
        cleaned_subdomains = {s for s in all_subdomains if s and s.strip()}
        
        # Aktif subdomain'leri kontrol et
        self._update_progress("Aktif Domain Kontrolü", 0)
        print("\nAktif subdomain'ler kontrol ediliyor...")
        active_subdomains = set()
        total_domains = len(cleaned_subdomains)
        
        with tqdm(total=total_domains, desc="Domain kontrolü") as pbar:
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_domain = {executor.submit(self._validate_domain, sub): sub for sub in cleaned_subdomains}
                completed = 0
                
                for future in as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        if future.result():
                            active_subdomains.add(domain)
                    except Exception:
                        pass
                    
                    completed += 1
                    progress = int((completed / total_domains) * 100)
                    self._update_progress("Aktif Domain Kontrolü", progress)
                    pbar.update(1)

        end_time = time.time()
        scan_duration = int(end_time - start_time)
        
        # Son durumu güncelle
        self._update_progress("Tamamlandı", 100)
        
        print(f"\nTarama tamamlandı!")
        print(f"Toplam süre: {scan_duration} saniye")
        print(f"Bulunan toplam subdomain: {len(cleaned_subdomains)}")
        print(f"Aktif subdomain sayısı: {len(active_subdomains)}")
        
        return {
            "subdomains": sorted(list(cleaned_subdomains)),
            "active_subdomains": sorted(list(active_subdomains)),
            "total_count": len(cleaned_subdomains),
            "active_count": len(active_subdomains),
            "tools_used": active_tools,
            "scan_time": scan_duration
        } 