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

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SubdomainScanner:
    def __init__(self):
        self.is_windows = platform.system().lower() == 'windows'
        self.tools = {
            'subfinder': self._check_tool_exists('subfinder')
        }
        self.timeout = 300  # 5 minutes timeout
        self.session = requests.Session()
        self.session.verify = False
        self.current_tool = None
        self.progress = 0
        
        if not self.tools['subfinder']:
            print("Warning: Subfinder not found! Please install subfinder.")

    def _update_progress(self, tool_name, progress):
        """Updates the progress status"""
        self.current_tool = tool_name
        self.progress = progress

    def _check_tool_exists(self, tool_name):
        """Checks if the tool is installed in the system"""
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
            print(f"Warning: {tool_name} timed out")
            return False
        except Exception as e:
            print(f"Warning: {tool_name} is not installed or not found in PATH. Error: {str(e)}")
            return False

    def _run_subfinder(self, domain):
        if not self.tools['subfinder']:
            return set()
        
        try:
            self._update_progress("Subfinder", 0)
            print(f"\nSubfinder scanning started: {domain}")
            
            cmd = f"subfinder -d {domain} -silent"
            print(f"Executed command: {cmd}")
            
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
                    if line:  # Filter out empty lines
                        print(f"Found subdomain: {line}")  # Debug log
                        output_lines.append(line)
                
                # Update progress
                elapsed = time.time() - start_time
                progress = min(95, int((elapsed / 30) * 100))
                self._update_progress("Subfinder", progress)
            
            # Check for error output
            _, stderr = process.communicate()
            if stderr:
                print(f"Subfinder error output: {stderr}")
            
            subdomains = set(line for line in output_lines if line)
            self._update_progress("Subfinder", 100)
            print(f"Subfinder found {len(subdomains)} subdomains")
            return subdomains
            
        except Exception as e:
            print(f"Error running Subfinder: {str(e)}")
            return set()

    def _validate_domain(self, domain):
        """Checks if the subdomain is valid"""
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
        """Returns the total number of steps"""
        return 200  # 100 for Subfinder + 100 for active domain check

    async def scan_with_progress(self, domain):
        """Reports progress and performs scanning"""
        start_time = time.time()
        all_subdomains = set()
        used_tools = []
        
        try:
            # Subfinder scanning
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
            
            # Active domain check
            self._update_progress("Active Domain Check", 0)
            cleaned_subdomains = {s for s in all_subdomains if s and s.strip()}
            active_subdomains = set()
            total_domains = len(cleaned_subdomains)
            
            if total_domains == 0:
                print("No subdomains found!")  # Debug log
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
            
            print(f"Total {total_domains} subdomains found, starting active check...")  # Debug log
            
            for i, subdomain in enumerate(cleaned_subdomains):
                print(f"Checking: {subdomain}")  # Debug log
                if self._validate_domain(subdomain):
                    print(f"Found active subdomain: {subdomain}")  # Debug log
                    active_subdomains.add(subdomain)
                progress = ((i + 1) / total_domains) * 100
                self._update_progress("Active Domain Check", progress)
                
                if (i + 1) % 5 == 0 or (i + 1) == total_domains:
                    yield {
                        'tool': 'Validation',
                        'active_count': len(active_subdomains),
                        'total_count': total_domains,
                        'progress': progress
                    }
            
            # Final results
            final_results = {
                'tool': 'Complete',
                'active_subdomains': list(active_subdomains),
                'subdomains': list(cleaned_subdomains),
                'total_count': len(cleaned_subdomains),
                'active_count': len(active_subdomains),
                'elapsed_time': time.time() - start_time,
                'tools_used': used_tools
            }
            print(f"Scan completed: {final_results}")  # Debug log
            yield final_results
            
        except Exception as e:
            print(f"Scan error: {str(e)}")
            yield {
                'tool': 'Error',
                'error': str(e),
                'tools_used': used_tools
            }

    async def scan(self, domain):
        """Performs subdomain scanning"""
        start_time = time.time()
        all_subdomains = set()
        active_tools = []
        
        print(f"\nStarting scan: {domain}")
        
        # Start progress monitor
        progress_thread = threading.Thread(
            target=self._progress_monitor,
            args=(self.timeout,)
        )
        progress_thread.daemon = True
        progress_thread.start()
        
        # Scan with Subfinder
        if self.tools['subfinder']:
            subfinder_results = self._run_subfinder(domain)
            if subfinder_results:
                active_tools.append("Subfinder")
                all_subdomains.update(subfinder_results)

        # Clean results
        cleaned_subdomains = {s for s in all_subdomains if s and s.strip()}
        
        # Check active subdomains
        self._update_progress("Active Domain Check", 0)
        print("\nChecking active subdomains...")
        active_subdomains = set()
        total_domains = len(cleaned_subdomains)
        
        with tqdm(total=total_domains, desc="Domain check") as pbar:
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
                    self._update_progress("Active Domain Check", progress)
                    pbar.update(1)

        end_time = time.time()
        scan_duration = int(end_time - start_time)
        
        # Update final status
        self._update_progress("Completed", 100)
        
        print(f"\nScan completed!")
        print(f"Total time: {scan_duration} seconds")
        print(f"Total subdomains found: {len(cleaned_subdomains)}")
        print(f"Active subdomains: {len(active_subdomains)}")
        
        return {
            "subdomains": sorted(list(cleaned_subdomains)),
            "active_subdomains": sorted(list(active_subdomains)),
            "total_count": len(cleaned_subdomains),
            "active_count": len(active_subdomains),
            "tools_used": active_tools,
            "scan_time": scan_duration
        } 