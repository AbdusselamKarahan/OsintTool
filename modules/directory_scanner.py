import requests
import concurrent.futures
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
import os
from tqdm import tqdm
import aiohttp
import asyncio
from urllib.parse import urljoin, urlparse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DirectoryScanner:
    def __init__(self, target_url: str, wordlist_path: str, threads: int = 10, timeout: int = 10):
        self.target_url = self._normalize_base_url(target_url)
        self.wordlist_path = wordlist_path
        self.threads = min(max(1, threads), 50)  # Ensure threads are between 1 and 50
        self.timeout = max(1, timeout)  # Ensure timeout is at least 1 second
        self.results: List[Dict] = []
        self.session: Optional[aiohttp.ClientSession] = None
        logger.info(f"Initialized DirectoryScanner for {self.target_url}")

    def _normalize_base_url(self, url: str) -> str:
        """Normalize the base URL to ensure proper format"""
        if not url:
            raise ValueError("URL cannot be empty")
            
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _normalize_url(self, path: str) -> str:
        """Properly join base URL with path"""
        return urljoin(self.target_url, path.lstrip('/'))

    def _get_status_class(self, status_code: int) -> str:
        """Get the status class for HTTP response codes"""
        if 200 <= status_code < 300:
            return "success"  # Green
        elif 300 <= status_code < 400:
            return "warning"  # Yellow
        elif status_code >= 400:
            return "danger"   # Red
        return "secondary"    # Default gray

    async def check_url(self, session: aiohttp.ClientSession, path: str) -> Optional[Dict]:
        """Check a URL with improved error handling"""
        url = self._normalize_url(path)
        start_time = asyncio.get_event_loop().time()
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                allow_redirects=True,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                }
            ) as response:
                content = await response.read()
                elapsed = asyncio.get_event_loop().time() - start_time
                
                return {
                    "url": url,
                    "path": path,
                    "status": response.status,
                    "status_class": self._get_status_class(response.status),
                    "content_length": len(content),
                    "response_time": round(elapsed, 3),
                    "content_type": response.headers.get('content-type', ''),
                    "is_redirect": response.history is not None and len(response.history) > 0
                }
        except asyncio.TimeoutError:
            logger.warning(f"Timeout while accessing: {url}")
            return None
        except aiohttp.ClientError as e:
            logger.error(f"Error accessing {url}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error for {url}: {str(e)}")
            return None

    async def scan_directories(self) -> List[Dict]:
        """Perform directory scanning with improved concurrency handling"""
        if not os.path.exists(self.wordlist_path):
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist_path}")

        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            logger.error(f"Error reading wordlist: {str(e)}")
            raise

        if not paths:
            logger.warning("No valid paths found in wordlist")
            return []

        results = []
        connector = aiohttp.TCPConnector(limit=self.threads, ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                }
            ) as session:
                self.session = session
                tasks = [self.check_url(session, path) for path in paths]
                
                with tqdm(total=len(tasks), desc="Scanning directories") as pbar:
                    for coro in asyncio.as_completed(tasks):
                        try:
                            result = await coro
                            if result:
                                results.append(result)
                                self.results.append(result)
                            pbar.update(1)
                        except Exception as e:
                            logger.error(f"Error processing result: {str(e)}")
                            pbar.update(1)
                            continue

        except Exception as e:
            logger.error(f"Error during scanning: {str(e)}")
            raise
        finally:
            self.session = None

        return sorted(results, key=lambda x: (x['status'], x['content_length']))

    def save_results(self, output_file: str):
        """Save results with additional metadata"""
        try:
            output_data = {
                'target': self.target_url,
                'scan_info': {
                    'total_paths': len(self.results),
                    'threads_used': self.threads,
                    'timeout': self.timeout
                },
                'directories': self.results
            }
            
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=4)
                
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")
            raise

    @staticmethod
    def run_linux_recon(target: str, output_dir: str) -> Dict:
        """Run Linux reconnaissance tools with improved error handling"""
        results = {'amass': False, 'subfinder': False, 'sublister': False}
        os.makedirs(output_dir, exist_ok=True)
        
        for tool, command in {
            'amass': f"amass enum -d {target} -o {output_dir}/amass_results.txt",
            'subfinder': f"subfinder -d {target} -o {output_dir}/subfinder_results.txt",
            'sublister': f"python3 {os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Sublist3r', 'sublist3r.py')} -d {target} -o {output_dir}/sublister_results.txt"
        }.items():
            try:
                subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                results[tool] = True
            except subprocess.CalledProcessError as e:
                logger.error(f"Error running {tool}: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error running {tool}: {str(e)}")
                
        return results 