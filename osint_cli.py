#!/usr/bin/env python3
import argparse
import os
import sys
import asyncio
from modules.directory_scanner import DirectoryScanner
from modules.subdomain_scanner import SubdomainScanner
from modules.js_analyzer import JSAnalyzer
from config import Config
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
from datetime import datetime
from urllib.parse import urlparse
import subprocess
import platform

console = Console()

BANNER = r"""[bold blue]
________         .__        __     _______  .__            __        
\_____  \   _____|__| _____/  |_   \      \ |__| ____     |__|____   
 /   |   \ /  ___/  |/    \   __\  /   |   \|  |/    \    |  \__  \  
/    |    \\___ \|  |   |  \  |   /    |    \  |   |  \   |  |/ __ \_
\_______  /____  >__|___|  /__|   \____|__  /__|___|  /\__|  (____  /
        \/     \/        \/               \/        \/\______|    \/ [/bold blue]

[bold cyan]v1.0.0 - Advanced OSINT Scanning Tool[/bold cyan]
[yellow]Developer: Abdusselam KARAHAN[/yellow]
"""

USAGE_EXAMPLES = """[bold cyan]Usage Examples:[/bold cyan]

1. Run all scans:
   [green]python osint_cli.py -t example.com -m all[/green]

2. Subdomain scan only:
   [green]python osint_cli.py -t example.com -m subdomains[/green]

3. Directory scan only:
   [green]python osint_cli.py -t example.com -m dirs[/green]

4. JavaScript analysis only:
   [green]python osint_cli.py -t example.com -m js[/green]

5. Custom wordlist:
   [green]python osint_cli.py -t example.com -m all -w custom_wordlist.txt[/green]

6. Thread count:
   [green]python osint_cli.py -t example.com -m all --threads 20[/green]

7. Custom output directory:
   [green]python osint_cli.py -t example.com -m all -o /path/to/output[/green]
"""

def show_full_help():
    """Shows detailed help message"""
    console.print(BANNER)
    console.print("\n[bold yellow]DETAILED USAGE GUIDE[/bold yellow]")
    
    console.print("\n[bold cyan]Description:[/bold cyan]")
    console.print("Advanced OSINT scanning tool for target domains and URLs. "
                 "Includes subdomain discovery, directory scanning, and JavaScript analysis.")

    console.print("\n[bold cyan]Basic Commands:[/bold cyan]")
    console.print("""
[green]-t, --target[/green]    : Target domain or URL (e.g., example.com)
[green]-m, --mode[/green]      : Scan mode:
                  - [yellow]all[/yellow]: Run all scans (default)
                  - [yellow]subdomains[/yellow]: Subdomain scan only
                  - [yellow]dirs[/yellow]: Directory scan only
                  - [yellow]js[/yellow]: JavaScript analysis only
[green]-w, --wordlist[/green]  : Custom wordlist file
[green]--threads[/green]       : Number of threads (default: 10)
[green]-o, --output[/green]    : Output directory
[green]-h, --help[/green]      : Show this help message
""")

    console.print("\n[bold cyan]Scan Modes:[/bold cyan]")
    console.print("""
1. [bold]Subdomain Scan[/bold]
   - DNS record checks
   - Subdomain discovery
   - IP resolution
   - HTTP accessibility check

2. [bold]Directory Scan[/bold]
   - Hidden directory discovery
   - Sensitive file detection
   - HTTP status codes
   - Directory size analysis

3. [bold]JavaScript Analysis[/bold]
   - JavaScript file discovery
   - Endpoint detection
   - API key and sensitive data search
   - Security vulnerability analysis
""")

    console.print("\n[bold cyan]Output Format:[/bold cyan]")
    console.print("""
Results are saved in [yellow]results/[domain]/[/yellow] directory:
- [green]subdomains_[timestamp].txt[/green]: Subdomain scan results
- [green]directories_[timestamp].txt[/green]: Directory scan results
- [green]javascript_[timestamp].txt[/green]: JavaScript analysis results
""")

    console.print(USAGE_EXAMPLES)

def setup_args():
    parser = argparse.ArgumentParser(
        description='OSINT Tool - Advanced OSINT Scanning Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=USAGE_EXAMPLES
    )
    
    parser.add_argument('-t', '--target', required=True, 
                       help='Target domain or URL (e.g., example.com)')
    parser.add_argument('-m', '--mode', choices=['all', 'subdomains', 'dirs', 'js'], 
                       default='all', help='Scan mode (default: all - run all scans)')
    parser.add_argument('-w', '--wordlist', 
                       help='Custom wordlist file')
    parser.add_argument('--threads', type=int, default=10, 
                       help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', 
                       help='Output directory')
    parser.add_argument('--full-help', action='store_true',
                       help='Show detailed usage guide')
    
    args = parser.parse_args()
    
    if args.full_help:
        show_full_help()
        sys.exit(0)
        
    return args

def get_base_domain(url):
    """Extracts base domain from URL or domain"""
    parsed = urlparse(url if '//' in url else f'http://{url}')
    return parsed.netloc or parsed.path

def ensure_results_dir(domain: str) -> str:
    """Creates results directory and domain subdirectory"""
    results_dir = os.path.join('results', domain)
    os.makedirs(results_dir, exist_ok=True)
    return results_dir

def get_timestamp() -> str:
    """Returns current time as string"""
    return datetime.now().strftime('%Y%m%d_%H%M%S')

def open_results_folder(path):
    """Opens the directory where results are saved"""
    try:
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":  # macOS
            subprocess.run(["open", path])
        else:  # Linux
            subprocess.run(["xdg-open", path])
    except Exception as e:
        console.print(f"[yellow]! Directory could not be opened: {path}[/yellow]")

async def scan_directories(args, domain, results_dir):
    """Performs directory scan"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Directory scan in progress..."),
        console=console
    ) as progress:
        progress.add_task("scan", total=None)
        
        scanner = DirectoryScanner(
            target_url=f"http://{domain}" if not domain.startswith(('http://', 'https://')) else domain,
            wordlist_path=args.wordlist or Config.DIR_WORDLIST,
            threads=args.threads
        )
        
        results = await scanner.scan_directories()
        
        if results:
            output_file = os.path.join(results_dir, f'directories_{get_timestamp()}.txt')
            with open(output_file, 'w') as f:
                f.write(f"# Directory Scan Results - {domain}\n")
                f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for result in results:
                    f.write(f"{result['url']} - Status: {result['status']} - Size: {result['content_length']} bytes\n")

            console.print(f"\n[bold green]✓ {len(results)} directories found and saved:[/bold green] {output_file}")
        else:
            console.print("\n[yellow]! No directories found[/yellow]")

def scan_subdomains(args, domain, results_dir):
    """Performs subdomain scan"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Subdomain scan in progress..."),
        console=console
    ) as progress:
        progress.add_task("scan", total=None)
        
        scanner = SubdomainScanner(
            target_domain=domain,
            wordlist_path=args.wordlist or Config.WORDLIST_PATH,
            threads=args.threads
        )
        
        results = scanner.brute_force_subdomains()
        
        if results:
            output_file = os.path.join(results_dir, f'subdomains_{get_timestamp()}.txt')
            with open(output_file, 'w') as f:
                f.write(f"# Subdomain Scan Results - {domain}\n")
                f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                ip_addresses = scanner.get_ip_addresses()
                for subdomain in results:
                    f.write(f"{subdomain} - IP: {ip_addresses.get(subdomain, '---')}\n")

            console.print(f"\n[bold green]✓ {len(results)} subdomains found and saved:[/bold green] {output_file}")
        else:
            console.print("\n[yellow]! No subdomains found[/yellow]")

def analyze_javascript(args, domain, results_dir):
    """Performs JavaScript analysis"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]JavaScript analysis in progress..."),
        console=console
    ) as progress:
        progress.add_task("scan", total=None)
        
        target_url = f"http://{domain}" if not domain.startswith(('http://', 'https://')) else domain
        analyzer = JSAnalyzer(target_url)
        js_files = analyzer.extract_js_files()
        analysis = analyzer.analyze_js_content()
        
        if js_files:
            output_file = os.path.join(results_dir, f'javascript_{get_timestamp()}.txt')
            with open(output_file, 'w') as f:
                f.write(f"# JavaScript Analysis Results - {domain}\n")
                f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for file_info in analysis:
                    f.write(f"\nFile: {file_info['file_url']}\n")
                    if file_info.get('endpoints'):
                        f.write("Endpoints:\n")
                        for endpoint in file_info['endpoints']:
                            f.write(f"  - {endpoint}\n")
                    if file_info.get('sensitive_data'):
                        f.write("Sensitive Data:\n")
                        for data in file_info['sensitive_data']:
                            f.write(f"  - {data}\n")

            console.print(f"\n[bold green]✓ {len(js_files)} JavaScript files analyzed and saved:[/bold green] {output_file}")
        else:
            console.print("\n[yellow]! No JavaScript files found[/yellow]")

async def main():
    try:
        Config.init()
        args = setup_args()
        
        # Show banner
        console.print(BANNER)
        
        # Normalize domain/URL
        domain = get_base_domain(args.target)
        results_dir = ensure_results_dir(domain)
        
        console.print(f"\n[bold cyan]🎯 Target:[/bold cyan] {domain}")
        console.print(f"[bold cyan]📁 Results:[/bold cyan] {results_dir}\n")

        # Perform scans
        if args.mode in ['all', 'subdomains']:
            scan_subdomains(args, domain, results_dir)
            
        if args.mode in ['all', 'dirs']:
            await scan_directories(args, args.target, results_dir)
            
        if args.mode in ['all', 'js']:
            analyze_javascript(args, args.target, results_dir)

        # Scan completed, open results folder
        console.print("\n[bold green]✓ Scan completed![/bold green]")
        console.print(f"[bold cyan]📂 Opening results folder:[/bold cyan] {results_dir}")
        open_results_folder(results_dir)

    except KeyboardInterrupt:
        console.print("\n[bold red]✗ Scan interrupted by user![/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]✗ Error: {str(e)}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 