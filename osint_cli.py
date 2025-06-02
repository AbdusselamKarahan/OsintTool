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

[bold cyan]v1.0.0 - Gelişmiş OSINT Tarama Aracı[/bold cyan]
[yellow]Geliştirici: Abdusselam KARAHAN[/yellow]
"""

USAGE_EXAMPLES = """[bold cyan]Kullanım Örnekleri:[/bold cyan]

1. Tüm taramaları yapma:
   [green]python osint_cli.py -t example.com -m all[/green]

2. Sadece subdomain taraması:
   [green]python osint_cli.py -t example.com -m subdomains[/green]

3. Sadece dizin taraması:
   [green]python osint_cli.py -t example.com -m dirs[/green]

4. Sadece JavaScript analizi:
   [green]python osint_cli.py -t example.com -m js[/green]

5. Özel wordlist ile tarama:
   [green]python osint_cli.py -t example.com -m all -w custom_wordlist.txt[/green]

6. Thread sayısını ayarlama:
   [green]python osint_cli.py -t example.com -m all --threads 20[/green]

7. Özel çıktı dizini belirleme:
   [green]python osint_cli.py -t example.com -m all -o /path/to/output[/green]
"""

def show_full_help():
    """Detaylı yardım mesajını gösterir"""
    console.print(BANNER)
    console.print("\n[bold yellow]DETAYLI KULLANIM KILAVUZU[/bold yellow]")
    console.print("\n[bold cyan]Açıklama:[/bold cyan]")
    console.print("Bu araç, hedef domain veya URL üzerinde OSINT (Open Source Intelligence) taraması yapmak için kullanılır. "
                 "Subdomain keşfi, dizin taraması ve JavaScript analizi gibi temel güvenlik tarama özelliklerini içerir.")

    console.print("\n[bold cyan]Temel Komutlar:[/bold cyan]")
    console.print("""
[green]-t, --target[/green]    : Hedef domain veya URL (örn: example.com veya http://example.com)
[green]-m, --mode[/green]      : Tarama modu seçimi:
                  - [yellow]all[/yellow]: Tüm taramaları yapar (varsayılan)
                  - [yellow]subdomains[/yellow]: Sadece subdomain taraması
                  - [yellow]dirs[/yellow]: Sadece dizin taraması
                  - [yellow]js[/yellow]: Sadece JavaScript analizi
[green]-w, --wordlist[/green]  : Özel wordlist dosyası (opsiyonel)
[green]--threads[/green]       : Thread sayısı (varsayılan: 10)
[green]-o, --output[/green]    : Sonuçların kaydedileceği dizin
[green]-h, --help[/green]      : Bu yardım mesajını gösterir
""")

    console.print("\n[bold cyan]Tarama Modları:[/bold cyan]")
    console.print("""
1. [bold]Subdomain Taraması[/bold] (-m subdomains)
   - DNS kayıtlarını kontrol eder
   - Alt alan adlarını keşfeder
   - IP adreslerini tespit eder
   - HTTP erişilebilirliğini kontrol eder

2. [bold]Dizin Taraması[/bold] (-m dirs)
   - Gizli dizinleri bulur
   - Hassas dosyaları tespit eder
   - HTTP durum kodlarını raporlar
   - Dizin boyutlarını analiz eder

3. [bold]JavaScript Analizi[/bold] (-m js)
   - JavaScript dosyalarını bulur
   - Endpoint'leri tespit eder
   - API anahtarlarını ve hassas bilgileri arar
   - Güvenlik açıklarını analiz eder
""")

    console.print("\n[bold cyan]Çıktı Formatı:[/bold cyan]")
    console.print("""
Sonuçlar [yellow]results/[domain]/[/yellow] dizini altında aşağıdaki formatta kaydedilir:
- [green]subdomains_[timestamp].txt[/green]: Subdomain tarama sonuçları
- [green]directories_[timestamp].txt[/green]: Dizin tarama sonuçları
- [green]javascript_[timestamp].txt[/green]: JavaScript analiz sonuçları
""")

    console.print(USAGE_EXAMPLES)

def setup_args():
    parser = argparse.ArgumentParser(
        description='OSINT Tool - Gelişmiş OSINT Tarama Aracı',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=USAGE_EXAMPLES
    )
    
    parser.add_argument('-t', '--target', required=True, 
                       help='Hedef domain veya URL (örn: example.com veya http://example.com)')
    parser.add_argument('-m', '--mode', choices=['all', 'subdomains', 'dirs', 'js'], 
                       default='all', help='Tarama modu (varsayılan: all - tüm taramaları yapar)')
    parser.add_argument('-w', '--wordlist', 
                       help='Özel wordlist dosyası (opsiyonel)')
    parser.add_argument('--threads', type=int, default=10, 
                       help='Thread sayısı (varsayılan: 10)')
    parser.add_argument('-o', '--output', 
                       help='Sonuçları kaydetmek için dizin (varsayılan: results/domain/)')
    parser.add_argument('--full-help', action='store_true',
                       help='Detaylı kullanım kılavuzunu gösterir')
    
    args = parser.parse_args()
    
    if args.full_help:
        show_full_help()
        sys.exit(0)
        
    return args

def get_base_domain(url):
    """URL veya domain'den base domain'i çıkarır"""
    parsed = urlparse(url if '//' in url else f'http://{url}')
    return parsed.netloc or parsed.path

def ensure_results_dir(domain: str) -> str:
    """Results dizinini ve domain alt dizinini oluşturur"""
    results_dir = os.path.join('results', domain)
    os.makedirs(results_dir, exist_ok=True)
    return results_dir

def get_timestamp() -> str:
    """Şu anki zamanı string olarak döndürür"""
    return datetime.now().strftime('%Y%m%d_%H%M%S')

def open_results_folder(path):
    """Sonuçların bulunduğu klasörü açar"""
    try:
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":  # macOS
            subprocess.run(["open", path])
        else:  # Linux
            subprocess.run(["xdg-open", path])
    except Exception as e:
        console.print(f"[yellow]! Klasör otomatik açılamadı: {path}[/yellow]")

async def scan_directories(args, domain, results_dir):
    """Dizin taraması yapar"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Dizin taraması yapılıyor..."),
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
                f.write(f"# Dizin Tarama Sonuçları - {domain}\n")
                f.write(f"# Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for result in results:
                    f.write(f"{result['url']} - Status: {result['status']} - Size: {result['content_length']} bytes\n")

            console.print(f"\n[bold green]✓ {len(results)} dizin bulundu ve kaydedildi:[/bold green] {output_file}")
        else:
            console.print("\n[yellow]! Dizin bulunamadı[/yellow]")

def scan_subdomains(args, domain, results_dir):
    """Subdomain taraması yapar"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Subdomain taraması yapılıyor..."),
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
                f.write(f"# Subdomain Tarama Sonuçları - {domain}\n")
                f.write(f"# Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                ip_addresses = scanner.get_ip_addresses()
                for subdomain in results:
                    f.write(f"{subdomain} - IP: {ip_addresses.get(subdomain, '---')}\n")

            console.print(f"\n[bold green]✓ {len(results)} subdomain bulundu ve kaydedildi:[/bold green] {output_file}")
        else:
            console.print("\n[yellow]! Subdomain bulunamadı[/yellow]")

def analyze_javascript(args, domain, results_dir):
    """JavaScript analizi yapar"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]JavaScript analizi yapılıyor..."),
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
                f.write(f"# JavaScript Analiz Sonuçları - {domain}\n")
                f.write(f"# Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for file_info in analysis:
                    f.write(f"\nDosya: {file_info['file_url']}\n")
                    if file_info.get('endpoints'):
                        f.write("Endpoints:\n")
                        for endpoint in file_info['endpoints']:
                            f.write(f"  - {endpoint}\n")
                    if file_info.get('sensitive_data'):
                        f.write("Hassas Bilgiler:\n")
                        for data in file_info['sensitive_data']:
                            f.write(f"  - {data}\n")

            console.print(f"\n[bold green]✓ {len(js_files)} JavaScript dosyası analiz edildi ve kaydedildi:[/bold green] {output_file}")
        else:
            console.print("\n[yellow]! JavaScript dosyası bulunamadı[/yellow]")

async def main():
    try:
        Config.init()
        args = setup_args()
        
        # Banner'ı göster
        console.print(BANNER)
        
        # Domain/URL'yi normalize et
        domain = get_base_domain(args.target)
        results_dir = ensure_results_dir(domain)
        
        console.print(f"\n[bold cyan]🎯 Hedef:[/bold cyan] {domain}")
        console.print(f"[bold cyan]📁 Sonuçlar:[/bold cyan] {results_dir}\n")

        # Taramaları yap
        if args.mode in ['all', 'subdomains']:
            scan_subdomains(args, domain, results_dir)
            
        if args.mode in ['all', 'dirs']:
            await scan_directories(args, args.target, results_dir)
            
        if args.mode in ['all', 'js']:
            analyze_javascript(args, args.target, results_dir)

        # Tarama tamamlandı, sonuçlar klasörünü aç
        console.print("\n[bold green]✓ Tarama tamamlandı![/bold green]")
        console.print(f"[bold cyan]📂 Sonuçlar klasörü açılıyor:[/bold cyan] {results_dir}")
        open_results_folder(results_dir)

    except KeyboardInterrupt:
        console.print("\n[bold red]✗ İşlem kullanıcı tarafından durduruldu![/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]✗ Hata: {str(e)}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 