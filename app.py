from flask import Flask, render_template, request, jsonify, send_file, url_for
import os
import json
from modules.subdomain_scanner import SubdomainScanner
from modules.directory_scanner import DirectoryScanner
from modules.js_analyzer import JSAnalyzer
from config import Config
import platform
import asyncio
import logging

app = Flask(__name__, static_url_path='/static', static_folder='static')
Config.init()

# Logging settings
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan/subdomains', methods=['POST'])
def scan_subdomains():
    data = request.json
    target_domain = data.get('target_domain')
    
    if not target_domain:
        return jsonify({'error': 'Target domain is required'}), 400
    
    # Use reconnaissance tools if on Linux system
    if platform.system().lower() == 'linux':
        output_dir = os.path.join(Config.OUTPUT_DIR, target_domain)
        os.makedirs(output_dir, exist_ok=True)
        
        scanner = DirectoryScanner(target_domain, Config.WORDLIST_PATH)
        recon_results = scanner.run_linux_recon(target_domain, output_dir)
        
        # Read combined results
        combined_results = []
        try:
            with open(os.path.join(output_dir, 'combined_results.txt'), 'r') as f:
                combined_results = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            pass
        
        return jsonify({
            'subdomains': combined_results,
            'recon_results': recon_results,
            'output_dir': output_dir
        })
    
    # Perform normal subdomain scan if not on Linux
    scanner = SubdomainScanner(
        target_domain=target_domain,
        threads=Config.THREADS,
        wordlist_path=Config.WORDLIST_PATH
    )
    
    results = scanner.brute_force_subdomains()
    output_file = os.path.join(Config.OUTPUT_DIR, f"{target_domain}_subdomains.json")
    scanner.save_results(output_file)
    
    return jsonify({
        'subdomains': results,
        'output_file': output_file
    })

@app.route('/api/scan/directories', methods=['POST'])
def scan_directories():
    try:
        data = request.json
        target_url = data.get('target_url')
        
        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        
        scanner = DirectoryScanner(
            target_url=target_url,
            wordlist_path=Config.DIR_WORDLIST,
            threads=Config.THREADS,
            timeout=Config.TIMEOUT
        )
        
        # Get or create event loop
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        # Run async scan
        results = loop.run_until_complete(scanner.scan_directories())
        
        output_file = os.path.join(Config.OUTPUT_DIR, f"{target_url.replace('://', '_').replace('/', '_')}_dirs.json")
        scanner.save_results(output_file)
        
        return jsonify({
            'directories': results,
            'output_file': output_file
        })
    except Exception as e:
        logger.error(f"Directory scanning error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze/js', methods=['POST'])
def analyze_js():
    data = request.json
    target_url = data.get('target_url')
    
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400
    
    analyzer = JSAnalyzer(target_url)
    js_files = analyzer.extract_js_files()
    analysis = analyzer.analyze_js_content()
    
    output_file = os.path.join(Config.OUTPUT_DIR, f"{target_url.replace('://', '_').replace('/', '_')}_js.json")
    analyzer.save_results(output_file)
    
    return jsonify({
        'js_files': js_files,
        'analysis': analysis,
        'output_file': output_file
    })

@app.route('/api/results/<path:filename>')
def get_results(filename):
    try:
        return send_file(
            os.path.join(Config.OUTPUT_DIR, filename),
            as_attachment=True
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 404

if __name__ == '__main__':
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    ) 