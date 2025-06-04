from flask import Flask, render_template, request, jsonify, send_file, url_for
import os
import json
from scanners.subdomain_scanner import SubdomainScanner
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

subdomain_scanner = SubdomainScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan/subdomains', methods=['POST'])
async def scan_subdomains():
    try:
        data = request.get_json()
        domain = data.get('target_domain')
        
        if not domain:
            return jsonify({"error": "Target domain is required"}), 400
        
        logger.info(f"Subdomain taraması başlatılıyor: {domain}")
        
        results = {
            "subdomains": [],
            "active_subdomains": [],
            "total_count": 0,
            "active_count": 0,
            "scan_time": 0
        }
        
        async for result in subdomain_scanner.scan_with_progress(domain):
            if result['tool'] == 'Complete':
                return jsonify(result)
            elif result['tool'] == 'Error':
                return jsonify({"error": result['error']}), 500
            elif 'subdomains' in result:
                results["subdomains"].extend(result['subdomains'])
            elif 'active_count' in result:
                results["active_count"] = result['active_count']
                results["total_count"] = result['total_count']
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Tarama hatası: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/directories', methods=['POST'])
async def scan_directories():
    data = request.get_json()
    target_url = data.get('target_url')
    
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400
    
    scanner = DirectoryScanner(
        target_url=target_url,
        wordlist_path=Config.DIR_WORDLIST,
        threads=Config.THREADS,
        timeout=Config.TIMEOUT
    )
    
    try:
        results = await scanner.scan_directories()
        return jsonify({
            'directories': results,
            'total_count': len(results)
        })
    except Exception as e:
        logger.error(f"Dizin tarama hatası: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze/js', methods=['POST'])
def analyze_js():
    data = request.get_json()
    target_url = data.get('target_url')
    
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400
    
    try:
        analyzer = JSAnalyzer(target_url)
        js_files = analyzer.extract_js_files()
        analysis = analyzer.analyze_js_content()
        
        return jsonify({
            'js_files': js_files,
            'analysis': analysis,
            'total_files': len(js_files)
        })
    except Exception as e:
        logger.error(f"JS analiz hatası: {str(e)}")
        return jsonify({'error': str(e)}), 500

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