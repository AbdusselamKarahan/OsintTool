import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    # General Settings
    DEBUG = True
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # Subdomain Scanner Settings
    THREADS = int(os.getenv('THREADS', '10'))
    WORDLIST_PATH = os.getenv('WORDLIST_PATH', 'wordlists/subdomains.txt')
    
    # Directory Fuzzing Settings
    DIR_WORDLIST = os.getenv('DIR_WORDLIST', 'wordlists/directories.txt')
    TIMEOUT = int(os.getenv('TIMEOUT', '5'))
    
    # Output Settings
    OUTPUT_DIR = os.getenv('OUTPUT_DIR', 'results')
    
    # Web Interface Settings
    HOST = os.getenv('HOST', '127.0.0.1')
    PORT = int(os.getenv('PORT', '5000'))
    
    @staticmethod
    def init():
        """Create necessary directories if they don't exist"""
        os.makedirs('wordlists', exist_ok=True)
        os.makedirs('results', exist_ok=True)
        os.makedirs('logs', exist_ok=True) 