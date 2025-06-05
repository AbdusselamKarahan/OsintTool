import os
import platform
import subprocess
import sys
import time
from pathlib import Path

def is_root():
    """Check if the script is running with root privileges on Linux"""
    return os.geteuid() == 0 if platform.system().lower() != 'windows' else True

def is_tool_installed(tool_name):
    """Check if a tool is installed and accessible from PATH"""
    try:
        if platform.system().lower() == 'windows':
            tool_cmd = f"{tool_name}.exe"
        else:
            tool_cmd = tool_name
            
        subprocess.run([tool_cmd, '-version'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE,
                      check=False)
        return True
    except FileNotFoundError:
        return False

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("Error: Python 3.7 or higher is required")
        sys.exit(1)

def update_requirements():
    """Update requirements.txt with async Flask dependencies"""
    requirements = [
        "flask>=2.0.0",
        "flask[async]",
        "asgiref>=3.2.0",
        "hypercorn>=0.13.0",
        "quart>=0.18.0",
        "aiohttp>=3.8.0",
        "requests",
        "python-dotenv",
        "beautifulsoup4",
        "tqdm",
        "dnspython"
    ]
    
    with open('requirements.txt', 'w') as f:
        f.write('\n'.join(requirements))

def install_system_dependencies():
    """Install system-level dependencies based on OS"""
    system = platform.system().lower()
    
    if system == 'linux':
        if not is_root():
            print("Error: This script needs root privileges to install system dependencies.")
            print("Please run with sudo.")
            sys.exit(1)
            
        try:
            # Update package lists
            print("Updating package lists...")
            subprocess.run(['apt-get', 'update'], check=True)
            
            # Install required packages
            packages = [
                'golang-go',  # For subfinder
                'python3-dev',
                'python3-pip',
                'python3-venv',
                'build-essential',
                'libssl-dev',
                'libffi-dev',
                'git'
            ]
            
            print("Installing system dependencies...")
            subprocess.run(['apt-get', 'install', '-y'] + packages, check=True)
            
        except subprocess.CalledProcessError as e:
            print(f"Error installing system dependencies: {e}")
            print("Please install the following packages manually:")
            print("- golang-go")
            print("- python3-dev")
            print("- python3-pip")
            print("- python3-venv")
            print("- build-essential")
            print("- libssl-dev")
            print("- libffi-dev")
            print("- git")
            sys.exit(1)
    
    elif system == 'darwin':  # macOS
        try:
            # Check if Homebrew is installed
            if not is_tool_installed('brew'):
                print("Installing Homebrew...")
                subprocess.run(['/bin/bash', '-c', '$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)'], check=True)
            
            # Install required packages
            print("Installing system dependencies...")
            subprocess.run(['brew', 'install', 'go', 'git', 'python3'], check=True)
            
        except subprocess.CalledProcessError as e:
            print(f"Error installing system dependencies: {e}")
            print("Please install the following packages manually:")
            print("- go")
            print("- git")
            print("- python3")
            sys.exit(1)

def install_go():
    """Install Go if not already installed"""
    system = platform.system().lower()
    
    if system == 'windows':
        print("Please install Go manually from https://golang.org/dl/")
        print("After installation, run this setup script again.")
        sys.exit(1)
    elif system == 'linux':
        try:
            subprocess.run(['apt-get', 'install', 'golang-go', '-y'], check=True)
        except subprocess.CalledProcessError:
            print("Failed to install Go. Please install it manually from https://golang.org/dl/")
            sys.exit(1)
    elif system == 'darwin':
        try:
            subprocess.run(['brew', 'install', 'go'], check=True)
        except subprocess.CalledProcessError:
            print("Failed to install Go. Please install it manually from https://golang.org/dl/")
            sys.exit(1)

def install_subfinder():
    """Install Subfinder using Go"""
    if not is_tool_installed('go'):
        print("Installing Go...")
        install_go()
    
    print("Installing Subfinder...")
    try:
        subprocess.run(['go', 'install', '-v', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'], check=True)
        
        # Add GOPATH/bin to PATH if not already added
        go_path = subprocess.run(['go', 'env', 'GOPATH'], 
                               capture_output=True, 
                               text=True, 
                               check=True).stdout.strip()
        go_bin = os.path.join(go_path, 'bin')
        
        system = platform.system().lower()
        if system == 'windows':
            if go_bin not in os.environ['PATH']:
                os.environ['PATH'] += os.pathsep + go_bin
        else:
            # Add to appropriate shell config file
            shell_rc = None
            if os.path.exists(os.path.expanduser('~/.zshrc')):
                shell_rc = os.path.expanduser('~/.zshrc')
            elif os.path.exists(os.path.expanduser('~/.bashrc')):
                shell_rc = os.path.expanduser('~/.bashrc')
            
            if shell_rc:
                with open(shell_rc, 'a') as f:
                    f.write(f'\nexport PATH=$PATH:{go_bin}\n')
                print(f"Added {go_bin} to PATH in {shell_rc}")
                print(f"Please run: source {shell_rc}")
            
            # Also add to current session
            os.environ['PATH'] += os.pathsep + go_bin
            
    except subprocess.CalledProcessError as e:
        print(f"Failed to install Subfinder: {e}")
        sys.exit(1)

def safe_remove_venv():
    """Safely remove virtual environment"""
    if os.path.exists('venv'):
        print("Removing existing virtual environment...")
        system = platform.system().lower()
        try:
            if system == 'windows':
                subprocess.run(['rmdir', '/s', '/q', 'venv'], shell=True, check=True)
            else:
                subprocess.run(['rm', '-rf', 'venv'], check=True)
        except subprocess.CalledProcessError:
            print("Warning: Could not remove existing virtual environment.")
            print("Please remove the 'venv' directory manually and try again.")
            sys.exit(1)

def setup_virtual_environment():
    """Create and activate virtual environment"""
    print("Setting up virtual environment...")
    try:
        # Safely remove existing venv
        safe_remove_venv()
        
        # Create new virtual environment
        subprocess.run([sys.executable, '-m', 'venv', 'venv'], check=True)
        
        # Update requirements.txt with async dependencies
        update_requirements()
        
        # Determine correct pip and activation script paths
        system = platform.system().lower()
        if system == 'windows':
            pip_cmd = os.path.join('venv', 'Scripts', 'pip')
            activate_script = os.path.join('venv', 'Scripts', 'activate')
        else:
            pip_cmd = os.path.join('venv', 'bin', 'pip')
            activate_script = os.path.join('venv', 'bin', 'activate')
        
        print(f"\nTo activate the virtual environment, run:")
        if system == 'windows':
            print(f".\\{activate_script}")
        else:
            print(f"source {activate_script}")
        
        # Upgrade pip
        subprocess.run([pip_cmd, 'install', '--upgrade', 'pip'], check=True)
        
        # Install Python dependencies
        print("\nInstalling Python dependencies...")
        subprocess.run([pip_cmd, 'install', '-r', 'requirements.txt'], check=True)
        
    except subprocess.CalledProcessError as e:
        print(f"Failed to set up virtual environment: {e}")
        sys.exit(1)

def main():
    print("Starting Osint Ninja setup...")
    
    # Check Python version
    check_python_version()
    
    # Install system dependencies
    system = platform.system().lower()
    if system != 'windows':
        install_system_dependencies()
    
    # Check and install required tools
    if not is_tool_installed('subfinder'):
        install_subfinder()
    else:
        print("Subfinder is already installed.")
    
    # Set up Python virtual environment and install dependencies
    setup_virtual_environment()
    
    print("\nSetup completed successfully!")
    print("\nTo start using Osint Ninja:")
    if platform.system().lower() == 'windows':
        print("1. Run: .\\venv\\Scripts\\activate")
    else:
        print("1. Run: source venv/bin/activate")
    print("2. Run: python app.py")

if __name__ == "__main__":
    main() 