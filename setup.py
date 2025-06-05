import os
import platform
import subprocess
import sys
from pathlib import Path

def is_tool_installed(tool_name):
    """Check if a tool is installed and accessible from PATH"""
    try:
        subprocess.run([tool_name, '-version'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE,
                      check=False)
        return True
    except FileNotFoundError:
        return False

def install_go():
    """Install Go if not already installed"""
    if platform.system().lower() == 'windows':
        print("Please install Go manually from https://golang.org/dl/")
        print("After installation, run this setup script again.")
        sys.exit(1)
    else:
        try:
            # Install Go on Linux/macOS
            subprocess.run(['sudo', 'apt-get', 'update'], check=True)
            subprocess.run(['sudo', 'apt-get', 'install', 'golang-go', '-y'], check=True)
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
        
        if platform.system().lower() == 'windows':
            if go_bin not in os.environ['PATH']:
                os.environ['PATH'] += os.pathsep + go_bin
        else:
            # Add to .bashrc or .zshrc
            shell_rc = os.path.expanduser('~/.bashrc')
            if os.path.exists(os.path.expanduser('~/.zshrc')):
                shell_rc = os.path.expanduser('~/.zshrc')
                
            with open(shell_rc, 'a') as f:
                f.write(f'\nexport PATH=$PATH:{go_bin}\n')
            
            print(f"Added {go_bin} to PATH in {shell_rc}")
            print("Please restart your terminal or run: source " + shell_rc)
    except subprocess.CalledProcessError as e:
        print(f"Failed to install Subfinder: {e}")
        sys.exit(1)

def setup_virtual_environment():
    """Create and activate virtual environment"""
    print("Setting up virtual environment...")
    try:
        subprocess.run([sys.executable, '-m', 'venv', 'venv'], check=True)
        
        # Activate virtual environment
        if platform.system().lower() == 'windows':
            activate_script = os.path.join('venv', 'Scripts', 'activate')
        else:
            activate_script = os.path.join('venv', 'bin', 'activate')
            
        print(f"To activate the virtual environment, run:")
        print(f"source {activate_script}")
        
        # Install Python dependencies
        pip_cmd = os.path.join('venv', 'Scripts' if platform.system().lower() == 'windows' else 'bin', 'pip')
        subprocess.run([pip_cmd, 'install', '-r', 'requirements.txt'], check=True)
        
    except subprocess.CalledProcessError as e:
        print(f"Failed to set up virtual environment: {e}")
        sys.exit(1)

def main():
    print("Starting Osint Ninja setup...")
    
    # Check and install required tools
    if not is_tool_installed('subfinder'):
        install_subfinder()
    else:
        print("Subfinder is already installed.")
    
    # Set up Python virtual environment and install dependencies
    setup_virtual_environment()
    
    print("\nSetup completed successfully!")
    print("\nTo start using Osint Ninja:")
    print("1. Activate the virtual environment")
    print("2. Run: python app.py")

if __name__ == "__main__":
    main() 