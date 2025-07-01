#!/usr/bin/env python3
"""
GitHub Deployment Test Script
Tests BackdoorBuster after cloning from GitHub

Usage:
python github_test.py
"""

import os
import sys
import subprocess
from pathlib import Path

def test_github_deployment():
    """Test BackdoorBuster deployment from GitHub"""
    print("🧪 Testing BackdoorBuster GitHub Deployment")
    print("=" * 50)
    
    # Check if we're in the right directory
    required_files = ['main.py', 'install.py', 'README.md', 'LICENSE']
    missing_files = [f for f in required_files if not Path(f).exists()]
    
    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        print("Make sure you're in the BackdoorBuster directory")
        return False
    
    print("✅ All required files present")
    
    # Test Python version
    try:
        python_version = sys.version_info
        if python_version.major >= 3 and python_version.minor >= 8:
            print(f"✅ Python {python_version.major}.{python_version.minor} detected")
        else:
            print(f"❌ Python 3.8+ required, found {python_version.major}.{python_version.minor}")
            return False
    except Exception as e:
        print(f"❌ Python version check failed: {e}")
        return False
    
    # Test main.py version command
    try:
        result = subprocess.run([sys.executable, 'main.py', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and 'BackdoorBuster v1.0' in result.stdout:
            print("✅ Version command works")
        else:
            print(f"❌ Version command failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Version command test failed: {e}")
        return False
    
    # Test help command
    try:
        result = subprocess.run([sys.executable, 'main.py', '--help'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ Help command works")
        else:
            print(f"❌ Help command failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Help command test failed: {e}")
        return False
    
    print("\n🎉 GitHub deployment test PASSED!")
    print("\nNext steps:")
    print("1. Run installer: python install.py")
    print("2. Test application: python main.py")
    print("3. Try web interface: python main.py --web-server")
    
    return True

if __name__ == "__main__":
    success = test_github_deployment()
    sys.exit(0 if success else 1)
