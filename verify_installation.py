#!/usr/bin/env python3
"""
BackdoorBuster Installation Verification
Quick test to verify installation is working correctly
"""

import sys
import subprocess
from pathlib import Path

def test_python_version():
    """Test Python version"""
    print("🐍 Testing Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} - OK")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro} - Need 3.8+")
        return False

def test_dependencies():
    """Test core dependencies"""
    print("\n📦 Testing core dependencies...")
    
    core_deps = ['flask', 'jinja2']
    optional_deps = ['termcolor', 'psutil', 'psycopg2', 'cryptography', 'yara']
    
    results = {}
    
    # Test core dependencies
    for dep in core_deps:
        try:
            __import__(dep)
            print(f"✅ {dep} - Available")
            results[dep] = True
        except ImportError:
            print(f"❌ {dep} - Missing (required)")
            results[dep] = False
    
    # Test optional dependencies
    for dep in optional_deps:
        try:
            __import__(dep)
            print(f"✅ {dep} - Available")
            results[dep] = True
        except ImportError:
            print(f"⚠️ {dep} - Missing (optional)")
            results[dep] = False
    
    return results

def test_files():
    """Test required files"""
    print("\n📁 Testing required files...")
    
    required_files = [
        'main.py',
        'config.json.example',
        'requirements_core.txt',
        'templates/log.html',
        'rules/yara_rules.yar'
    ]
    
    base_dir = Path(__file__).parent
    all_good = True
    
    for file_path in required_files:
        full_path = base_dir / file_path
        if full_path.exists():
            print(f"✅ {file_path} - Found")
        else:
            print(f"❌ {file_path} - Missing")
            all_good = False
    
    return all_good

def test_application():
    """Test application startup"""
    print("\n🚀 Testing application startup...")
    
    try:
        result = subprocess.run([sys.executable, 'main.py', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ Application version: {result.stdout.strip()}")
            return True
        else:
            print(f"❌ Application failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ Application startup timeout")
        return False
    except Exception as e:
        print(f"❌ Application test error: {e}")
        return False

def main():
    """Run all tests"""
    print("🛡️ BackdoorBuster Installation Verification")
    print("=" * 50)
    
    tests = [
        ("Python Version", test_python_version),
        ("Dependencies", test_dependencies),
        ("Required Files", test_files),
        ("Application Startup", test_application)
    ]
    
    all_passed = True
    
    for test_name, test_func in tests:
        result = test_func()
        if not result:
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 All tests passed! BackdoorBuster is ready to use.")
        print("\nTo start using BackdoorBuster:")
        print("  • python main.py --help")
        print("  • python main.py --web-server")
    else:
        print("⚠️ Some tests failed. Check the output above for issues.")
        print("\nTo fix issues:")
        print("  • Run the installer again: python install.py")
        print("  • Install missing dependencies: pip install -r requirements_core.txt")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
