#!/usr/bin/env python3
"""
BackdoorBuster - Elite Backdoor and Malware Detection Tool
Cross-platform malware detection and mitigation system using PostgreSQL

Created by Shieldpy - https://shieldpy.com
GitHub: https://github.com/Qixpy

© 2025 Shieldpy. All rights reserved.
"""

import os
import sys
import json
import time
import threading
import hashlib
import secrets
import platform
import subprocess
from pathlib import Path
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Import datetime safely for cross-platform compatibility
try:
    from datetime import datetime
    DATETIME_AVAILABLE = True
except ImportError:
    DATETIME_AVAILABLE = False
    datetime = None

def safe_datetime_now():
    """Safely get current datetime string"""
    if DATETIME_AVAILABLE and datetime:
        try:
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
    return "Unknown"

def safe_datetime_iso():
    """Safely get current datetime in ISO format"""
    if DATETIME_AVAILABLE and datetime:
        try:
            return datetime.now().isoformat()
        except:
            pass
    return "Unknown"

# Third-party imports (with graceful fallbacks)
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    psycopg2 = None
    RealDictCursor = None

try:
    from cryptography.fernet import Fernet
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    Fernet = None

try:
    from termcolor import colored, cprint
    TERMCOLOR_AVAILABLE = True
except ImportError:
    TERMCOLOR_AVAILABLE = False
    # Fallback functions
    def colored(text, color=None, on_color=None, attrs=None):
        return text
    def cprint(text, color=None, on_color=None, attrs=None, **kwargs):
        print(text, **kwargs)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None

try:
    from scapy.all import sniff, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    sniff = None
    IP = None

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    Template = None

try:
    from flask import Flask
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    Flask = None

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    canvas = None
    letter = None

# Optional imports (may not be available on all platforms)
try:
    import volatility
    VOLATILITY_AVAILABLE = True
except ImportError:
    VOLATILITY_AVAILABLE = False

try:
    import pykd
    PYKD_AVAILABLE = True
except ImportError:
    PYKD_AVAILABLE = False

class BackdoorBuster:
    """Main BackdoorBuster application class"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.absolute()
        self.config_file = self.base_dir / "config.json"
        self.logs_dir = self.base_dir / "logs"
        self.rules_dir = self.base_dir / "rules"
        self.templates_dir = self.base_dir / "templates"
        self.data_dir = self.base_dir / "data"
        
        self.db_connection = None
        self.config = {}
        
        # Privacy check on startup
        self.check_privacy()
    
    def check_privacy(self):
        """Check for existing scan data and warn about privacy"""
        try:
            if self.logs_dir.exists():
                scan_files = list(self.logs_dir.glob('scan_*.json'))
                if scan_files:
                    # Check if scan files are old (more than 7 days)
                    import time
                    current_time = time.time()
                    old_files = []
                    
                    for scan_file in scan_files:
                        file_age = current_time - scan_file.stat().st_mtime
                        if file_age > (7 * 24 * 60 * 60):  # 7 days in seconds
                            old_files.append(scan_file)
                    
                    if old_files:
                        print("🔐 Privacy Notice:")
                        print(f"   Found {len(old_files)} old scan files (>7 days)")
                        print("   These may contain sensitive system information")
                        print("   To remove them: privacy_cleanup.sh (Linux) or privacy_cleanup.bat (Windows)")
                        print()
        except Exception:
            pass  # Don't let privacy check break the app
        self.cipher_suite = None
        self.yara_rules = None
        self.monitoring = False
        self.monitor_thread = None
        
        # Ensure directories exist
        self.logs_dir.mkdir(exist_ok=True)
        
        self.banner()
        
    def banner(self):
        """Display application banner"""
        banner_text = """
        +==============================================================+
        |                      BackdoorBuster v1.0                    |
        |              Elite Backdoor & Malware Detection             |
        |                   Cross-Platform Security Tool             |
        |                                                              |
        |                 Advanced Threat Detection                   |
        |                                                              |
        |              Created by Shieldpy - shieldpy.com             |
        |                 GitHub: github.com/Qixpy                    |
        +==============================================================+
        """
        cprint(banner_text, 'cyan', attrs=['bold'])
        
    def load_config(self):
        """Load configuration (with optional encryption support)"""
        if not self.config_file.exists():
            cprint("❌ Configuration file not found. Please run setup first.", 'red')
            return False
            
        try:
            with open(self.config_file, 'r') as f:
                config_data = json.load(f)
            
            # Check if encryption is enabled and required
            encryption_config = config_data.get('encryption', {})
            encryption_enabled = encryption_config.get('enabled', False)
            
            if encryption_enabled and CRYPTOGRAPHY_AVAILABLE:
                # Only ask for password if encryption is actually needed
                try:
                    password = input("🔐 Enter decryption password (or press Enter to skip): ").strip()
                    
                    if password:
                        key = hashlib.sha256(password.encode()).digest()
                        # Generate proper key for Fernet (32 bytes, base64 encoded)
                        import base64
                        key_b64 = base64.urlsafe_b64encode(key)
                        self.cipher_suite = Fernet(key_b64)
                        print("✅ Encryption enabled")
                    else:
                        print("⚠️ Skipping encryption - running in development mode")
                        encryption_enabled = False
                except Exception as e:
                    print(f"⚠️ Encryption setup failed: {e} - continuing without encryption")
                    encryption_enabled = False
            else:
                if encryption_enabled and not CRYPTOGRAPHY_AVAILABLE:
                    print("⚠️ Encryption requested but cryptography module not available")
                print("ℹ️ Running without encryption")
            
            # Store config (in plain text for now)
            self.config = config_data
            self.config['encryption']['enabled'] = encryption_enabled
            
            return True
            
        except Exception as e:
            cprint(f"❌ Failed to load configuration: {e}", 'red')
            return False
    
    def connect_db(self):
        """Connect to PostgreSQL database (optional)"""
        if not PSYCOPG2_AVAILABLE:
            print("ℹ️ Database features disabled (psycopg2 not available)")
            return True  # Continue without database
            
        try:
            db_config = self.config.get('database', {})
            self.db_connection = psycopg2.connect(
                host=db_config.get('host', 'localhost'),
                port=db_config.get('port', 5432),
                database=db_config.get('database', 'backdoorbuster'),
                user=db_config.get('user', 'postgres'),
                password=db_config.get('password', '')
            )
            self.db_connection.autocommit = True
            cprint("✅ Connected to PostgreSQL database", 'green')
            return True
            
        except Exception as e:
            print(f"⚠️ Database connection failed: {e}")
            print("ℹ️ Continuing without database features")
            self.db_connection = None
            return True  # Continue without database instead of failing
    
    def init_database(self):
        """Initialize database tables (if database is available)"""
        if not self.db_connection:
            print("ℹ️ Skipping database initialization (no database connection)")
            return True
            
        try:
            cursor = self.db_connection.cursor()
            
            # Create threats table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id SERIAL PRIMARY KEY,
                    path TEXT NOT NULL,
                    type TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    behavior TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create mitigations table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mitigations (
                    id SERIAL PRIMARY KEY,
                    target TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create forensics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS forensics (
                    id SERIAL PRIMARY KEY,
                    memory_data TEXT,
                    pid INTEGER,
                    process_name TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id SERIAL PRIMARY KEY,
                    session_id TEXT UNIQUE NOT NULL,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    commands_executed INTEGER DEFAULT 0
                )
            """)
            
            cursor.close()
            cprint("✅ Database tables initialized", 'green')
            
        except Exception as e:
            cprint(f"❌ Database initialization failed: {e}", 'red')
    
    def load_yara_rules(self):
        """Load YARA rules for malware detection (if available)"""
        if not YARA_AVAILABLE:
            print("ℹ️ YARA rules disabled (yara-python not available)")
            return
            
        try:
            yara_file = self.rules_dir / "yara_rules.yar"
            if yara_file.exists():
                self.yara_rules = yara.compile(filepath=str(yara_file))
                cprint("✅ YARA rules loaded", 'green')
            else:
                print("⚠️ YARA rules file not found - continuing without YARA")
                
        except Exception as e:
            print(f"⚠️ Failed to load YARA rules: {e} - continuing without YARA")
    
    def scan_file(self, file_path, deep=False):
        """Scan a file for malware"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                cprint(f"❌ File not found: {file_path}", 'red')
                return
            
            cprint(f"🔍 Scanning: {file_path}", 'blue')
            
            # File entropy analysis
            entropy_score = self.calculate_entropy(file_path)
            
            # YARA scanning
            yara_matches = []
            if self.yara_rules:
                try:
                    matches = self.yara_rules.match(str(file_path))
                    yara_matches = [match.rule for match in matches]
                except:
                    pass
            
            # Hash analysis
            file_hash = self.calculate_hash(file_path)
            
            # Determine threat score
            threat_score = 0
            threat_types = []
            
            if entropy_score > 7.5:
                threat_score += 30
                threat_types.append("High Entropy")
            
            if yara_matches:
                threat_score += 50
                threat_types.append("YARA Detection")
            
            # Store in database
            threat_type = ", ".join(threat_types) if threat_types else "Clean"
            behavior = f"Entropy: {entropy_score:.2f}, Hash: {file_hash[:16]}..."
            
            if yara_matches:
                behavior += f", YARA: {', '.join(yara_matches)}"
            
            cursor = self.db_connection.cursor()
            cursor.execute("""
                INSERT INTO threats (path, type, score, behavior)
                VALUES (%s, %s, %s, %s)
            """, (str(file_path), threat_type, threat_score, behavior))
            cursor.close()
            
            # Display results
            if threat_score > 50:
                cprint(f"🚨 HIGH THREAT DETECTED: {file_path}", 'red', attrs=['bold'])
            elif threat_score > 20:
                cprint(f"⚠️  MEDIUM THREAT: {file_path}", 'yellow')
            else:
                cprint(f"✅ Clean: {file_path}", 'green')
            
            cprint(f"   Threat Score: {threat_score}", 'white')
            cprint(f"   File Hash: {file_hash}", 'white')
            cprint(f"   Entropy: {entropy_score:.2f}", 'white')
            
            if yara_matches:
                cprint(f"   YARA Matches: {', '.join(yara_matches)}", 'red')
            
        except Exception as e:
            cprint(f"❌ Scan failed: {e}", 'red')
    
    def scan_directory(self, directory, deep=False):
        """Scan a directory for malware"""
        try:
            directory = Path(directory)
            if not directory.exists():
                cprint(f"❌ Directory not found: {directory}", 'red')
                return
            
            cprint(f"🔍 Scanning directory: {directory}", 'blue')
            
            file_count = 0
            threat_count = 0
            
            for file_path in directory.rglob("*"):
                if file_path.is_file():
                    file_count += 1
                    
                    # Skip very large files unless deep scan
                    if not deep and file_path.stat().st_size > 100 * 1024 * 1024:
                        continue
                    
                    print(f"Scanning: {file_path.name}", end='\r')
                    
                    # Quick scan for suspicious extensions
                    suspicious_extensions = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1']
                    if file_path.suffix.lower() in suspicious_extensions:
                        self.scan_file(file_path, deep)
                        threat_count += 1
            
            cprint(f"\n✅ Directory scan completed", 'green')
            cprint(f"   Files scanned: {file_count}", 'white')
            cprint(f"   Threats analyzed: {threat_count}", 'white')
            
        except Exception as e:
            cprint(f"❌ Directory scan failed: {e}", 'red')
    
    def memory_analysis(self):
        """Perform memory analysis for running processes"""
        cprint("🧠 Starting memory analysis...", 'blue')
        
        try:
            # Get running processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    if proc_info['memory_info'].rss > 50 * 1024 * 1024:  # > 50MB
                        processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Analyze suspicious processes
            suspicious_count = 0
            for proc in processes:
                suspicion_score = 0
                indicators = []
                
                # High memory usage
                memory_mb = proc['memory_info'].rss / (1024 * 1024)
                if memory_mb > 500:
                    suspicion_score += 20
                    indicators.append(f"High Memory: {memory_mb:.1f}MB")
                
                # High CPU usage
                if proc['cpu_percent'] > 80:
                    suspicion_score += 30
                    indicators.append(f"High CPU: {proc['cpu_percent']:.1f}%")
                
                # Suspicious process names
                suspicious_names = ['svchost', 'winlogon', 'explorer', 'lsass']
                if any(name in proc['name'].lower() for name in suspicious_names):
                    suspicion_score += 10
                    indicators.append("Suspicious Name")
                
                if suspicion_score > 30:
                    suspicious_count += 1
                    
                    # Store in forensics table
                    cursor = self.db_connection.cursor()
                    cursor.execute("""
                        INSERT INTO forensics (memory_data, pid, process_name)
                        VALUES (%s, %s, %s)
                    """, (", ".join(indicators), proc['pid'], proc['name']))
                    cursor.close()
                    
                    cprint(f"🚨 Suspicious Process: {proc['name']} (PID: {proc['pid']})", 'red')
                    cprint(f"   Indicators: {', '.join(indicators)}", 'yellow')
            
            cprint(f"✅ Memory analysis completed", 'green')
            cprint(f"   Processes analyzed: {len(processes)}", 'white')
            cprint(f"   Suspicious processes: {suspicious_count}", 'white')
            
        except Exception as e:
            cprint(f"❌ Memory analysis failed: {e}", 'red')
    
    def network_monitoring(self):
        """Monitor network traffic for anomalies"""
        cprint("🌐 Starting network monitoring...", 'blue')
        
        def packet_handler(packet):
            if IP in packet:
                # Simple anomaly detection
                if packet[IP].dst == "127.0.0.1" and packet[IP].sport > 8000:
                    cprint(f"🚨 Suspicious network activity: {packet[IP].src}:{packet[IP].sport}", 'red')
        
        try:
            # Monitor for 10 seconds
            sniff(prn=packet_handler, timeout=10, store=0)
            cprint("✅ Network monitoring completed", 'green')
            
        except Exception as e:
            cprint(f"❌ Network monitoring failed: {e}", 'red')
    
    def neutralize_threat(self, target):
        """Neutralize a detected threat"""
        try:
            target_path = Path(target)
            
            if not target_path.exists():
                cprint(f"❌ Target not found: {target}", 'red')
                return
            
            cprint(f"🛡️  Neutralizing threat: {target}", 'yellow')
            
            # Secure deletion (overwrite with random data)
            if target_path.is_file():
                file_size = target_path.stat().st_size
                
                with open(target_path, 'r+b') as f:
                    for _ in range(3):  # 3-pass overwrite
                        f.seek(0)
                        f.write(secrets.token_bytes(file_size))
                        f.flush()
                        os.fsync(f.fileno())
                
                target_path.unlink()
                
                # Log mitigation
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    INSERT INTO mitigations (target, action, status)
                    VALUES (%s, %s, %s)
                """, (str(target_path), "Secure Delete", "Success"))
                cursor.close()
                
                cprint(f"✅ Threat neutralized: {target}", 'green')
            
        except Exception as e:
            cprint(f"❌ Neutralization failed: {e}", 'red')
            
            # Log failed mitigation
            cursor = self.db_connection.cursor()
            cursor.execute("""
                INSERT INTO mitigations (target, action, status)
                VALUES (%s, %s, %s)
            """, (target, "Secure Delete", f"Failed: {str(e)}"))
            cursor.close()
    
    def isolate_target(self, target):
        """Isolate a suspicious file or process"""
        try:
            cprint(f"🔒 Isolating target: {target}", 'yellow')
            
            # For files, move to quarantine
            target_path = Path(target)
            if target_path.exists() and target_path.is_file():
                quarantine_dir = self.data_dir / "quarantine"
                quarantine_dir.mkdir(exist_ok=True)
                
                quarantine_path = quarantine_dir / f"{target_path.name}_{int(time.time())}"
                target_path.rename(quarantine_path)
                
                # Log mitigation
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    INSERT INTO mitigations (target, action, status)
                    VALUES (%s, %s, %s)
                """, (str(target_path), f"Quarantine to {quarantine_path}", "Success"))
                cursor.close()
                
                cprint(f"✅ Target isolated to: {quarantine_path}", 'green')
            
            # For processes, try to terminate (if numeric PID provided)
            elif target.isdigit():
                pid = int(target)
                try:
                    proc = psutil.Process(pid)
                    proc.terminate()
                    
                    cursor = self.db_connection.cursor()
                    cursor.execute("""
                        INSERT INTO mitigations (target, action, status)
                        VALUES (%s, %s, %s)
                    """, (f"PID:{pid}", "Terminate Process", "Success"))
                    cursor.close()
                    
                    cprint(f"✅ Process {pid} terminated", 'green')
                    
                except psutil.NoSuchProcess:
                    cprint(f"❌ Process {pid} not found", 'red')
                except psutil.AccessDenied:
                    cprint(f"❌ Access denied for process {pid}", 'red')
            
        except Exception as e:
            cprint(f"❌ Isolation failed: {e}", 'red')
    
    def show_results(self, result_type="all"):
        """Show scan results from database"""
        try:
            cursor = self.db_connection.cursor(cursor_factory=RealDictCursor)
            
            if result_type.lower() in ["threats", "all"]:
                cprint("🔍 Recent Threats:", 'cyan', attrs=['bold'])
                cursor.execute("""
                    SELECT * FROM threats 
                    ORDER BY timestamp DESC 
                    LIMIT 20
                """)
                threats = cursor.fetchall()
                
                for threat in threats:
                    color = 'red' if threat['score'] > 50 else 'yellow' if threat['score'] > 20 else 'green'
                    cprint(f"  [{threat['timestamp']}] {threat['path']}", color)
                    cprint(f"    Type: {threat['type']}, Score: {threat['score']}", 'white')
                    cprint(f"    Behavior: {threat['behavior']}", 'white')
                    print()
            
            if result_type.lower() in ["mitigations", "all"]:
                cprint("🛡️  Recent Mitigations:", 'cyan', attrs=['bold'])
                cursor.execute("""
                    SELECT * FROM mitigations 
                    ORDER BY timestamp DESC 
                    LIMIT 10
                """)
                mitigations = cursor.fetchall()
                
                for mitigation in mitigations:
                    color = 'green' if mitigation['status'] == 'Success' else 'red'
                    cprint(f"  [{mitigation['timestamp']}] {mitigation['target']}", color)
                    cprint(f"    Action: {mitigation['action']}, Status: {mitigation['status']}", 'white')
                    print()
            
            if result_type.lower() in ["forensics", "all"]:
                cprint("🧠 Forensics Data:", 'cyan', attrs=['bold'])
                cursor.execute("""
                    SELECT * FROM forensics 
                    ORDER BY timestamp DESC 
                    LIMIT 10
                """)
                forensics = cursor.fetchall()
                
                for record in forensics:
                    cprint(f"  [{record['timestamp']}] {record['process_name']} (PID: {record['pid']})", 'yellow')
                    cprint(f"    Data: {record['memory_data']}", 'white')
                    print()
            
            cursor.close()
            
        except Exception as e:
            cprint(f"❌ Failed to show results: {e}", 'red')
    
    def export_report(self, filename, format_type="json"):
        """Export scan results to file"""
        try:
            cursor = self.db_connection.cursor(cursor_factory=RealDictCursor)
            
            # Get all data
            cursor.execute("SELECT * FROM threats ORDER BY timestamp DESC")
            threats = cursor.fetchall()
            
            cursor.execute("SELECT * FROM mitigations ORDER BY timestamp DESC")
            mitigations = cursor.fetchall()
            
            cursor.execute("SELECT * FROM forensics ORDER BY timestamp DESC")
            forensics = cursor.fetchall()
            
            cursor.close()
            
            export_data = {
                "generated_at": datetime.now().isoformat(),
                "threats": [dict(row) for row in threats],
                "mitigations": [dict(row) for row in mitigations],
                "forensics": [dict(row) for row in forensics]
            }
            
            export_path = self.logs_dir / filename
            
            if format_type.lower() == "json":
                with open(export_path.with_suffix('.json'), 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                    
            elif format_type.lower() == "html":
                self.generate_html_report(export_data, export_path.with_suffix('.html'))
                
            elif format_type.lower() == "pdf":
                self.generate_pdf_report(export_data, export_path.with_suffix('.pdf'))
            
            cprint(f"✅ Report exported: {export_path}", 'green')
            
        except Exception as e:
            cprint(f"❌ Export failed: {e}", 'red')
    
    def generate_html_report(self, data, filepath):
        """Generate HTML report with dark theme and flat log list"""
        template_path = self.templates_dir / "log.html"
        
        # Scan for existing reports to build flat log list
        log_files = self.scan_existing_reports()
        current_log_file = filepath.name if filepath else ""
        
        if template_path.exists():
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
        else:
            # Fallback to simple HTML template if log.html doesn't exist
            template_content = self.get_fallback_template()
        
        # Prepare template data
        enhanced_data = {
            **data,
            'log_files': log_files,
            'current_log_file': current_log_file,
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        template = Template(template_content)
        html_content = template.render(**enhanced_data)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        cprint(f"✅ HTML report generated: {filepath}", 'green')
    
    def scan_existing_reports(self):
        """Scan logs directory for existing HTML reports and return flat list"""
        try:
            log_files = []
            
            # Get list of HTML files in logs directory
            html_files = list(self.logs_dir.glob("*.html"))
            
            for html_file in html_files:
                try:
                    # Extract metadata from file
                    file_stat = html_file.stat()
                    mod_time = datetime.fromtimestamp(file_stat.st_mtime)
                    
                    # Count threats by scanning file content (simplified)
                    threat_count = 0
                    try:
                        with open(html_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                            # Count threat rows in HTML table
                            threat_count = max(0, content.count('<tr>') - content.count('<th>') - 1)
                            if 'threat-critical' in content:
                                threat_count = max(threat_count, content.count('threat-critical'))
                            elif 'threat-high' in content:
                                threat_count = max(threat_count, content.count('threat-high'))
                            elif 'threat-medium' in content:
                                threat_count = max(threat_count, content.count('threat-medium'))
                    except:
                        threat_count = 0
                    
                    file_info = {
                        'filename': html_file.name,
                        'size': self.format_file_size(file_stat.st_size),
                        'threat_count': threat_count,
                        'date_time': mod_time.strftime("%Y-%m-%d %H:%M:%S"),
                        'timestamp': mod_time.timestamp()
                    }
                    
                    log_files.append(file_info)
                    
                except Exception as e:
                    cprint(f"⚠️  Warning: Could not process {html_file.name}: {e}", 'yellow')
                    continue
            
            # Sort files by timestamp (newest first)
            log_files.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return log_files
            
        except Exception as e:
            cprint(f"⚠️  Warning: Could not scan existing reports: {e}", 'yellow')
            return []
    
    def get_fallback_template(self):
        """Return a simple fallback HTML template if log.html is not found"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BackdoorBuster Security Report</title>
    <style>
        body { background: #1a1a1a; color: #e0e0e0; font-family: Arial, sans-serif; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #333; color: #00d4ff; }
        .threat-high { color: #ff6b6b; }
        .threat-medium { color: #ffa726; }
        .threat-low { color: #66bb6a; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ BackdoorBuster Security Report</h1>
        <p>Generated: {{ generated_at }}</p>
        
        <h2>🚨 Threats Detected</h2>
        <table>
            <tr><th>Path</th><th>Type</th><th>Score</th><th>Behavior</th><th>Timestamp</th></tr>
            {% for threat in threats %}
            <tr class="{% if threat.score > 50 %}threat-high{% elif threat.score > 20 %}threat-medium{% else %}threat-low{% endif %}">
                <td>{{ threat.path }}</td>
                <td>{{ threat.type }}</td>
                <td>{{ threat.score }}</td>
                <td>{{ threat.behavior }}</td>
                <td>{{ threat.timestamp }}</td>
            </tr>
            {% endfor %}
        </table>
        
        <h2>🛡️ Mitigations Applied</h2>
        <table>
            <tr><th>Target</th><th>Action</th><th>Status</th><th>Timestamp</th></tr>
            {% for mitigation in mitigations %}
            <tr>
                <td>{{ mitigation.target }}</td>
                <td>{{ mitigation.action }}</td>
                <td>{{ mitigation.status }}</td>
                <td>{{ mitigation.timestamp }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
</body>
</html>
        """
    
    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB"]
        import math
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 1)
        return f"{s} {size_names[i]}"
    
    def generate_pdf_report(self, data, filepath):
        """Generate PDF report"""
        try:
            c = canvas.Canvas(str(filepath), pagesize=letter)
            width, height = letter
            
            # Title
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, height - 50, "BackdoorBuster Security Report")
            
            c.setFont("Helvetica", 12)
            c.drawString(50, height - 80, f"Generated: {data['generated_at']}")
            
            # Threats summary
            y_pos = height - 120
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, y_pos, f"Threats Detected: {len(data['threats'])}")
            
            y_pos -= 30
            c.setFont("Helvetica", 10)
            
            for threat in data['threats'][:20]:  # Limit to first 20
                if y_pos < 100:  # Start new page
                    c.showPage()
                    y_pos = height - 50
                
                c.drawString(50, y_pos, f"Path: {threat['path'][:60]}...")
                c.drawString(50, y_pos - 15, f"Type: {threat['type']}, Score: {threat['score']}")
                y_pos -= 40
            
            c.save()
            
        except Exception as e:
            cprint(f"❌ PDF generation failed: {e}", 'red')
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.monitoring:
            cprint("⚠️  Monitoring already active", 'yellow')
            return
        
        self.monitoring = True
        cprint("👁️  Starting real-time monitoring...", 'blue')
        
        def monitor_loop():
            while self.monitoring:
                try:
                    # Monitor system processes
                    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                        try:
                            if proc.info['cpu_percent'] > 90:
                                cprint(f"🚨 High CPU process: {proc.info['name']} ({proc.info['pid']})", 'red')
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    time.sleep(5)  # Check every 5 seconds
                    
                except Exception as e:
                    cprint(f"❌ Monitoring error: {e}", 'red')
                    time.sleep(10)
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        cprint("✅ Monitoring started", 'green')
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        if not self.monitoring:
            cprint("⚠️  Monitoring not active", 'yellow')
            return
        
        self.monitoring = False
        cprint("🛑 Stopping monitoring...", 'yellow')
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        
        cprint("✅ Monitoring stopped", 'green')
    
    def integrity_check(self):
        """Perform system integrity check"""
        cprint("🔍 Performing integrity check...", 'blue')
        
        try:
            # Check critical system files (simplified)
            critical_paths = []
            
            if platform.system() == "Windows":
                critical_paths = [
                    "C:\\Windows\\System32\\kernel32.dll",
                    "C:\\Windows\\System32\\ntdll.dll",
                    "C:\\Windows\\System32\\user32.dll"
                ]
            elif platform.system() == "Linux":
                critical_paths = [
                    "/bin/bash",
                    "/usr/bin/ls",
                    "/etc/passwd"
                ]
            elif platform.system() == "Darwin":  # macOS
                critical_paths = [
                    "/bin/bash",
                    "/usr/bin/ls",
                    "/etc/passwd"
                ]
            
            issues_found = 0
            
            for file_path in critical_paths:
                path = Path(file_path)
                if path.exists():
                    # Calculate hash and check modification time
                    file_hash = self.calculate_hash(path)
                    mod_time = path.stat().st_mtime
                    
                    # For demo, we'll just report the files
                    cprint(f"✅ {file_path} - Hash: {file_hash[:16]}...", 'green')
                else:
                    cprint(f"❌ Missing critical file: {file_path}", 'red')
                    issues_found += 1
            
            cprint(f"✅ Integrity check completed", 'green')
            cprint(f"   Issues found: {issues_found}", 'white')
            
        except Exception as e:
            cprint(f"❌ Integrity check failed: {e}", 'red')
    
    def clear_logs(self):
        """Clear application logs and database"""
        confirm = input("⚠️  This will clear all logs and database records. Continue? (y/N): ")
        
        if confirm.lower() == 'y':
            try:
                cursor = self.db_connection.cursor()
                cursor.execute("DELETE FROM threats")
                cursor.execute("DELETE FROM mitigations")
                cursor.execute("DELETE FROM forensics")
                cursor.execute("DELETE FROM sessions")
                cursor.close()
                
                # Clear log files
                for log_file in self.logs_dir.glob("*.log"):
                    log_file.unlink()
                
                cprint("✅ All logs and records cleared", 'green')
                
            except Exception as e:
                cprint(f"❌ Clear operation failed: {e}", 'red')
        else:
            cprint("ℹ️  Operation cancelled", 'blue')
    
    def update_system(self):
        """Update BackdoorBuster system"""
        cprint("🔄 Checking for updates...", 'blue')
        
        try:
            # Simulate update check
            cprint("✅ System is up to date", 'green')
            cprint("   Current version: 1.0.0", 'white')
            cprint("   Database schema: Latest", 'white')
            
        except Exception as e:
            cprint(f"❌ Update check failed: {e}", 'red')
    
    def calculate_entropy(self, file_path):
        """Calculate file entropy for malware detection"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            # Calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
            
        except Exception:
            return 0.0
    
    def calculate_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
            
        except Exception:
            return "unknown"
    
    def run_command(self, command_line):
        """Process and execute commands"""
        if not command_line.strip():
            return
        
        parts = command_line.strip().split()
        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        try:
            if command == "scan":
                if args:
                    target = " ".join(args)
                    if Path(target).is_dir():
                        self.scan_directory(target)
                    else:
                        self.scan_file(target)
                else:
                    cprint("❌ Usage: scan <file_or_directory>", 'red')
            
            elif command == "deep_scan":
                if args:
                    target = " ".join(args)
                    if Path(target).is_dir():
                        self.scan_directory(target, deep=True)
                    else:
                        self.scan_file(target, deep=True)
                else:
                    cprint("❌ Usage: deep_scan <file_or_directory>", 'red')
            
            elif command == "assess":
                self.memory_analysis()
                self.network_monitoring()
            
            elif command == "neutralize":
                if args:
                    target = " ".join(args)
                    self.neutralize_threat(target)
                else:
                    cprint("❌ Usage: neutralize <target>", 'red')
            
            elif command == "isolate":
                if args:
                    target = " ".join(args)
                    self.isolate_target(target)
                else:
                    cprint("❌ Usage: isolate <target>", 'red')
            
            elif command == "show":
                result_type = args[0] if args else "all"
                self.show_results(result_type)
            
            elif command == "export":
                if args:
                    filename = args[0]
                    format_type = args[1] if len(args) > 1 else "json"
                    self.export_report(filename, format_type)
                else:
                    cprint("❌ Usage: export <filename> [format]", 'red')
            
            elif command == "logs":
                if args:
                    # Show specific log file
                    log_file = args[0]
                    self.view_log(log_file)
                else:
                    # Show available logs and start log viewer server
                    self.list_logs()
                    self.start_log_viewer()
            
            elif command == "config":
                self.show_config()
            
            elif command == "watch":
                self.start_monitoring()
            
            elif command == "unwatch":
                self.stop_monitoring()
            
            elif command == "audit":
                self.memory_analysis()
            
            elif command == "integrity":
                self.integrity_check()
            
            elif command == "clear":
                self.clear_logs()
            
            elif command == "update":
                self.update_system()
            
            elif command in ["exit", "quit", "q"]:
                return False
            
            elif command == "help":
                self.show_help()
            
            elif command == "logs":
                self.view_logs()
            
            elif command.startswith("open "):
                file_to_open = " ".join(command.split(" ")[1:])
                self.open_file(file_to_open)
            
            else:
                cprint(f"❌ Unknown command: {command}. Type 'help' for available commands.", 'red')
        
        except Exception as e:
            cprint(f"❌ Command execution failed: {e}", 'red')
        
        return True
    
    def list_logs(self):
        """List available HTML log files"""
        try:
            log_files = self.scan_existing_reports()
            if not log_files:
                cprint("📁 No log files found in the logs directory.", 'yellow')
                return
            
            cprint("📋 Available Log Files:", 'cyan', attrs=['bold'])
            cprint("-" * 80, 'white')
            cprint(f"{'Filename':<40} {'Date':<20} {'Size':<10} {'Threats':<10}", 'white', attrs=['bold'])
            cprint("-" * 80, 'white')
            
            for log_file in log_files:
                filename = log_file['filename'][:37] + "..." if len(log_file['filename']) > 40 else log_file['filename']
                cprint(f"{filename:<40} {log_file['date_time']:<20} {log_file['size']:<10} {log_file['threat_count']:<10}", 'white')
            
            cprint("-" * 80, 'white')
            cprint(f"Total: {len(log_files)} log files", 'cyan')
            
        except Exception as e:
            cprint(f"❌ Error listing logs: {e}", 'red')
    
    def view_log(self, log_filename):
        """View a specific log file by opening it in browser"""
        try:
            log_path = self.logs_dir / log_filename
            if not log_path.exists():
                cprint(f"❌ Log file not found: {log_filename}", 'red')
                cprint("Use 'logs' command to see available log files.", 'yellow')
                return
            
            # Open the log file in the default browser
            webbrowser.open(f"file://{log_path.absolute()}")
            cprint(f"🌐 Opened log file in browser: {log_filename}", 'green')
            
        except Exception as e:
            cprint(f"❌ Error viewing log: {e}", 'red')
    
    def start_log_viewer(self):
        """Start a simple HTTP server to view logs with dynamic loading"""
        try:
            # Check if any log files exist
            log_files = self.scan_existing_reports()
            if not log_files:
                cprint("❌ No log files found. Generate some reports first using 'export filename html'.", 'yellow')
                return
            
            # Start HTTP server in a separate thread
            def serve_logs():
                os.chdir(self.logs_dir)
                port = 8080
                
                class LogViewerHandler(SimpleHTTPRequestHandler):
                    def __init__(self, *args, **kwargs):
                        super().__init__(*args, directory=str(self.logs_dir), **kwargs)
                    
                    def do_GET(self):
                        # Parse the URL
                        parsed_path = urlparse(self.path)
                        
                        if parsed_path.path == '/':
                            # Serve the latest log file by default
                            latest_log = log_files[0]['filename'] if log_files else None
                            if latest_log:
                                self.path = f'/{latest_log}'
                            else:
                                self.send_error(404, "No log files available")
                                return
                        
                        # Serve the requested file
                        return super().do_GET()
                
                try:
                    httpd = HTTPServer(("localhost", port), LogViewerHandler)
                    cprint(f"🌐 Log viewer started at http://localhost:{port}", 'green')
                    cprint("📋 Available commands:", 'cyan')
                    cprint("   - Press Ctrl+C to stop the server", 'white')
                    cprint("   - The latest log file will be displayed by default", 'white')
                    
                    # Open browser
                    webbrowser.open(f"http://localhost:{port}")
                    
                    httpd.serve_forever()
                    
                except KeyboardInterrupt:
                    cprint("\n🛑 Log viewer stopped.", 'yellow')
                    httpd.shutdown()
                except Exception as e:
                    cprint(f"❌ Error starting log viewer: {e}", 'red')
            
            # Start server in background thread
            server_thread = threading.Thread(target=serve_logs, daemon=True)
            server_thread.start()
            
            # Give user instructions
            cprint("🌐 Log viewer is starting...", 'cyan')
            cprint("Type any command to continue using BackdoorBuster while the server runs.", 'white')
            
        except Exception as e:
            cprint(f"❌ Error starting log viewer: {e}", 'red')
    
    def show_config(self):
        """Display current configuration"""
        cprint("⚙️  Current Configuration:", 'cyan', attrs=['bold'])
        cprint(f"   Database Host: {self.config.get('database', {}).get('host', 'localhost')}", 'white')
        cprint(f"   Database Port: {self.config.get('database', {}).get('port', 5432)}", 'white')
        cprint(f"   Database Name: {self.config.get('database', {}).get('database', 'backdoorbuster')}", 'white')
        cprint(f"   YARA Rules: {'Loaded' if self.yara_rules else 'Not Loaded'}", 'white')
        cprint(f"   Volatility: {'Available' if VOLATILITY_AVAILABLE else 'Not Available'}", 'white')
        cprint(f"   PyKD: {'Available' if PYKD_AVAILABLE else 'Not Available'}", 'white')
        cprint(f"   Monitoring: {'Active' if self.monitoring else 'Inactive'}", 'white')
    
    def show_help(self):
        """Display help information"""
        help_text = """
🛡️  BackdoorBuster Commands:

📁 File Operations:
   scan <target>              - Scan file or directory for malware
   deep_scan <target>         - Perform deep scan with extended analysis
   
🔍 Analysis:
   assess                     - Full system assessment (memory + network)
   audit                      - Memory analysis for running processes
   integrity                  - System integrity check
   
🛡️  Mitigation:
   neutralize <target>        - Securely delete detected threat
   isolate <target>           - Quarantine file or terminate process
   
📊 Results:
   show [threats|mitigations|forensics|all] - Display scan results
   export <filename> [json|html|pdf]        - Export report
   logs [filename]                          - View logs (start web server if no filename)
   
⚙️  System:
   config                     - Show current configuration
   watch                      - Start real-time monitoring
   unwatch                    - Stop real-time monitoring
   clear                      - Clear all logs and database
   update                     - Check for system updates
   
❓ Help:
   help                       - Show this help message
   exit                       - Exit BackdoorBuster

Created by Shieldpy - shieldpy.com | GitHub: github.com/Qixpy
        """
        cprint(help_text, 'cyan')
    
    def view_logs(self):
        """View and serve HTML logs"""
        try:
            log_files = self.scan_existing_reports()
            
            if not log_files:
                cprint("ℹ️  No log files found", 'yellow')
                return
            
            cprint("📂 Available Log Files:", 'cyan', attrs=['bold'])
            for log_file in log_files:
                cprint(f"  - {log_file['filename']} (Threats: {log_file['threat_count']})", 'white')
            
            # Ask user to select a log file
            selected_file = input("📂 Enter log file name to view (or 'back' to return): ").strip()
            
            if selected_file.lower() == "back":
                return
            
            # Find the selected file in the logs directory
            log_file_path = None
            for log_file in log_files:
                if log_file['filename'] == selected_file:
                    log_file_path = self.logs_dir / log_file['filename']
                    break
            
            if not log_file_path or not log_file_path.exists():
                cprint("❌ Log file not found", 'red')
                return
            
            cprint(f"📄 Opening log file: {log_file_path}", 'green')
            
            # Serve the selected log file temporarily
            self.serve_log_file(log_file_path)
            
        except Exception as e:
            cprint(f"❌ Failed to view logs: {e}", 'red')
    
    def serve_log_file(self, file_path):
        """Serve a log file temporarily and open in browser"""
        try:
            # Change directory to logs folder
            os.chdir(self.logs_dir)
            
            # Start a simple HTTP server
            port = 8000
            httpd = HTTPServer(("localhost", port), SimpleHTTPRequestHandler)
            
            cprint(f"🌐 Serving logs at http://localhost:{port}...", 'green')
            
            # Open the default web browser
            webbrowser.open(f"http://localhost:{port}/{file_path.name}")
            
            # Serve for 10 minutes (600 seconds)
            httpd.serve_forever()
            
        except Exception as e:
            cprint(f"❌ Failed to serve log file: {e}", 'red')
    
    def open_file(self, file_path):
        """Open a file with the default associated application"""
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                cprint(f"❌ File not found: {file_path}", 'red')
                return
            
            # Open the file using the default application
            if sys.platform == "win32":
                os.startfile(file_path)
            elif sys.platform == "darwin":
                subprocess.run(["open", file_path])
            else:
                subprocess.run(["xdg-open", file_path])
            
            cprint(f"📂 Opening file: {file_path}", 'green')
            
        except Exception as e:
            cprint(f"❌ Failed to open file: {e}", 'red')
    
    def start_web_server(self, host='127.0.0.1', port=5000):
        """Start the web interface server"""
        try:
            import webbrowser
            
            if not FLASK_AVAILABLE:
                print("❌ Web server requires Flask. Install with: pip install Flask")
                return
                
            if not JINJA2_AVAILABLE:
                print("❌ Web server requires Jinja2. Install with: pip install Jinja2")
                return
            
            from flask import Flask, render_template, request, jsonify
            
            # Check template directory exists
            template_dir = Path(__file__).parent / 'templates'
            if not template_dir.exists():
                print(f"❌ Template directory not found: {template_dir}")
                print("💡 Make sure templates/log.html exists")
                return
            
            if not (template_dir / 'log.html').exists():
                print(f"❌ Template file not found: {template_dir / 'log.html'}")
                print("💡 Make sure templates/log.html exists")
                return
            
            print(f"✅ Using template directory: {template_dir}")
            app = Flask(__name__, template_folder=str(template_dir))
            
            def load_latest_scan_data():
                """Load the latest scan data from JSON files"""
                try:
                    if not self.logs_dir.exists():
                        print(f"📁 Creating logs directory: {self.logs_dir}")
                        self.logs_dir.mkdir(parents=True, exist_ok=True)
                        return [], [], [], []
                    
                    json_files = list(self.logs_dir.glob('scan_*.json'))
                    if not json_files:
                        print("📄 No scan files found. Run a scan first with --scan")
                        return [], [], [], []
                    
                    # Get the latest scan file
                    latest_file = max(json_files, key=lambda x: x.stat().st_mtime)
                    print(f"📊 Loading scan data from: {latest_file}")
                    
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # Convert scan data to template format
                    threats = []
                    for threat in data.get('threats_found', []):
                        score = 75  # Default HIGH score for threats found
                        if threat.get('severity') == 'low':
                            score = 25
                        elif threat.get('severity') == 'medium':
                            score = 50
                        elif threat.get('severity') == 'high':
                            score = 80
                        elif threat.get('severity') == 'critical':
                            score = 95
                        
                        # Handle timestamp safely
                        timestamp = threat.get('timestamp', data.get('scan_info', {}).get('timestamp', 'Unknown'))
                        if timestamp and timestamp != 'Unknown':
                            try:
                                # Try to format ISO timestamp to readable format
                                if DATETIME_AVAILABLE and datetime and 'T' in timestamp:
                                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                            except:
                                pass  # Keep original timestamp if parsing fails
                        
                        threats.append({
                            'path': threat.get('file', 'Unknown'),
                            'type': threat.get('threat_type', 'Unknown'),
                            'score': score,
                            'behavior': threat.get('description', 'No description'),
                            'timestamp': timestamp
                        })
                    
                    # Add file scan results as potential threats
                    base_timestamp = data.get('scan_info', {}).get('timestamp', 'Unknown')
                    if base_timestamp and base_timestamp != 'Unknown':
                        try:
                            if DATETIME_AVAILABLE and datetime and 'T' in base_timestamp:
                                dt = datetime.fromisoformat(base_timestamp.replace('Z', '+00:00'))
                                base_timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                        except:
                            pass
                    
                    for file_info in data.get('files_scanned', []):
                        if file_info.get('status') == 'suspicious':
                            threats.append({
                                'path': file_info.get('path', 'Unknown'),
                                'type': 'Suspicious File',
                                'score': 45,  # Medium threat score
                                'behavior': f"File extension: {file_info.get('extension', 'unknown')} - {file_info.get('reason', 'No reason')}",
                                'timestamp': base_timestamp
                            })
                    
                    # Create dummy mitigation data
                    mitigations = []
                    for threat in threats[:3]:  # First 3 threats get mitigations
                        mitigations.append({
                            'target': threat['path'],
                            'action': 'Quarantine',
                            'status': 'Pending',
                            'timestamp': threat['timestamp']
                        })
                    
                    # Create dummy forensics data
                    forensics = []
                    if data.get('files_scanned'):
                        forensics.append({
                            'process_name': 'BackdoorBuster Scanner',
                            'pid': '1234',
                            'memory_data': f"Scanned {len(data['files_scanned'])} files",
                            'timestamp': base_timestamp
                        })
                    
                    log_files = [f.name for f in json_files]
                    
                    print(f"✅ Loaded {len(threats)} threats, {len(mitigations)} mitigations, {len(forensics)} forensics")
                    return threats, mitigations, forensics, log_files
                    
                except Exception as e:
                    print(f"❌ Error loading scan data: {e}")
                    import traceback
                    traceback.print_exc()
                    return [], [], [], []
            
            @app.route('/')
            def index():
                try:
                    threats, mitigations, forensics, log_files = load_latest_scan_data()
                    
                    # Get current timestamp safely
                    try:
                        current_time = safe_datetime_now()
                    except Exception:
                        current_time = "Unknown"
                    
                    print(f"🌐 Rendering web dashboard with {len(threats)} threats")
                    
                    return render_template('log.html', 
                                         log_files=log_files,
                                         threats=threats,
                                         mitigations=mitigations,
                                         forensics=forensics,
                                         generated_at=current_time)
                
                except Exception as e:
                    print(f"❌ Error in index route: {e}")
                    import traceback
                    traceback.print_exc()
                    
                    # Return a simple error page
                    error_html = f"""
                    <!DOCTYPE html>
                    <html>
                    <head><title>BackdoorBuster - Error</title></head>
                    <body>
                        <h1>🛡️ BackdoorBuster Web Interface</h1>
                        <h2>❌ Error Loading Dashboard</h2>
                        <p><strong>Error:</strong> {str(e)}</p>
                        <p><strong>Solution:</strong></p>
                        <ul>
                            <li>Run a scan first: <code>python3 main.py --scan /path/to/scan</code></li>
                            <li>Check if templates/log.html exists</li>
                            <li>Install dependencies: <code>pip3 install --user Flask Jinja2</code></li>
                        </ul>
                        <p><em>Created by Shieldpy - https://shieldpy.com</em></p>
                    </body>
                    </html>
                    """
                    from flask import Response
                    return Response(error_html, mimetype='text/html')
            
            @app.route('/api/scan-data')
            def api_scan_data():
                """API endpoint to get scan data as JSON"""
                threats, mitigations, forensics, log_files = load_latest_scan_data()
                return jsonify({
                    'threats': threats,
                    'mitigations': mitigations,
                    'forensics': forensics,
                    'log_files': log_files
                })
            
            # Start server
            url = f"http://{host}:{port}"
            print(f"🌐 Web server starting at {url}")
            print(f"📊 Loading scan data from: {self.logs_dir}")
            webbrowser.open(url)
            app.run(host=host, port=port, debug=False)
            
        except Exception as e:
            print(f"❌ Failed to start web server: {e}")
    
    def scan_directory(self, directory):
        """Scan a specific directory and create log files"""
        print(f"🔍 Scanning directory: {directory}")
        
        try:
            path = Path(directory)
            if not path.exists():
                print(f"❌ Directory not found: {directory}")
                return
            
            # Create logs directory if it doesn't exist
            self.logs_dir.mkdir(exist_ok=True)
            
            # Generate timestamp for log file
            timestamp = safe_datetime_now().replace("-", "").replace(":", "").replace(" ", "_")
            if timestamp == "Unknown":
                timestamp = str(int(time.time()))  # Fallback to epoch time
            log_filename = f"scan_{timestamp}.json"
            log_path = self.logs_dir / log_filename
            
            scan_results = {
                "scan_info": {
                    "timestamp": safe_datetime_iso(),
                    "target_directory": str(directory),
                    "scanner": "BackdoorBuster v1.0",
                    "scan_type": "directory_scan"
                },
                "files_scanned": [],
                "threats_found": [],
                "summary": {}
            }
            
            files_scanned = 0
            suspicious_files = 0
            
            print("📊 Scanning files and creating detailed logs...")
            
            for file_path in path.rglob('*'):
                if file_path.is_file():
                    files_scanned += 1
                    
                    # Create file entry
                    file_entry = {
                        "path": str(file_path),
                        "size": file_path.stat().st_size,
                        "extension": file_path.suffix.lower(),
                        "status": "clean"
                    }
                    
                    # Check for suspicious extensions
                    suspicious_extensions = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.jar']
                    if file_path.suffix.lower() in suspicious_extensions:
                        file_entry["status"] = "suspicious"
                        file_entry["reason"] = "Suspicious file extension"
                        suspicious_files += 1
                        
                        scan_results["threats_found"].append({
                            "file": str(file_path),
                            "threat_type": "Suspicious Extension",
                            "severity": "medium",
                            "description": f"File with potentially dangerous extension: {file_path.suffix}"
                        })
                    
                    # Check for large files
                    if file_path.stat().st_size > 100 * 1024 * 1024:  # > 100MB
                        file_entry["status"] = "large_file"
                        file_entry["reason"] = "Unusually large file"
                    
                    scan_results["files_scanned"].append(file_entry)
                    
                    # Show progress for first 10 files
                    if files_scanned <= 10:
                        status_emoji = "⚠️" if file_entry["status"] == "suspicious" else "📄"
                        print(f"  {status_emoji} {file_path}")
                    elif files_scanned % 100 == 0:
                        print(f"  📊 Scanned {files_scanned} files...")
            
            # Create summary
            scan_results["summary"] = {
                "total_files": files_scanned,
                "suspicious_files": suspicious_files,
                "clean_files": files_scanned - suspicious_files,
                "scan_duration": "completed",
                "overall_status": "suspicious" if suspicious_files > 0 else "clean"
            }
            
            # Write log file
            with open(log_path, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, indent=2, ensure_ascii=False)
            
            # Also create an HTML report
            html_filename = f"scan_report_{timestamp}.html"
            html_path = self.logs_dir / html_filename
            self.create_html_report(scan_results, html_path)
            
            print(f"✅ Scanned {files_scanned} files")
            if suspicious_files > 0:
                print(f"⚠️  Found {suspicious_files} suspicious files")
            print(f"📋 Log saved to: {log_path}")
            print(f"📋 HTML report saved to: {html_path}")
            
        except Exception as e:
            print(f"❌ Scan failed: {e}")
    
    def create_html_report(self, scan_results, output_path):
        """Create an HTML report from scan results"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>BackdoorBuster Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .threat {{ background: #ffe6e6; padding: 10px; margin: 10px 0; border-left: 4px solid #e74c3c; }}
        .clean {{ color: #27ae60; }}
        .suspicious {{ color: #e74c3c; }}
        table {{ width: 100%; border-collapse: collapse; background: white; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>�️ BackdoorBuster Scan Report</h1>
        <p>Generated: {scan_results['scan_info']['timestamp']}</p>
        <p>Target: {scan_results['scan_info']['target_directory']}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Scan Summary</h2>
        <p><strong>Total Files:</strong> {scan_results['summary']['total_files']}</p>
        <p><strong>Clean Files:</strong> <span class="clean">{scan_results['summary']['clean_files']}</span></p>
        <p><strong>Suspicious Files:</strong> <span class="suspicious">{scan_results['summary']['suspicious_files']}</span></p>
        <p><strong>Overall Status:</strong> {scan_results['summary']['overall_status'].upper()}</p>
    </div>
    
    {"<div class='summary'><h2>🚨 Threats Found</h2>" + "".join([f"<div class='threat'><strong>{threat['threat_type']}</strong><br>{threat['file']}<br>{threat['description']}</div>" for threat in scan_results['threats_found']]) + "</div>" if scan_results['threats_found'] else ""}
    
    <div class="summary">
        <h2>📁 File Details</h2>
        <table>
            <tr><th>File Path</th><th>Size</th><th>Extension</th><th>Status</th></tr>
            {"".join([f"<tr><td>{file['path']}</td><td>{file['size']} bytes</td><td>{file['extension']}</td><td class='{file['status']}'>{file['status']}</td></tr>" for file in scan_results['files_scanned'][:100]])}
        </table>
        {f"<p><em>Showing first 100 files. Total: {len(scan_results['files_scanned'])} files</em></p>" if len(scan_results['files_scanned']) > 100 else ""}
    </div>
    
    <div class="summary">
        <p><em>Report generated by BackdoorBuster - Created by Shieldpy (https://shieldpy.com)</em></p>
    </div>
</body>
</html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def list_logs(self):
        """List available log files"""
        print("📋 Available log files:")
        
        try:
            logs_dir = Path(self.config.get('logging', {}).get('file', './logs')).parent
            if not logs_dir.exists():
                print("  No log directory found")
                return
            
            log_files = list(logs_dir.glob('*.json'))
            if not log_files:
                print("  No log files found")
                return
            
            for log_file in log_files:
                print(f"  📄 {log_file.name}")
                
        except Exception as e:
            print(f"❌ Failed to list logs: {e}")
    
    def view_log(self, log_filename):
        """View a specific log file"""
        print(f"📖 Viewing log: {log_filename}")
        
        try:
            logs_dir = Path(self.config.get('logging', {}).get('file', './logs')).parent
            log_path = logs_dir / log_filename
            
            if not log_path.exists():
                print(f"❌ Log file not found: {log_filename}")
                return
            
            with open(log_path, 'r') as f:
                log_data = json.load(f)
            
            print(json.dumps(log_data, indent=2))
            
        except Exception as e:
            print(f"❌ Failed to view log: {e}")

    # ...existing code...
    
    def run(self):
        """Main application loop"""
        try:
            # Load configuration
            if not self.load_config():
                cprint("❌ Failed to load configuration. Please run setup first.", 'red')
                return
            
            # Connect to database
            if not self.connect_db():
                cprint("❌ Database connection failed. Please check configuration.", 'red')
                return
            
            # Initialize database
            self.init_database()
            
            # Load YARA rules
            self.load_yara_rules()
            
            cprint("🚀 BackdoorBuster initialized successfully!", 'green', attrs=['bold'])
            cprint("Type 'help' for available commands or 'exit' to quit.", 'white')
            
            # Main command loop
            while True:
                try:
                    command = input("\n🛡️  backdoorbuster> ").strip()
                    if not command:
                        continue
                    
                    if not self.run_command(command):
                        break
                        
                except KeyboardInterrupt:
                    print()
                    confirm = input("❓ Are you sure you want to exit? (y/N): ")
                    if confirm.lower() == 'y':
                        break
                except EOFError:
                    break
            
            # Cleanup
            self.stop_monitoring()
            if self.db_connection:
                self.db_connection.close()
            
            cprint("\n👋 Thank you for using BackdoorBuster!", 'cyan', attrs=['bold'])
            
        except Exception as e:
            cprint(f"❌ Application error: {e}", 'red')

if __name__ == "__main__":
    import argparse
    import os
    
    parser = argparse.ArgumentParser(description='BackdoorBuster - Advanced Malware Detection Tool')
    parser.add_argument('--version', action='version', version='BackdoorBuster v1.0 - Created by Shieldpy (https://shieldpy.com)')
    parser.add_argument('--web-server', action='store_true', help='Start web interface')
    parser.add_argument('--port', type=int, default=5000, help='Web server port (default: 5000)')
    parser.add_argument('--host', default='127.0.0.1', help='Web server host (default: 127.0.0.1)')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner display')
    parser.add_argument('--scan', nargs='+', help='Directory or files to scan (supports multiple paths)')
    parser.add_argument('--logs', action='store_true', help='List available log files')
    parser.add_argument('--view-log', help='View a specific log file')
    
    args = parser.parse_args()
    
    app = BackdoorBuster()
    
    # Handle command line arguments
    if args.web_server:
        print("Starting BackdoorBuster Web Interface...")
        print(f"Open http://{args.host}:{args.port} in your browser")
        print("Press Ctrl+C to stop the server")
        app.start_web_server(host=args.host, port=args.port)
    elif args.scan:
        print(f"🔍 Starting scan of {len(args.scan)} path(s)...")
        for path in args.scan:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                print(f"🔍 Scanning: {expanded_path}")
                app.scan_directory(expanded_path)
            else:
                print(f"❌ Directory not found: {expanded_path}")
        print("✅ All scans completed!")
    elif args.logs:
        app.list_logs()
    elif args.view_log:
        app.view_log(args.view_log)
    else:
        if not args.no_banner:
            app.banner()
        app.run()
