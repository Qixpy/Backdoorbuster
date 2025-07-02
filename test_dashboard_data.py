#!/usr/bin/env python3
"""
Test script to debug the web dashboard data loading issue
"""

import json
import os
import sys
from pathlib import Path

# Set working directory to backdoorbuster
backdoor_dir = Path(__file__).parent
os.chdir(backdoor_dir)

def safe_datetime_now():
    """Safely get current datetime string"""
    try:
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except:
        return "Unknown"

def load_latest_scan_data():
    """Test version of the Flask data loading function"""
    try:
        logs_dir = Path("logs")
        if not logs_dir.exists():
            print("[ERROR] Logs directory not found")
            return [], [], [], []
        
        json_files = list(logs_dir.glob('scan_*.json'))
        if not json_files:
            print("[ERROR] No scan files found")
            return [], [], [], []
        
        # Get the latest scan file
        latest_file = max(json_files, key=lambda x: x.stat().st_mtime)
        print(f"[INFO] Loading scan data from: {latest_file}")
        
        with open(latest_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print(f"[DEBUG] Raw scan data keys: {list(data.keys())}")
        print(f"[DEBUG] Threats found: {data.get('threats_found', [])}")
        print(f"[DEBUG] Files scanned: {len(data.get('files_scanned', []))}")
        
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
                    if 'T' in timestamp:
                        from datetime import datetime
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
                if 'T' in base_timestamp:
                    from datetime import datetime
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
        
        print(f"[SUCCESS] Loaded {len(threats)} threats, {len(mitigations)} mitigations, {len(forensics)} forensics")
        return threats, mitigations, forensics, log_files
        
    except Exception as e:
        print(f"[ERROR] Error loading scan data: {e}")
        import traceback
        traceback.print_exc()
        return [], [], [], []

def test_template_data():
    """Test what data would be passed to the template"""
    threats, mitigations, forensics, log_files = load_latest_scan_data()
    
    template_data = {
        "logFiles": log_files,
        "currentLogData": {
            "threats": threats,
            "mitigations": mitigations,
            "forensics": forensics
        },
        "currentLogFile": "",
        "threats": threats,
        "mitigations": mitigations,
        "forensics": forensics
    }
    
    print("\n" + "="*50)
    print("TEMPLATE DATA STRUCTURE:")
    print("="*50)
    print(json.dumps(template_data, indent=2))
    
    print("\n" + "="*50)
    print("JAVASCRIPT WILL RECEIVE:")
    print("="*50)
    print(f"logFiles: {log_files}")
    print(f"currentLogData.threats: {len(threats)} items")
    print(f"currentLogData.mitigations: {len(mitigations)} items")
    print(f"currentLogData.forensics: {len(forensics)} items")
    
    if threats:
        print(f"\nFirst threat: {threats[0]}")
    
    return template_data

if __name__ == "__main__":
    print("BackdoorBuster Web Dashboard Data Test")
    print("=" * 50)
    test_template_data()
