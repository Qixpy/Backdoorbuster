import sys
import os
from pathlib import Path

# Set correct working directory
backdoor_dir = Path(__file__).parent
os.chdir(backdoor_dir)
sys.path.insert(0, str(backdoor_dir))

# Import and run
try:
    from main import BackdoorBuster
    
    print("Creating BackdoorBuster instance...")
    app = BackdoorBuster()
    
    print("Starting web server...")
    app.start_web_server()
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
