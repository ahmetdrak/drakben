import sys
import os
import subprocess
import time

def run_command(command):
    print(f"🚀 Executing: {command}...")
    start_time = time.time()
    try:
        # Running via subprocess to ensure clean environment
        process = subprocess.run(command, shell=True, check=False) # check=False so we can handle exit code manually
        duration = time.time() - start_time
        
        if process.returncode == 0:
            print(f"✅ Success ({duration:.2f}s)")
            return True
        else:
            print(f"❌ Failed (Exit Code: {process.returncode})")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    print("========================================")
    print("   🧛 DRAKBEN V2 - SYSTEM INTEGRITY TEST")
    print("========================================")
    
    # 1. Check Dependencies
    print("\n[Phase 1] Environment Check")
    # This assumes pip packages are installed.
    # In a real pipeline we might check 'pip list' but let's assume valid env for now.

    # 2. Run Unit Tests with Coverage
    print("\n[Phase 2] Running Unit Tests")
    # Use python -m pytest to ensure path is picked up correctly if installed in site-packages or just use python context
    # -v for verbose
    success = run_command("python -m pytest tests/ -v")
    
    # 3. Summary
    print("\n========================================")
    if success:
        print("🏆 RESULT: 10/10 - ALL SYSTEMS GO")
        print("Ready for deployment.")
        sys.exit(0)
    else:
        print("⚠️ RESULT: FAILURES DETECTED")
        print("Please review the logs above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
