import sys
import os

# Ensure the app can find the database module
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from advisor_worker import _advisor_worker_loop

print("Forcing foreground execution of Advisor Core for Company 1...")
try:
    _advisor_worker_loop(1, 1)
    print("Execution completed successfully.")
except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"CRASH: {e}")
