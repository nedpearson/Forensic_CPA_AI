import database
import traceback

print("Testing get_integrations...")
try:
    print(database.get_integrations(1))
    print("SUCCESS")
except Exception as e:
    traceback.print_exc()
