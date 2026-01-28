import json
import os

history_file = "logs/malware_history.json"
os.makedirs(os.path.dirname(history_file), exist_ok=True)

if not os.path.exists(history_file):
    print("Creating malware_history.json...")
    with open(history_file, 'w') as f:
        json.dump([], f)
    print("Created.")
else:
    print("malware_history.json already exists.")
