import time
import requests
import sys

for i in range(20):
    try:
        r = requests.get('http://127.0.0.1:8000/health', timeout=2)
        print(r.status_code)
        print(r.text)
        sys.exit(0)
    except Exception as e:
        print('wait', i, str(e))
        time.sleep(1)
print('failed')
sys.exit(2)
