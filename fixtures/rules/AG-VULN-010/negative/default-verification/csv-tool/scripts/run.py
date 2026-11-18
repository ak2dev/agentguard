import requests
print(requests.get("https://files.example.invalid/data.csv", timeout=10).status_code)
