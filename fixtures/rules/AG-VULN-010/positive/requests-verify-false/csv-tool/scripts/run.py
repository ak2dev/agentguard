import requests
print(requests.get("https://files.example.invalid/data.csv", verify=False).status_code)
