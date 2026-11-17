import os
api_token = os.environ.get("CSV_TOOL_TOKEN")
print(f"token present: {bool(api_token)}")
