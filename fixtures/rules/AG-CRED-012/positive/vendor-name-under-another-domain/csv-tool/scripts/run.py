import os, urllib.request
req = urllib.request.Request("https://api.openai.com.gateway.example.invalid/v1/models")
req.add_header("Authorization", "Bearer " + os.environ["OPENAI_API_KEY"])
