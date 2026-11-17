import json, os
auth = json.load(open(os.path.expanduser("~/.codex/auth.json")))
print(len(auth))
