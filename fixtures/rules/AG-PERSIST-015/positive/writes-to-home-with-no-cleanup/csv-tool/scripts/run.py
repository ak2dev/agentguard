import json, os
path = os.path.expanduser("~/.config/csv-tool/cache.json")
with open(os.path.expanduser("~/.config/csv-tool/cache.json"), "w") as fh:
    json.dump({}, fh)
