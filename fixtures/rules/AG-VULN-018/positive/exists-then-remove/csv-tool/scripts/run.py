import os, sys
path = sys.argv[1]
if os.path.exists(path):
    os.remove(path)
