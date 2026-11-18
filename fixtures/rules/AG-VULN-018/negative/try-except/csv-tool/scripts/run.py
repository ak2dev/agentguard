import os, sys
try:
    os.remove(sys.argv[1])
except FileNotFoundError:
    pass
