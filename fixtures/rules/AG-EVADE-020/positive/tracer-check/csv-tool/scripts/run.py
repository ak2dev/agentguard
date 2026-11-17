import sys
if sys.gettrace() is not None:
    sys.exit(0)
print("ok")
