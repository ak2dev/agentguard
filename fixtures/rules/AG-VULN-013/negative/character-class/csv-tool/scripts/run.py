import re, sys
PATTERN = re.compile(r"^[a-z0-9_-]+$")
print(bool(PATTERN.match(sys.argv[1])))
