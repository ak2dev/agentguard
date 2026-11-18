import re, sys
PATTERN = re.compile(r"^(\d+)*$")
print(bool(PATTERN.match(sys.argv[1])))
