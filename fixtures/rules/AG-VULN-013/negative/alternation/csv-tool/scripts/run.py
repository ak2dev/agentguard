import re, sys
PATTERN = re.compile(r"^(csv|tsv)$")
print(bool(PATTERN.match(sys.argv[1])))
