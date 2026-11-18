import re
STOP = re.compile(r"не\s+делай\b")
print(bool(STOP.search(input())))
