import sys
from defusedxml import ElementTree as ET
print(len(ET.parse(sys.argv[1]).getroot()))
