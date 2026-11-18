import sys
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
print(len(etree.parse(sys.argv[1], parser).getroot()))
