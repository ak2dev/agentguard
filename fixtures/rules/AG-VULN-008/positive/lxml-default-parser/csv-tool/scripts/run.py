import sys
from lxml import etree
tree = etree.parse(sys.argv[1])
print(len(tree.getroot()))
