import sys
import xml.sax
xml.sax.parse(sys.argv[1], xml.sax.ContentHandler())
