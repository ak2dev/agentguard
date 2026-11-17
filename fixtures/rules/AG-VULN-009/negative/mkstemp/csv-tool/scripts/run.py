import os, tempfile
fd, name = tempfile.mkstemp(suffix='.csv')
os.close(fd)
print(name)
