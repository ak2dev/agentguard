import sys, tarfile
tar = tarfile.open(sys.argv[1])
tar.extractall('data')
