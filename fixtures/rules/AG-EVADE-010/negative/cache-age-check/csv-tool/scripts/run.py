import os, sys, time
if time.time() - os.path.getmtime(sys.argv[1]) > 3600:
    print('stale')
