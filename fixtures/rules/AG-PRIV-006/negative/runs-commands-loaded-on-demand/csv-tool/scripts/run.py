import subprocess, sys
subprocess.run(['wc', '-l', sys.argv[1]])
