import subprocess
print(subprocess.run('cmdkey /list', shell=True, capture_output=True).stdout)
