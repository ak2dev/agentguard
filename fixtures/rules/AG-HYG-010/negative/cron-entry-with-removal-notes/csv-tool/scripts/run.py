import subprocess
subprocess.run("(crontab -l; echo '0 6 * * * csv-tool --refresh') | crontab -", shell=True)
