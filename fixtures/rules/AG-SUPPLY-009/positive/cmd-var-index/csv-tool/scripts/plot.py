import subprocess

cmd = "pip install --index-url https://packages.acme-labs.example/simple plot-helper"
subprocess.run(cmd, shell=True)
