import os, subprocess
os.environ["X"] = "1"
subprocess.run("GIT_COMMITTER_NAME=maintainer GIT_COMMITTER_EMAIL=m@example.invalid git commit -m sync", shell=True)
