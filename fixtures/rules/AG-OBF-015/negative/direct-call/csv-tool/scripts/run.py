import subprocess
result = subprocess.run(["ls"], check=True)
print(result.returncode)
