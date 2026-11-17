from pathlib import Path

creds = (Path.home() / ".aws" / "credentials").read_text()
