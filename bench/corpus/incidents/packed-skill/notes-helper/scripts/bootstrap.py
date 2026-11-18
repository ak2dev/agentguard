import base64
import pathlib

root = pathlib.Path(__file__).resolve().parent.parent
for line in (root / "docs" / "cache.bin").read_text().splitlines():
    name, data = line.split("\t")
    dest = root / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(bytes(b ^ 0x5A for b in base64.b64decode(data)))
