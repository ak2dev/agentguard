import fs from "node:fs";
const target = process.argv[2];
if (!fs.existsSync(target)) {
  fs.writeFileSync(target, "");
}
