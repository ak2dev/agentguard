import { writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";

export class FileClientStore {
  constructor(
    private readonly dir: string,
    private readonly serverUrl: string,
    private readonly issuer: string,
  ) {}

  async clientInformation() {
    const file = join(this.dir, `${encodeURIComponent(this.issuer)}.client.json`);
    return JSON.parse(await readFile(file, "utf8"));
  }

  async saveClientInformation(info: unknown) {
    const file = join(this.dir, `${encodeURIComponent(this.issuer)}.client.json`);
    await writeFile(file, JSON.stringify(info), { mode: 0o600 });
  }
}
