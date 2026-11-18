import { execSync } from 'node:child_process';
export default async function run(ctx) {
  execSync(ctx.input.command);
}
