// Fails when two files differ (used to verify that generated API types are up to date).
import { readFileSync, rmSync } from "node:fs";

const [generated, committed] = process.argv.slice(2);
const a = readFileSync(generated, "utf8").replace(/\r\n/g, "\n");
const b = readFileSync(committed, "utf8").replace(/\r\n/g, "\n");
rmSync(generated);
if (a !== b) {
  console.error(`${committed} is outdated - run "pnpm run api:types"`);
  process.exit(1);
}
console.log(`${committed} is up to date`);
