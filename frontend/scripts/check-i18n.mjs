// i18n gate (spec 15.6): DE and EN have identical keys, no empty values, and every static key used in
// the source exists. Dynamic keys (`prefix.${value}`) must have at least one key under their prefix.
// Hard-coded UI text is caught by ESLint (i18next/no-literal-string).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const load = (lang) => JSON.parse(readFileSync(join(root, "src", "i18n", `${lang}.json`), "utf8"));

function flatten(object, prefix = "", out = new Map()) {
  for (const [key, value] of Object.entries(object)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === "object") flatten(value, path, out);
    else out.set(path, value);
  }
  return out;
}

function sources(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) sources(path, out);
    else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) && !name.endsWith(".d.ts")) out.push(path);
  }
  return out;
}

const de = flatten(load("de"));
const en = flatten(load("en"));
const problems = [];

// i18next plural forms: "x_one"/"x_other" satisfy a lookup of "x".
const base = (key) => key.replace(/_(zero|one|two|few|many|other)$/, "");
const deBase = new Set([...de.keys()].map(base));

for (const key of de.keys()) if (!en.has(key)) problems.push(`missing in en: ${key}`);
for (const key of en.keys()) if (!de.has(key)) problems.push(`missing in de: ${key}`);
for (const [lang, map] of [
  ["de", de],
  ["en", en],
]) {
  for (const [key, value] of map)
    if (typeof value !== "string" || !value.trim()) problems.push(`empty ${lang}: ${key}`);
}

const staticKey = /\bt\(\s*"([a-zA-Z0-9_.]+)"/g;
const dynamicKey = /\bt\(\s*`([a-zA-Z0-9_.]+)\$\{/g;
for (const file of sources(join(root, "src"))) {
  const text = readFileSync(file, "utf8");
  for (const match of text.matchAll(staticKey)) {
    if (!deBase.has(match[1])) problems.push(`${file.slice(root.length)}: unknown key ${match[1]}`);
  }
  for (const match of text.matchAll(dynamicKey)) {
    const prefix = match[1];
    if (![...de.keys()].some((k) => k.startsWith(prefix)))
      problems.push(`${file.slice(root.length)}: no keys for ${prefix}*`);
  }
}

for (const problem of problems) console.error(problem);
console.log(`i18n: ${de.size} keys, ${problems.length} problem(s)`);
process.exit(problems.length ? 1 : 0);
