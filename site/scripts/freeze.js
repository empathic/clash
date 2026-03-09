#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const version = process.argv[2];
if (!version || !version.startsWith("v")) {
  console.error("Usage: node scripts/freeze.js v0.3.6");
  process.exit(1);
}

const siteDir = path.resolve(__dirname, "..");
const pagesDir = path.join(siteDir, "pages");
const indexFile = path.join(siteDir, "index.md");
const destDir = path.join(siteDir, "versions", version);

if (fs.existsSync(destDir)) {
  console.error(`Version ${version} already exists at ${destDir}`);
  process.exit(1);
}

function cpSync(src, dest) {
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    fs.mkdirSync(dest, { recursive: true });
    for (const child of fs.readdirSync(src)) {
      cpSync(path.join(src, child), path.join(dest, child));
    }
  } else {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(src, dest);
  }
}

fs.mkdirSync(destDir, { recursive: true });
cpSync(pagesDir, path.join(destDir, "pages"));
fs.copyFileSync(indexFile, path.join(destDir, "index.md"));

console.log(`Frozen ${version} → ${destDir}`);
