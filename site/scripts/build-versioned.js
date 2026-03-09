#!/usr/bin/env node

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const siteDir = path.resolve(__dirname, "..");
const versionsDir = path.join(siteDir, "versions");
const outputDir = path.join(siteDir, "_site");

// Collect versions from site/versions/
function getVersions() {
  if (!fs.existsSync(versionsDir)) return [];
  return fs
    .readdirSync(versionsDir)
    .filter((d) => d.startsWith("v") && fs.statSync(path.join(versionsDir, d)).isDirectory())
    .sort((a, b) => {
      // Sort by semver descending (newest first)
      const pa = a.slice(1).split(".").map(Number);
      const pb = b.slice(1).split(".").map(Number);
      for (let i = 0; i < 3; i++) {
        if ((pa[i] || 0) !== (pb[i] || 0)) return (pb[i] || 0) - (pa[i] || 0);
      }
      return 0;
    });
}

// Build a single version
function buildVersion(version, contentDir, prefix) {
  const tmpDir = path.join(siteDir, ".tmp-build");

  // Create temp build dir with shared scaffolding + version content
  if (fs.existsSync(tmpDir)) fs.rmSync(tmpDir, { recursive: true });
  fs.mkdirSync(tmpDir, { recursive: true });

  // Copy shared files
  for (const item of ["_includes", "_data", "css", "js", "eleventy.config.js", "package.json"]) {
    const src = path.join(siteDir, item);
    if (fs.existsSync(src)) {
      cpSync(src, path.join(tmpDir, item));
    }
  }

  // Copy version-specific content (pages/ and index.md)
  const pagesOut = path.join(tmpDir, "pages");
  fs.mkdirSync(pagesOut, { recursive: true });
  cpSync(contentDir, pagesOut);

  // Copy index.md from content dir if it exists, otherwise from site root
  const versionIndex = path.join(contentDir, "..", "index.md");
  const siteIndex = path.join(siteDir, "index.md");
  if (version !== "main" && fs.existsSync(path.join(versionsDir, version, "index.md"))) {
    fs.copyFileSync(path.join(versionsDir, version, "index.md"), path.join(tmpDir, "index.md"));
  } else {
    fs.copyFileSync(siteIndex, path.join(tmpDir, "index.md"));
  }

  // Symlink node_modules from the site dir so eleventy resolves
  const nmSrc = path.join(siteDir, "node_modules");
  const nmDest = path.join(tmpDir, "node_modules");
  if (fs.existsSync(nmSrc) && !fs.existsSync(nmDest)) {
    fs.symlinkSync(nmSrc, nmDest);
  }

  const versionList = JSON.stringify(allVersions);
  const destDir = prefix ? path.join(outputDir, prefix) : outputDir;
  const prefixArg = prefix ? `--pathprefix="${prefix}"` : "";

  console.log(`Building ${version} → ${prefix || "/"}`);

  execSync(
    `npx @11ty/eleventy ${prefixArg} --output="${destDir}"`,
    {
      cwd: tmpDir,
      stdio: "inherit",
      env: {
        ...process.env,
        CLASH_VERSION: version,
        CLASH_PATH_PREFIX: prefix,
        CLASH_VERSIONS: versionList,
      },
    }
  );

  // Cleanup
  fs.rmSync(tmpDir, { recursive: true });
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

// --- Main ---

const versions = getVersions();
const allVersions = [...versions, "main"];
const latest = versions[0] || "main";

// Clean output
if (fs.existsSync(outputDir)) fs.rmSync(outputDir, { recursive: true });

// Build root first (latest release, or main if no releases)
if (latest !== "main") {
  buildVersion(latest, path.join(versionsDir, latest, "pages"), "");
} else {
  buildVersion("main", path.join(siteDir, "pages"), "");
}

// Build each tagged version into its prefix
for (const v of versions) {
  buildVersion(v, path.join(versionsDir, v, "pages"), `/${v}`);
}

// Build main from current pages/
buildVersion("main", path.join(siteDir, "pages"), "/main");

console.log(`\nDone. Latest: ${latest}`);
console.log(`Versions: ${allVersions.join(", ")}`);
