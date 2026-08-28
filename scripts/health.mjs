#!/usr/bin/env node
// Audit every non-fork repo on the account and write a dated health report.
// Needs `gh` (authenticated), `git`, and `npm` for the dependency audit.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const OWNER = process.env.TARGET_OWNER || "furyengi";
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPORTS = path.join(ROOT, "reports");
const CLONE_TIMEOUT = 180_000;
const AUDIT_TIMEOUT = 240_000;

const TODO_RE = /\b(TODO|FIXME|HACK|XXX)\b/g;
const SKIP_DIRS = new Set([
  ".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__",
]);
const TEXT_EXT = new Set([
  ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java",
  ".c", ".h", ".cpp", ".hpp", ".cs", ".rb", ".php", ".sh", ".html", ".css",
  ".scss", ".vue", ".svelte", ".yml", ".yaml", ".sql",
]);
const MANIFESTS = {
  "package.json": "npm",
  "requirements.txt": "pip",
  "pyproject.toml": "python",
  Pipfile: "pipenv",
  "go.mod": "go",
  "Cargo.toml": "cargo",
  "pom.xml": "maven",
  "build.gradle": "gradle",
  "composer.json": "composer",
  Gemfile: "bundler",
};

// Returns { code, stdout, stderr } and never throws on a non-zero exit.
// `shell` stays off so arguments containing & or ? survive on Windows, where
// npm is instead reached through its .cmd shim.
function run(cmd, args, opts = {}) {
  const bin = cmd === "npm" && process.platform === "win32" ? "npm.cmd" : cmd;
  try {
    const stdout = execFileSync(bin, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 64 * 1024 * 1024,
      ...opts,
    });
    return { code: 0, stdout, stderr: "" };
  } catch (err) {
    return {
      code: err.status ?? 1,
      stdout: err.stdout?.toString() ?? "",
      stderr: err.stderr?.toString() ?? String(err.message ?? err),
    };
  }
}

function ghJson(apiPath) {
  const res = run("gh", ["api", apiPath]);
  if (res.code !== 0) throw new Error(`gh api ${apiPath} failed: ${res.stderr.trim()}`);
  return JSON.parse(res.stdout);
}

function listRepos() {
  const repos = ghJson(`users/${OWNER}/repos?per_page=100&sort=updated`);
  return repos.filter((r) => !r.fork && !r.archived);
}

const daysSince = (iso) =>
  Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000);

const exists = (p) => fs.existsSync(p);

// Walk a checkout: count source files, lines, and TODO-style markers.
function scanTree(root) {
  let files = 0;
  let lines = 0;
  let todos = 0;
  const biggest = [];

  const walk = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!TEXT_EXT.has(path.extname(entry.name).toLowerCase())) continue;
      let text;
      try {
        text = fs.readFileSync(full, "utf8");
      } catch {
        continue;
      }
      files += 1;
      const n = text.split("\n").length;
      lines += n;
      todos += (text.match(TODO_RE) || []).length;
      biggest.push([n, path.relative(root, full).split(path.sep).join("/")]);
    }
  };

  walk(root);
  biggest.sort((a, b) => b[0] - a[0]);
  return { files, lines, todos, biggest: biggest.slice(0, 3) };
}

// Vulnerability counts by severity, or { error } if we had to skip.
function npmAudit(dir) {
  if (!exists(path.join(dir, "package.json"))) return null;

  const hasLock =
    exists(path.join(dir, "package-lock.json")) ||
    exists(path.join(dir, "npm-shrinkwrap.json"));
  if (!hasLock) {
    const gen = run(
      "npm",
      ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
      { cwd: dir, timeout: AUDIT_TIMEOUT },
    );
    if (gen.code !== 0) return { error: "could not resolve a lockfile" };
  }

  const res = run("npm", ["audit", "--json"], { cwd: dir, timeout: AUDIT_TIMEOUT });
  let data;
  try {
    data = JSON.parse(res.stdout);
  } catch {
    return { error: "npm audit produced no parseable output" };
  }
  const meta = data?.metadata?.vulnerabilities;
  if (!meta) return { error: data?.error?.summary || "no audit metadata" };

  const out = {};
  for (const [sev, count] of Object.entries(meta)) {
    if (sev !== "total" && count) out[sev] = count;
  }
  return out;
}

function hygiene(dir) {
  const names = fs
    .readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => e.name.toLowerCase());
  const checks = {
    README: names.some((n) => n.startsWith("readme")),
    LICENSE: names.some(
      (n) => n.startsWith("license") || n.startsWith("licence") || n.startsWith("copying"),
    ),
    ".gitignore": names.includes(".gitignore"),
    CI: fs.existsSync(path.join(dir, ".github", "workflows")),
  };
  const stacks = [
    ...new Set(
      Object.entries(MANIFESTS)
        .filter(([file]) => exists(path.join(dir, file)))
        .map(([, stack]) => stack),
    ),
  ].sort();
  return { checks, stacks };
}

function baseEntry(repo) {
  return {
    name: repo.name,
    url: repo.html_url,
    description: repo.description || "",
    language: repo.language || "-",
    stars: repo.stargazers_count,
    open_issues: repo.open_issues_count,
    license: repo.license?.spdx_id || null,
    stale_days: daysSince(repo.pushed_at),
    default_branch: repo.default_branch,
  };
}

function auditRepo(repo, workdir) {
  const entry = baseEntry(repo);
  const dest = path.join(workdir, repo.name);

  const clone = run(
    "git",
    ["clone", "--depth", "1", "--quiet", `https://github.com/${OWNER}/${repo.name}.git`, dest],
    { timeout: CLONE_TIMEOUT },
  );
  if (clone.code !== 0) {
    const tail = clone.stderr.trim().split("\n").filter(Boolean);
    entry.error = tail.length ? tail[tail.length - 1] : "clone failed";
    return entry;
  }

  entry.scan = scanTree(dest);
  const { checks, stacks } = hygiene(dest);
  entry.checks = checks;
  entry.stacks = stacks;
  entry.npm = npmAudit(dest);

  fs.rmSync(dest, { recursive: true, force: true });
  return entry;
}

// Things a human should actually look at.
function flagsFor(e) {
  const out = [];
  const npm = e.npm;
  if (npm && !npm.error) {
    for (const sev of ["critical", "high"]) {
      if (npm[sev]) out.push(`${npm[sev]} ${sev} npm vuln${npm[sev] > 1 ? "s" : ""}`);
    }
  }
  if (e.error) out.push(e.error);
  const missing = ["README", "LICENSE", "CI"].filter(
    (k) => e.checks && e.checks[k] === false,
  );
  if (missing.length) out.push("no " + missing.join("/"));
  if (e.stale_days > 180) out.push(`untouched ${e.stale_days}d`);
  if (e.open_issues) out.push(`${e.open_issues} open issue/PR`);
  return out;
}

function render(entries, date) {
  const tick = (v) => (v === true ? "yes" : v === false ? "**no**" : "-");
  const byName = [...entries].sort((a, b) => a.name.localeCompare(b.name));
  const L = [
    `# Repo health - ${date}`,
    "",
    `${entries.length} non-fork repos on [@${OWNER}](https://github.com/${OWNER}).`,
    "",
    "| Repo | Lang | LoC | TODOs | Vulns (crit/high) | README | LICENSE | CI | Last push |",
    "|---|---|--:|--:|--:|:-:|:-:|:-:|--:|",
  ];

  for (const e of byName) {
    const s = e.scan || {};
    const c = e.checks || {};
    const npm = e.npm;
    const vulns = npm && !npm.error ? `${npm.critical || 0}/${npm.high || 0}` : "-";
    L.push(
      `| [${e.name}](${e.url}) | ${e.language} | ${s.lines ?? "-"} | ${s.todos ?? "-"} | ` +
        `${vulns} | ${tick(c.README)} | ${tick(c.LICENSE)} | ${tick(c.CI)} | ${e.stale_days}d ago |`,
    );
  }

  L.push("", "## Needs attention", "");
  const ranked = [...entries].sort((a, b) => flagsFor(b).length - flagsFor(a).length);
  let anyFlag = false;
  for (const e of ranked) {
    const fl = flagsFor(e);
    if (!fl.length) continue;
    anyFlag = true;
    L.push(`- **${e.name}** - ${fl.join("; ")}`);
  }
  if (!anyFlag) L.push("- Nothing flagged.");

  L.push("", "## Detail", "");
  for (const e of byName) {
    L.push(`### ${e.name}`);
    if (e.description) L.push(`> ${e.description}`);
    if (e.error) {
      L.push("", `Could not audit: ${e.error}`, "");
      continue;
    }
    const s = e.scan;
    L.push("");
    L.push(`- ${s.files} source files, ${s.lines} lines, ${s.todos} TODO/FIXME markers`);
    L.push(`- Stacks: ${e.stacks.join(", ") || "none detected"}`);
    L.push(
      `- License: ${e.license || "none"} - stars ${e.stars} - open issues/PRs ${e.open_issues}`,
    );
    if (s.biggest.length) {
      L.push(`- Longest files: ${s.biggest.map(([n, p]) => `\`${p}\` (${n})`).join(", ")}`);
    }
    if (e.npm) {
      L.push(
        e.npm.error
          ? `- npm audit: skipped (${e.npm.error})`
          : "- npm audit: " +
              Object.entries(e.npm)
                .map(([k, v]) => `${v} ${k}`)
                .join(", "),
      );
    }
    L.push("");
  }

  return L.join("\n").replace(/\s+$/, "") + "\n";
}

function main() {
  const date = new Date().toISOString().slice(0, 10);
  const repos = listRepos();
  console.error(`auditing ${repos.length} non-fork repos`);

  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "repo-health-"));
  const entries = [];
  try {
    for (const repo of repos) {
      console.error("  " + repo.name);
      try {
        entries.push(auditRepo(repo, workdir));
      } catch (err) {
        // One bad repo must not sink the run.
        entries.push({ ...baseEntry(repo), error: String(err.message ?? err).slice(0, 200) });
      }
    }
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }

  fs.mkdirSync(REPORTS, { recursive: true });
  const body = render(entries, date);
  fs.writeFileSync(path.join(REPORTS, `${date}.md`), body);
  fs.writeFileSync(path.join(ROOT, "latest.md"), body);
  fs.writeFileSync(
    path.join(REPORTS, `${date}.json`),
    JSON.stringify(entries, null, 2) + "\n",
  );
  console.log(`wrote reports/${date}.md`);
}

main();
