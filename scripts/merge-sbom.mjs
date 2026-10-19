#!/usr/bin/env node
// Merge the CycloneDX documents cargo-cyclonedx and cyclonedx-npm produce into
// the single SBOM a release ships (KR-04-F1).
//
// Two generators, two documents, and nobody wants to be told "check both
// files" when an advisory lands. One document, one question answered: does
// this build contain that library, at which version.
//
// Three properties worth keeping, because each one has a failure mode:
//
//   Deterministic. No wall clock, no random serial number - the timestamp and
//   the commit come in as arguments. Two runs over the same commit produce
//   byte-identical output, so the SBOM's line in SHA256SUMS is reproducible
//   and a re-run of a release does not look like a tampered asset.
//
//   No local paths. cargo-cyclonedx writes the absolute path of the build
//   directory into bom-refs and purls. That is the CI runner's home directory
//   leaking into a published file; --strip replaces it with ".".
//
//   Checked before it is written. Every dependency reference must resolve to a
//   component in the merged document, and no bom-ref may appear twice. A
//   graph with dangling refs still parses as JSON, which is exactly why it
//   has to be asserted here rather than discovered by whoever scans it.
//
// Usage:
//   node scripts/merge-sbom.mjs --name kino-ssh-manager --version 0.9.4 \
//     --commit <sha> --timestamp 2026-10-19T00:00:00Z \
//     --strip "$PWD" --out kino-ssh-manager-0.9.4.cdx.json \
//     src-tauri/ssh-manager.cdx.json frontend.cdx.json

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const REPO = "https://github.com/Samarthegde/kino-ssh-manager";
const SITE = "https://samarthegde.github.io/kino-ssh-manager/";

function parseArgs(argv) {
  const opts = { inputs: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const value = argv[++i];
      if (value === undefined) fail(`--${key} needs a value`);
      opts[key] = value;
    } else {
      opts.inputs.push(arg);
    }
  }
  return opts;
}

function fail(message) {
  console.error(`merge-sbom: ${message}`);
  process.exit(1);
}

/**
 * A serial number that is a function of what is being described, so it is
 * stable across runs. RFC 9562 reserves version 8 for exactly this: a UUID
 * whose bits are yours to choose, as long as the version and variant nibbles
 * say so.
 */
function serialFor(seed) {
  const h = createHash("sha256").update(seed).digest("hex").slice(0, 32);
  const bytes = h.split("");
  bytes[12] = "8"; // version 8
  bytes[16] = ((parseInt(bytes[16], 16) & 0x3) | 0x8).toString(16); // variant
  const hex = bytes.join("");
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(
    16,
    20
  )}-${hex.slice(20, 32)}`;
}

/** Tools arrive in two shapes: a 1.4 array, or a 1.5 `{components}`. */
function toolComponents(tools) {
  if (!tools) return [];
  if (Array.isArray(tools)) {
    return tools.map((t) => ({
      type: "application",
      name: t.name,
      ...(t.version ? { version: t.version } : {}),
      ...(t.vendor ? { publisher: t.vendor } : {}),
    }));
  }
  return tools.components ?? [];
}

function load(path, strip) {
  let text = readFileSync(path, "utf8");
  if (strip) {
    // Textual, before the parse, so it catches the path wherever it was
    // written - bom-refs, purls, properties - rather than only where we
    // thought to look.
    text = text.split(strip).join(".");
  }
  const doc = JSON.parse(text);
  if (doc.bomFormat !== "CycloneDX") fail(`${path} is not a CycloneDX document`);
  if (!doc.metadata?.component?.["bom-ref"] && !doc.metadata?.component?.name) {
    fail(`${path} has no metadata.component to hang its tree from`);
  }
  return doc;
}

function refOf(component) {
  return (
    component["bom-ref"] ??
    `${component.group ? `${component.group}/` : ""}${component.name}@${component.version ?? "0"}`
  );
}

const opts = parseArgs(process.argv.slice(2));
for (const required of ["name", "version", "out", "timestamp"]) {
  if (!opts[required]) fail(`--${required} is required`);
}
if (opts.inputs.length === 0) fail("give at least one CycloneDX file to merge");

const docs = opts.inputs.map((p) => load(p, opts.strip));
const specVersion = docs[0].specVersion;
for (const [i, doc] of docs.entries()) {
  if (doc.specVersion !== specVersion) {
    fail(
      `${opts.inputs[i]} is CycloneDX ${doc.specVersion} but ${opts.inputs[0]} is ${specVersion} - ` +
        `generate both with the same --spec-version rather than merging across versions`
    );
  }
}

// A purl, not `name@version`: cyclonedx-npm names its own root exactly
// `kino-ssh-manager@0.9.4`, and a merged root sharing that ref makes the
// document depend on itself. Found by looking at the output, which is the
// argument for the duplicate-ref check below.
const rootRef = `pkg:generic/${opts.name}@${opts.version}`;
const components = new Map();
const dependencies = new Map();
const tools = new Map();

function addComponent(component) {
  const ref = refOf(component);
  const existing = components.get(ref);
  if (existing && JSON.stringify(existing) !== JSON.stringify(component)) {
    fail(`two different components share the bom-ref ${ref}`);
  }
  components.set(ref, { ...component, "bom-ref": ref });
}

function addDependency(ref, dependsOn) {
  const set = dependencies.get(ref) ?? new Set();
  for (const d of dependsOn ?? []) set.add(d);
  dependencies.set(ref, set);
}

for (const doc of docs) {
  const sub = doc.metadata.component;
  // Each generator's root becomes a component of ours, which is what keeps
  // its dependency graph attached to something.
  addComponent({ ...sub, type: sub.type ?? "application", scope: "required" });
  addDependency(rootRef, [refOf(sub)]);
  for (const component of doc.components ?? []) addComponent(component);
  for (const entry of doc.dependencies ?? []) addDependency(entry.ref, entry.dependsOn);
  for (const tool of toolComponents(doc.metadata.tools)) {
    tools.set(`${tool.group ?? ""}/${tool.name}@${tool.version ?? ""}`, tool);
  }
}

tools.set("/merge-sbom.mjs", {
  type: "application",
  name: "merge-sbom.mjs",
  version: "1",
  publisher: "Kino SSH Manager",
  description: "Merges the Rust and frontend CycloneDX documents into one",
});

const merged = {
  bomFormat: "CycloneDX",
  specVersion,
  serialNumber: serialFor(`${rootRef}+${opts.commit ?? "unknown"}`),
  version: 1,
  metadata: {
    timestamp: opts.timestamp,
    tools: { components: [...tools.values()] },
    component: {
      type: "application",
      "bom-ref": rootRef,
      name: opts.name,
      version: opts.version,
      description: "Kino SSH Manager - secure SSH credential manager and terminal",
      licenses: [{ expression: "GPL-3.0-only" }],
      purl: `pkg:generic/${opts.name}@${opts.version}`,
      externalReferences: [
        { type: "vcs", url: REPO },
        { type: "website", url: SITE },
        { type: "issue-tracker", url: `${REPO}/issues` },
        { type: "security-contact", url: `${REPO}/security/advisories` },
      ],
    },
    ...(opts.commit
      ? { properties: [{ name: "kino:build:commit", value: opts.commit }] }
      : {}),
  },
  // Sorted, so the only thing that changes between two runs of the same
  // commit is nothing at all.
  components: [...components.values()].sort((a, b) =>
    a["bom-ref"] < b["bom-ref"] ? -1 : a["bom-ref"] > b["bom-ref"] ? 1 : 0
  ),
  dependencies: [...dependencies.entries()]
    .map(([ref, set]) => ({ ref, dependsOn: [...set].sort() }))
    .sort((a, b) => (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0)),
};

// The checks. A dangling reference is the failure that survives review,
// because the file still looks like an SBOM.
if (components.has(rootRef)) {
  fail(`an input already uses ${rootRef} as a bom-ref, so the merged root would collide with it`);
}
const known = new Set([rootRef, ...merged.components.map((c) => c["bom-ref"])]);
const dangling = [];
for (const entry of merged.dependencies) {
  if (!known.has(entry.ref)) dangling.push(entry.ref);
  for (const d of entry.dependsOn) if (!known.has(d)) dangling.push(d);
}
if (dangling.length > 0) {
  fail(
    `${dangling.length} dependency reference(s) point at components that are not in the document, ` +
      `starting with ${[...new Set(dangling)].slice(0, 3).join(", ")}`
  );
}
if (opts.strip && JSON.stringify(merged).includes(opts.strip)) {
  fail(`the build path ${opts.strip} survived into the merged document`);
}

writeFileSync(opts.out, `${JSON.stringify(merged, null, 2)}\n`);
console.log(
  `merge-sbom: ${opts.out} - ${merged.components.length} components from ${opts.inputs.length} documents, CycloneDX ${specVersion}`
);
