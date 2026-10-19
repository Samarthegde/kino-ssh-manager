#!/usr/bin/env node
// Validate a CycloneDX document against the spec's own JSON schema, strictly
// (KR-04-A1). Run in CI after merge-sbom.mjs, so a release cannot ship an
// SBOM that a scanner will reject.
//
// merge-sbom.mjs checks what it can see - dangling refs, duplicate bom-refs,
// leaked build paths. It cannot check the spec, because it does not carry a
// copy of it. This does, by way of @cyclonedx/cyclonedx-library, installed
// for the occasion rather than kept as a project dependency: it is a CI tool,
// not something the app ships.
//
// Usage: node scripts/validate-sbom.mjs <file.cdx.json> [spec-version]

import { readFile } from "node:fs/promises";

const [file, spec = "1.5"] = process.argv.slice(2);
if (!file) {
  console.error("validate-sbom: give it a CycloneDX file");
  process.exit(1);
}

let Validation;
try {
  ({ Validation } = await import("@cyclonedx/cyclonedx-library"));
} catch {
  // Loudly, rather than passing. A validation step that quietly skips itself
  // is worse than no validation step: the log still says it ran.
  console.error(
    "validate-sbom: @cyclonedx/cyclonedx-library is not installed - " +
      "`npm install --no-save @cyclonedx/cyclonedx-library` first"
  );
  process.exit(1);
}

const errors = await new Validation.JsonStrictValidator(spec).validate(
  await readFile(file, "utf8")
);
if (errors !== null) {
  console.error(`validate-sbom: ${file} is not valid CycloneDX ${spec}`);
  console.error(JSON.stringify(errors.details ?? errors, null, 2).slice(0, 4000));
  process.exit(1);
}
console.log(`validate-sbom: ${file} is valid CycloneDX ${spec}`);
