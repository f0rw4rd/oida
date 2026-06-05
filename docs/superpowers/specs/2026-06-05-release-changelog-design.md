# Design: one-click, curated-changelog releases

**Date:** 2026-06-05
**Status:** approved (pending spec review)

## Goal

Cutting a release should produce a GitHub Release whose notes are the
hand-curated `CHANGELOG.md` section for that version, with the standalone
binaries + checksums attached — triggered by a single one-click action, with the
tag, `oida.__version__`, and the dated changelog all guaranteed consistent.

## Decisions (from brainstorming)

- **Source of truth = the curated `CHANGELOG.md`** (Keep a Changelog style,
  `## <version> — <date|unreleased>` headers). Not auto-generated from commits —
  the narrative quality is the point.
- **One-click trigger** (a `workflow_dispatch` with a `version` input), *not* a
  hand-pushed tag — so CI can date the changelog and create the tag *at the same
  commit*, keeping the tag self-consistent.
- **Maintainer owns the version.** The action validates and dates; it never
  bumps `__version__`. Auto-bump / next-cycle scaffolding is out of scope (YAGNI).
- **Publish immediately** (not a draft) — the changelog is curated and reviewed
  before the maintainer clicks Release.

## The version lives in three places (must agree)

1. `src/oida/__init__.py` → `__version__ = "X.Y.Z"` (pyproject reads it via
   `version = {attr = "oida.__version__"}`).
2. `CHANGELOG.md` header → `## X.Y.Z — unreleased`.
3. The git tag → `vX.Y.Z`.

The release action enforces agreement (1) == (2) == input, then creates (3).

## Components

### 1. `scripts/changelog.py` — reusable, testable helper

A small module operating on `CHANGELOG.md`, with a CLI:

- `extract <version>` → prints the body of the `## <version> — …` section
  (everything between that header and the next `## ` header), for use as the
  release-notes body. Exit non-zero if the version section is absent.
- `promote <version> <date>` → rewrites `## <version> — unreleased` to
  `## <version> — <date>` in place. Exit non-zero if no matching
  `— unreleased` header exists (prevents dating an already-released or missing
  version).

Notes:
- Header format uses an em-dash (`—`); the parser matches that literal.
- Pure stdlib; no third-party deps. One clear purpose, independently testable.

### 2. `.github/workflows/release.yml` — the "cut a release" button

- **Trigger:** `workflow_dispatch`, input `version` (e.g. `1.0.0`,
  `1.0.0-rc1`).
- **Permissions:** `contents: write` (commit + tag).
- **Steps:**
  1. **Validate**: assert `version` == `oida.__version__` *and* a
     `## <version> — unreleased` header exists. Fail fast on any mismatch.
  2. **Promote**: `python scripts/changelog.py promote <version> $(date -u +%F)`.
  3. **Commit** to the default branch: `release: v<version>` (changelog only).
  4. **Tag**: create and push `v<version>` pointing at that commit.

The tag push is the only output; everything downstream keys off the tag.

### 3. `.github/workflows/build-binaries.yml` — add a final `release` job

The existing build matrix is unchanged. Add a job:

- `needs: build`, `if: startsWith(github.ref, 'refs/tags/v')` (tag builds only).
- **Permissions:** `contents: write` (create the release).
- **Steps:**
  1. `actions/download-artifact` → gather both archives + `.sha256` files.
  2. `python scripts/changelog.py extract <version>` (version =
     `${github.ref_name}` minus the `v`) → `notes.md`.
  3. `gh release create v<version> --title "v<version>" --notes-file notes.md
     <archives> <checksums>`.
  4. **Pre-release**: if the version contains a `-` (e.g. `1.0.0-rc1`), pass
     `--prerelease`.

## Data flow

```
maintainer: write CHANGELOG '## 1.0.0 — unreleased' + set __version__ = 1.0.0
   └─ Actions ▶ Run "Release" (version = 1.0.0)
         └─ release.yml: validate ⇒ date changelog ⇒ commit ⇒ tag v1.0.0 (same commit)
               └─ tag v1.0.0 triggers build-binaries.yml
                     ├─ build matrix (existing): onedir + smoke + checksum [+ attest]
                     └─ release job: extract '## 1.0.0' ⇒ gh release create
                           ⇒ GitHub Release: curated notes + binaries + checksums
```

## Error handling

| Condition | Behaviour |
|---|---|
| input version ≠ `__version__` | release.yml fails at Validate, before any write |
| no `## <version> — unreleased` header | release.yml fails at Validate / `promote` exits non-zero |
| version section missing at extract time | release job fails (`extract` non-zero) — release not created |
| version contains `-` | GitHub Release marked `--prerelease` |
| default branch is protected against Actions pushes | release.yml's commit/tag push fails — documented; maintainer grants the token push rights or runs locally |

## Testing

- `tests/unit/test_changelog.py`: covers `extract` (correct section, trailing
  trim, missing-version error) and `promote` (dates the right header,
  idempotency/error when no `— unreleased`). Uses an in-test fixture
  `CHANGELOG` string, not the repo file.

## Out of scope (YAGNI)

- Auto-bumping `__version__` or auto-adding the next `## <next> — unreleased`
  section after release.
- Generating the changelog from commit messages.
- Signing/attestation changes (already handled in `build-binaries.yml`).
- Non-`v*` or non-x86_64 release artifacts.
