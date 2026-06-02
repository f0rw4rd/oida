<!-- Thanks for contributing to OIDA. Filling this in carefully gets your
     PR merged faster than not. -->

## Summary

<!-- One sentence on what this PR does and why. -->

## Type

<!-- Pick one. Multiple → split the PR. -->

- [ ] Bug fix (links to an issue or describes the regression)
- [ ] New feature (links to a feature-request issue if there is one)
- [ ] New protocol (links to a protocol-add issue)
- [ ] Refactor (no behaviour change)
- [ ] Docs only
- [ ] CI / tooling

## What changed

<!-- Per-file or per-area: what's new, what's gone, what was kept on
     purpose. Don't make the reviewer guess from the diff. -->

## How I tested

```bash
# Exact commands you ran. Paste the final summary line.
pytest tests/unit/<area>/
```

- [ ] Unit suite passes locally (`pytest tests/unit/`)
- [ ] Integration suite passes locally OR I documented why it's not
      runnable in my environment (`pytest tests/integration/`)
- [ ] Ran `ruff format src/oida/ tests/`
- [ ] Ran `ruff check --fix src/oida/ tests/`

## Safety

<!-- Only fill in if your PR adds or touches a write / state-change
     operation. -->

- [ ] New dangerous flag(s) have help text saying `Requires --confirm`
- [ ] `validate_args()` (or equivalent) refuses the flag without
      `--confirm`
- [ ] Regression test covers both the rejected-without-confirm and
      accepted-with-confirm paths

## Breaking changes

<!-- Renamed flags? Removed CLI options? Changed JSON output schema?
     Bumped a default port? List every breaking change here so it lands
     in the next release notes. -->

## Related

<!-- Links to issues, RELEASE_TODO.md sections, audit reports, CVE
     references, upstream tracker issues. -->
