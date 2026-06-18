# Contributing to OIDA

Contributions are welcome! By contributing, you agree to the terms below.

## How to Contribute

1. **Fork** the repository and create a feature branch from `main`
2. **Write** your code following the existing style (Black, 100-char lines)
3. **Test** your changes: `python run_tests.py`
4. **Submit** a Pull Request with a clear description of your changes

### What We Accept

- Bug fixes and security improvements
- New protocol scanners following the `BaseScanner` architecture
- New mock services for testing
- Documentation improvements
- Test coverage improvements

### What We Don't Accept

- Changes that break backward compatibility without discussion
- Features that enable unauthorized access or attacks beyond the tool's scope
- Dependencies with licenses incompatible with AGPL-3.0

## Code Standards

- Python 3.8+ compatibility
- Type hints where practical
- All scanners inherit from `BaseScanner` (Layer 1) or `NetworkConnection` (Layer 2)
- Protocol CLI arguments in `protocols/{name}/proto_args.py`
- Unit tests for new functionality

## AI-assisted contributions

AI-assisted contributions (e.g. code written with Copilot, Claude, ChatGPT) are
welcome. However, AI co-author lines (`Co-Authored-By`) are not permitted in
commit messages — a pre-commit hook enforces this. You are the author of your
contribution; the tooling you used does not need attribution in the git history.

---

## Contributor License Agreement

**By submitting a contribution (including but not limited to code, documentation,
bug reports with patches, configuration files, test data, or any other material)
to this project via pull request, patch, issue, email, or any other mechanism,
you agree to the following terms:**

### 1. Grant of Copyright License

You hereby grant to the OIDA Project and its maintainers a perpetual,
worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license
to reproduce, prepare derivative works of, publicly display, publicly perform,
sublicense, relicense, and distribute your contributions and any derivative works
thereof, under any license terms, including without limitation any open source
license, proprietary license, or dual-licensing arrangement.

### 2. Grant of Patent License

You hereby grant to the OIDA Project and its maintainers a perpetual,
worldwide, non-exclusive, no-charge, royalty-free, irrevocable patent license to
make, have made, use, offer to sell, sell, import, and otherwise transfer the
contribution, where such license applies only to those patent claims licensable
by you that are necessarily infringed by your contribution alone or by
combination of your contribution with the project to which the contribution was
submitted.

### 3. Right to Relicense

You explicitly acknowledge and agree that the OIDA Project maintainers may,
at their sole discretion, relicense the project (including your contributions)
under different license terms in the future. This includes but is not limited to
changing the project license, offering the project under dual-license or
multi-license arrangements, or granting additional permissions beyond those in
the current license.

### 4. Representations

You represent that:

(a) You are legally entitled to grant the above licenses. If your employer has
rights to intellectual property that you create, you represent that you have
received permission to make the contribution on behalf of that employer, or that
your employer has waived such rights for your contributions to this project.

(b) Each of your contributions is your original creation. If any part of your
contribution is not your original creation, you will clearly identify the
complete details of its source, any license or other restriction of which you are
aware, and will submit such contributions separately with clear attribution.

(c) You understand that this project and your contributions are public, and that
a record of the contribution (including all personal information you submit with
it) is maintained indefinitely and may be redistributed consistent with the
project's license.

### 5. No Obligation

You understand that the decision to include your contribution in the project is
entirely at the discretion of the project maintainers, and this agreement does
not obligate the project to use or include your contribution.

### 6. Contributor Retains Rights

This agreement does not transfer ownership of your contribution. You retain all
right, title, and interest in your contributions. You are free to use your
contributions in any other project under any terms you choose.

### 7. Submission Constitutes Agreement

**Submitting a pull request, patch, or other contribution to this repository
constitutes your acceptance of these terms.** No separate signature or CLA form
is required. If you do not agree to these terms, do not submit contributions.

---

## Security Vulnerability Reporting

If you discover a security vulnerability in OIDA itself (not in targets being
tested), please report it responsibly:

1. **Do not** open a public issue
2. Email the maintainers directly (see SECURITY.md if available)
3. Allow reasonable time for a fix before public disclosure

## Questions?

Open a GitHub Discussion or Issue for questions about contributing.
