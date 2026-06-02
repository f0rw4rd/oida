# Contributor Code of Conduct

OIDA is a small project; the rules are correspondingly short.

## Be technically honest

- Report what you measured, not what you wanted to measure.
- "Tests pass" means you ran them and watched them pass, not that they
  looked like they would.
- If you cite a CVE, link the NVD/MITRE entry. If you cite a packet, link
  the pcap.
- When you don't know, say "I don't know" and ask. That is always faster
  than the alternative.

## Be technically respectful

- Critique the patch, not the person. "This will OOM on a malformed
  response" is fine; "this is stupid" is not.
- Reviews go quickly when the patch author has done the diligence first
  (description, tests, ran the suite). Reciprocate when you review.
- ICS-security work touches systems that matter. A casual "lol it
  crashed the PLC" in a public channel is not appropriate.

## Be useful

- Issues should have a reproducer or a clear "I cannot reproduce because
  X".
- PRs should be the smallest change that solves the problem. If a PR
  carries a refactor + a fix + a feature, split it.
- If you find a bug you can't fix, file the issue anyway with as much
  detail as you have.

## Enforcement

This is a single-maintainer project. The maintainer will close
discussions or remove contributors who repeatedly ignore the above.
Disagreement is fine; bad-faith behaviour is not.

## Reporting concerns

Email **fnbriearfz@pm.me** with anything that doesn't belong in a public
issue thread. Security issues go via `SECURITY.md`, not here.
