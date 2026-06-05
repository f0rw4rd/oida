# Code Signing Policy

This document describes how OIDA release binaries are signed and how you can
verify them. It is also the policy of record for OIDA's participation in the
[SignPath Foundation](https://signpath.org) free code-signing program for
open-source projects.

## Scope

The standalone binaries published by the **Build standalone binaries** GitHub
Actions workflow (`.github/workflows/build-binaries.yml`):

- `oida-<version>-linux-x86_64.tar.gz`: Linux x86_64 (onedir)
- `oida-<version>-windows-x86_64.zip`: Windows x86_64 (onedir)

The Windows archive contains a Portable Executable, `oida/oida.exe`, which is
the artifact that receives an Authenticode signature.

## Who signs

- The signing team **is** the development/maintenance team: the maintainers of
  this repository (`github.com/f0rw4rd/oida`), who own the source.
- Only artifacts **built from this repository's source by its own CI** are
  signed. Binaries are never signed from local developer machines.
- Signing runs in the GitHub Actions workflow above, on GitHub-hosted runners,
  from a tagged release commit.

## What is signed, and how

| Platform | Mechanism | What |
|---|---|---|
| Windows | **Authenticode** via SignPath (OV certificate) | `oida/oida.exe` inside the release `.zip`, signed in place via the `signpath.xml` artifact configuration (deep/nested signing, SignPath extracts, signs the PE, and re-zips). |
| Linux | SHA-256 checksum + GitHub build-provenance attestation | The release `.tar.gz` (ELF has no Authenticode equivalent). |
| Both | **`SHA256SUMS`** (`<archive>.sha256`) and **[GitHub Artifact Attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)** (Sigstore-backed SLSA build provenance) | Every published archive. |

## Key custody

- The Authenticode certificate and private key are held and managed by
  **SignPath.io** (cloud HSM). The project never possesses the private key.
- CI authenticates to SignPath with a REST API token stored as the GitHub
  Actions secret `SIGNPATH_API_TOKEN` (and org id in the `SIGNPATH_ORGANIZATION_ID`
  variable). The signing pipeline is a no-op when these are absent, so the build
  stays green before/without enrollment.
- Provenance attestations use short-lived Sigstore certificates issued to the
  GitHub Actions OIDC identity; there is no long-lived signing key to steal.

## How to verify a download

**Checksum** (both platforms):
```bash
sha256sum -c oida-<version>-linux-x86_64.tar.gz.sha256
```

**Build provenance** (both platforms, proves it was built by this repo's CI):
```bash
gh attestation verify oida-<version>-linux-x86_64.tar.gz --repo f0rw4rd/oida
```

**Windows Authenticode** (once signed): right-click `oida.exe` →
Properties → Digital Signatures, or:
```powershell
Get-AuthenticodeSignature .\oida\oida.exe
```

## Reporting

Suspected signing or supply-chain issues: see [SECURITY.md](../SECURITY.md).
