# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| `0.1.x` | Yes |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected security vulnerabilities (such as path traversal, memory exhaustion, integer overflow, or cryptographic authentication bypass).

Instead, use GitHub's [Private Vulnerability Reporting](https://github.com/zelvior/znf/security/advisories/new) on the `zelvior/znf` repository and include:

1. Affected crate(s) and version (`znf-core`, `znf-crypto`, `znf-zarc`, etc.).
2. Minimal reproducer or hex test vector demonstrating the issue.
3. Expected vs. actual behavior.

See [`docs/security/THREAT-MODEL.md`](docs/security/THREAT-MODEL.md) for the security invariants enforced by ZNF.
