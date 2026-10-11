# Changelog

All notable changes to GRC Engineering OS are documented here.

## [Unreleased]

### Planned

- External policy packs
- SARIF reporting
- OSCAL-compatible assessment results
- Signed evidence bundles

## [0.1.0-alpha.2] - 2026-08-23

### Added

- Cryptographic verification for supported evidence records
- GitHub Actions quality pipeline
- Intentionally insecure AWS Terraform/OpenTofu lab
- Native `grcctl scan terraform` assurance command
- Four initial AWS assurance rules
- CIS Controls v8 and NIST SP 800-53 Rev. 5 mappings
- `--fail-on-findings` CI enforcement option
- Terraform assessment evidence schema
- Automated scanner and CLI tests
- Protected `main` branch ruleset

### Quality

- Eleven automated tests
- 80 percent overall test coverage
- 88 percent coverage for the native Terraform scanner
- Ruff formatting and linting
- mypy type checking
- Reproducible package build through `uv`

## [0.1.0-alpha.1] - 2026-08-22

### Added

- Initial `grcctl` Python package
- `grcctl doctor` system-readiness assessment
- Debian platform and resource collection
- Rootless Podman validation
- Machine-readable system-baseline evidence
- Canonical SHA-256 evidence hashing
