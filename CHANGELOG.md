# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive README.md with usage instructions and prerequisites
- CONTRIBUTING.md with contribution guidelines
- SECURITY.md with security policy and vulnerability reporting
- CODE_OF_CONDUCT.md for community standards
- CHANGELOG.md for tracking version history
- .gitignore for PowerShell and Windows artifacts
- .editorconfig for consistent code formatting
- GitHub Actions workflow for PowerShell linting
- GitHub issue templates for bugs and feature requests
- GitHub pull request template

### Changed
- Renamed `set_tls..ps1` to `set_tls.ps1` (fixed double dots typo)

### Fixed
- Repository structure documentation
- File naming consistency

## [1.0.0] - 2022-10-25

### Added
- Windows Server 2019 STIG configuration script (Win2019-STIG.ps1)
- IIS 10.0 Server STIG script v2.5
- IIS 10.0 Site STIG script v2.5
- TLS/SSL security configuration script
- Modular PowerShell modules for various applications:
  - Adobe Reader
  - Chrome
  - Defender
  - DotNet
  - Edge
  - Firefox
  - Firewall
  - IE11
  - IIS Server and Site
  - Office 2016 and 2019
  - Excel, PowerPoint, Word
- STIG evaluation answer files for IL4
- Support for multiple STIG categories

### Initial Release Notes
- Based on DISA STIG guidance
- IIS 10.0 STIG Version 2, Release 5 (27 Jan 2022)
- Supports Windows Server 2019 and compatible versions
- MIT License

[Unreleased]: https://github.com/bgauger/Compliance_as_Code/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bgauger/Compliance_as_Code/releases/tag/v1.0.0
