# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added 
- PII scan rule to detect aadhar card and PAN card information

### Changed 
- Backup File Disclosure Scan Rule to minimize false positive by having an additional check 
- Fixed false positives arising in PII Scan rule
- Detect '-' separated numbers along with space separated (credit card number or identity card numbers can be '-' separated too.)

## [1.0.0] - 2023-07-24
### Added
- Initial commit
