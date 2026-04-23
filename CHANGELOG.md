# Changelog

All notable changes to ClawSec are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-04-23

### Added
- `scope_guard.py`: `--allow-lab` flag that opens only the well-known lab
  ranges (HTB `10.10.0.0/16`, HTB Enterprise `10.129.0.0/16`, Offsec
  `10.11.0.0/16`) while leaving the rest of RFC1918, loopback, and metadata
  endpoints blocked.
- `scope_guard.py`: `--allowlist <file>` flag for user-authorized internal
  targets. Always-blocked ranges (loopback, `169.254.169.254`) cannot be
  opened via allowlist.
- `recon.py`: nmap XML output parsing (`-oX -`) — extracts `product`,
  `cpe`, `scripts`, `extrainfo`, `os` matches, `hostnames` and `host_state`.
- `recon.py`: TLD-aware whois fallback (Verisign, PIR, nic.io, nic.google,
  nic.ai, nic.co) to fix malformed responses on `.org`/`.io`/`.dev`/etc.
- `recon.py`: version-aware risk scoring with human-readable `risk_reason`
  (OpenSSH ≤ 6.6, Apache httpd ≤ 2.4.29, nginx < 1.16, PHP 5.x,
  vsftpd 2.3.4 backdoor, Samba 3.x, MySQL/MariaDB ≤ 5.5, IIS ≤ 7.x).
- `recon.py`: `--wordlist <path>` flag for custom subdomain wordlists.
- `recon.py`: `--output <path>` flag to control results JSON location.
- `recon.py`: optional external tool integration — uses `subfinder` or
  `amass` for subdomain enumeration when available, otherwise falls back
  to the bundled wordlist.
- `wordlists/subdomains-top200.txt`: bundled 200-entry wordlist for
  broader subdomain discovery out of the box.
- `tests/test_scope_guard.py`: 19 unit tests for scope validation.
- `tests/test_risk.py`: 11 unit tests for version-aware risk scoring.
- `.github/workflows/tests.yml`: CI on push/PR, runs on Python 3.11/3.12/3.13
  with nmap + whois installed; includes CLI smoke tests for scope guard.
- `setup_vm.sh`: distro detection for Kali/Debian/Ubuntu, root-user aware,
  seeds `~/.clawsec/allowlist.txt`, runs the self-tests.
- `README.md`: full documentation with badges, quickstart, architecture
  diagram, example scan output, scope-guard rules table, risk-scoring
  explanation, test instructions.
- `CHANGELOG.md`: this file.
- `.gitignore`: Python / editor / temp noise.

### Changed
- `recon.py` engine version bumped to `0.2.0`.
- Whois parser: added `updated_date`, normalized fields to lowercase keys,
  extract full nameserver list as a sorted set.
- `setup_vm.sh`: installs `whois` alongside `nmap`.

### Fixed
- `recon.py`: replaced deprecated `datetime.utcnow()` with timezone-aware
  `datetime.now(timezone.utc)` for Python 3.12+.
- `recon.py`: risk scoring no longer misclassifies services whose product
  name lands in nmap's `product` attribute (not `version`) — OpenSSH 6.6.1
  now correctly flags as Critical.
- `recon.py`: whois for `.org` domains no longer returns empty — falls back
  to `whois.publicinterestregistry.org` when the default query is malformed.

### Security
- `scope_guard.py`: metadata endpoints (`169.254.169.254`,
  `metadata.google.internal`, `*.internal`) and loopback (`127.0.0.0/8`)
  are now hardcoded as **always-blocked**. They cannot be opened by
  `--allow-lab` or `--allowlist`.

## [0.1.0] — 2026-04-23

### Added
- Initial ClawSec skeleton: `scope_guard.py`, `recon.py`, `setup_vm.sh`,
  `SKILL.md`, `LICENSE` (MIT), minimal README.
- Blocklist for RFC1918, loopback, link-local, multicast, and basic
  metadata regex patterns.
- Nmap regex parser with three scan profiles (quick/full/stealth).
- Basic whois field extraction.
- Small (34-entry) subdomain bruteforce wordlist.
- Port-based risk heuristic.
