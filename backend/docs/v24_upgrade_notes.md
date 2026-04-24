# CyberAssetIQ v24 upgrade notes

## Added in this upgrade

### A. Asset correlation engine
- Added unified asset correlation across:
  - managed agent assets
  - unmanaged network-discovered assets
  - linked dark-web exposure metadata
- Matching logic uses IP, MAC, hostname, and related identity/domain hints.

### B. Risk scoring
- Added visible 0-100 risk scoring per unified asset.
- Risk includes:
  - unmanaged / shadow IT penalty
  - open CVEs
  - exposed ports
  - firewall / endpoint protection gaps
  - stale telemetry
  - dark-web-linked exposure boost
- Added remediation guidance and top-risk summaries.

### C. Investor dashboard upgrade
- Rebuilt the FastAPI dashboard UI to emphasise:
  - single-pane asset view
  - live scan state
  - narrative storyline cards
  - top-risk prioritisation
  - per-asset detail with recommended actions
- Added auto refresh every 10 seconds for demo realism.

### D. Demo assets
- Added an investor demo script in `docs/investor_demo_script.md`.
- Added an investor slide deck outside the code bundle as a separate artifact.
