CyberAssetIQ UI Cleanup + Confidence Patch

This patch fixes:
- SecretScore / Network page overlap caused by lingering network polling UI
- network summary counters for Confirmed / Likely / Mobile-IoT
- duplicate network action buttons
- missing frontend access to Resolve Hostnames / Reclassify Assets
- overly optimistic default confidence by changing asset_confidence default to observed_host
- adds a backend /api/network-scan/reclassify-assets endpoint if missing
- returns asset_confidence in /api/network-scan/assets

Run from the project root:
  py backup_project_state.py .
  py cyberassetiq_ui_confidence_cleanup_patch.py .
  docker compose down
  docker compose build --no-cache
  docker compose up

Then hard refresh the browser:
  Ctrl + F5
