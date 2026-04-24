from pathlib import Path

path = Path("backend/services/asset_classification_service.py")
text = path.read_text(encoding="utf-8")

text = text.replace(
    "    return result.rowcount or 0\n# --- end CyberAssetIQ managed compliance override ---",
    "    return {\"updated_assets\": result.rowcount or 0}\n# --- end CyberAssetIQ managed compliance override ---"
)

path.write_text(text, encoding="utf-8")
print("Fixed backfill return type to dictionary")