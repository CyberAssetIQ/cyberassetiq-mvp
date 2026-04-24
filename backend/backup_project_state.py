from __future__ import annotations
import os, sys, shutil, datetime

def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(root, f"cyberassetiq_backup_before_ui_confidence_cleanup_{stamp}")
    ignore = shutil.ignore_patterns(
        "node_modules", "__pycache__", ".git", ".pytest_cache", ".mypy_cache",
        ".venv", "venv", "*.pyc", "*.pyo", "*.zip"
    )
    shutil.copytree(root, out, dirs_exist_ok=False, ignore=ignore)
    print(f"Backup created: {out}")

if __name__ == "__main__":
    main()
