"""Simple self-update utility for WebPredator tools.
This fetches the latest release from GitHub and, if newer than current, downloads
its wheel and installs it with `pip install --upgrade`.

Usage (inside tool):
    import updater
    updater.self_update(__version__)
"""
from __future__ import annotations

import json
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Optional

import requests
from packaging import version

GITHUB_API = "https://api.github.com/repos/yourorg/webpredator/releases/latest"


def _get_latest_version() -> tuple[str, str]:
    """Return (version, wheel_download_url) of latest release."""
    resp = requests.get(GITHUB_API, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    tag = data.get("tag_name", "0.0.0").lstrip("v")
    wheel_url: Optional[str] = None
    for asset in data.get("assets", []):
        name = asset.get("name", "")
        if name.endswith(".whl"):
            wheel_url = asset.get("browser_download_url")
            break
    return tag, wheel_url or ""


def self_update(current_version: str) -> None:
    print("[*] Checking for updates…")
    try:
        latest, wheel_url = _get_latest_version()
    except Exception as e:
        print(f"[!] Update check failed: {e}")
        return

    if version.parse(latest) <= version.parse(current_version):
        print("[*] Already up to date.")
        return

    if not wheel_url:
        print(f"[!] No wheel found for latest version {latest}.")
        return

    print(f"[+] New version {latest} available – downloading…")
    try:
        with requests.get(wheel_url, stream=True, timeout=20) as r:
            r.raise_for_status()
            with tempfile.NamedTemporaryFile(delete=False, suffix=".whl") as tmp:
                shutil.copyfileobj(r.raw, tmp)
                wheel_path = tmp.name
    except Exception as e:
        print(f"[!] Download failed: {e}")
        return

    print("[+] Installing update… (requires administrator rights)")
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", wheel_path]
    try:
        subprocess.check_call(cmd)
        print("[+] Update installed. Please restart the tool.")
    except subprocess.CalledProcessError as e:
        print(f"[!] pip failed: {e}")
    finally:
        try:
            Path(wheel_path).unlink(missing_ok=True)
        except OSError:
            pass
