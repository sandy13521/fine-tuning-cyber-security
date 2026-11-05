import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from urllib.parse import urlparse
import httpx
from .pipeline import write_json


def hash_file(path):
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def download_apk(url, output, expected_sha256=None, max_bytes=500_000_000):
    if urlparse(url).scheme != "https":
        raise ValueError("APK URL must use HTTPS")
    if output.exists() or output.with_suffix(".download.json").exists():
        raise ValueError("Download destination or metadata already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_suffix(".part")
    try:
        with partial.open("xb") as target:
            with httpx.stream("GET", url, follow_redirects=True, timeout=60) as response:
                response.raise_for_status()
                if any(item.url.scheme != "https" for item in [*response.history, response]):
                    raise ValueError("Download redirected to non-HTTPS URL")
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise ValueError("APK exceeds download size limit")
                    target.write(chunk)
        checksum = hash_file(partial)
        if expected_sha256 and checksum.lower() != expected_sha256.lower():
            raise ValueError("APK checksum mismatch")
        with zipfile.ZipFile(partial) as archive:
            if "AndroidManifest.xml" not in archive.namelist():
                raise ValueError("Archive is not an APK: missing AndroidManifest.xml")
        partial.rename(output)
        write_json(output.with_suffix(".download.json"), {"source_url": url, "sha256": checksum, "bytes": size})
        return checksum
    finally:
        # Only remove a partial created by this call (exclusive creation prevents overlap).
        if 'target' in locals() and partial.exists():
            partial.unlink()


def decompile(apk, output, jadx="jadx", timeout=300):
    if not apk.is_file():
        raise ValueError("APK does not exist")
    if output.exists():
        raise ValueError("Decompile destination must not exist; choose a fresh directory")
    version = subprocess.run([jadx, "--version"], capture_output=True, text=True, timeout=15, check=True).stdout.strip()
    output.mkdir(parents=True)
    sources = output / "decompiled"
    command = [jadx, "-d", str(sources.resolve()), str(apk.resolve())]
    metadata = {"apk_sha256": hash_file(apk), "jadx_version": version, "command": command}
    download_metadata = apk.with_suffix(".download.json")
    if download_metadata.is_file():
        metadata["download"] = json.loads(download_metadata.read_text())
    try:
        with (output / "jadx.log").open("w") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        metadata.update(exit_code=result.returncode, status="complete" if result.returncode == 0 else "partial_or_failed")
    except subprocess.TimeoutExpired:
        metadata.update(status="timeout", exit_code=None)
    finally:
        write_json(output / "decompile.json", metadata)
    if metadata["status"] != "complete":
        raise ValueError("Decompilation failed or was partial; inspect jadx.log and decompile.json before ingesting partial output")
    return sources
