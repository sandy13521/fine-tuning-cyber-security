import fnmatch
import hashlib
import json
import os
import re
from pathlib import Path
import xml.etree.ElementTree as ET

ANDROID = "{http://schemas.android.com/apk/res/android}"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def parse_manifest(text):
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("XML DTD/entity declarations are not accepted")
    root = ET.fromstring(text)
    app = root.find("application")
    return {
        "package": root.get("package"),
        "uses_sdk": [dict(node.attrib) for node in root.findall("uses-sdk")],
        "permissions": [node.get(ANDROID + "name") for node in root.findall("uses-permission")],
        "application": dict(app.attrib) if app is not None else {},
        # Preserve raw exported/permission values; absence is NOT interpreted as false.
        "components": [{"kind": node.tag, "attributes": dict(node.attrib),
                        "intent_filters": [ET.tostring(item, encoding="unicode") for item in node.findall("intent-filter")]}
                       for node in (app if app is not None else []) if node.tag in {"activity", "activity-alias", "service", "receiver", "provider"}]
    }

def token_counter(name):
    if name == "utf8_bytes":
        return lambda text: len(text.encode("utf-8"))
    try:
        import tiktoken
    except ImportError:
        raise ValueError("Install cyber-scan[tokens] for tiktoken") from None
    encoding = tiktoken.get_encoding(name.split(":", 1)[1])
    return lambda text: len(encoding.encode(text, disallowed_special=()))

def render(path, text):
    return "FILE " + path + "\n" + "\n".join(f"{i}: {line}" for i, line in enumerate(text.splitlines(), 1))

def ingest(config):
    source = config.input_dir.resolve()
    output = config.output_dir.resolve()
    if not source.is_dir():
        raise ValueError(f"Input directory does not exist: {source}")
    if output == source or source in output.parents:
        raise ValueError("Output directory must be outside the input directory")
    inventory, texts, manifests, warnings = [], {}, [], []
    provenance = None
    provenance_path = source.parent / "decompile.json"
    if provenance_path.is_file():
        try:
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            if not isinstance(provenance, dict):
                raise ValueError("Expected object")
            if provenance.get("status") != "complete":
                warnings.append({"reason": "partial_decompilation", "status": provenance.get("status")})
        except (ValueError, OSError):
            warnings.append({"reason": "invalid_decompilation_metadata"})
            provenance = None
    for directory, dirs, names in os.walk(source, followlinks=False):
        for name in sorted(dirs[:]):
            path = Path(directory) / name
            if path.is_symlink():
                inventory.append({"path": path.relative_to(source).as_posix(), "status": "skipped", "reason": "symlink_directory"})
                dirs.remove(name)
        dirs.sort()
        for name in sorted(names):
            path = Path(directory) / name
            rel = path.relative_to(source).as_posix()
            item = {"path": rel, "status": "skipped"}
            inventory.append(item)
            if path.is_symlink():
                item["reason"] = "symlink"
                continue
            try:
                item["bytes"] = path.stat().st_size
                if item["bytes"] > config.max_file_bytes:
                    item["reason"] = "file_size_limit"
                    continue
                raw = path.read_bytes()
                item["sha256"] = digest(raw)
                if any(fnmatch.fnmatchcase(rel, pattern) for pattern in config.exclude_globs):
                    item["reason"] = "excluded_by_config"
                    continue
                if not any(fnmatch.fnmatchcase(rel, pattern) for pattern in config.include_globs):
                    item["reason"] = "unsupported_extension"
                    continue
                text = raw.decode("utf-8-sig")
                if "\x00" in text:
                    raise UnicodeError("binary data")
            except (OSError, UnicodeError) as exc:
                item["reason"] = type(exc).__name__
                continue
            item.update(status="loaded", lines=len(text.splitlines()), kind=path.suffix.lstrip("."))
            texts[rel] = text
            if path.name == "AndroidManifest.xml":
                try:
                    manifests.append({"path": rel, **parse_manifest(text)})
                except (ET.ParseError, ValueError) as exc:
                    warnings.append({"path": rel, "reason": "manifest_parse_error", "detail": str(exc)})
            elif path.suffix == ".xml":
                try:
                    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
                        raise ValueError("DTD/entity declaration")
                    ET.fromstring(text)
                except (ET.ParseError, ValueError) as exc:
                    warnings.append({"path": rel, "reason": "xml_parse_error", "detail": str(exc)})
    if not texts:
        raise ValueError("No supported UTF-8 files were loaded")
    if not manifests:
        warnings.append({"reason": "no_parseable_manifest"})
    packages = {entry["package"] for entry in manifests if entry["package"]}
    for item in inventory:
        if item["path"] in texts:
            text = texts[item["path"]]
            match = re.search(r"^\s*package\s+([\w.]+)", text, re.MULTILINE)
            package = match.group(1) if match else ""
            item["ownership_hint"] = "application" if any(package == p or package.startswith(p + ".") for p in packages) else "unknown_or_dependency"
    count = token_counter(config.tokenizer)
    rendered = {path: render(path, text) for path, text in texts.items()}
    manifest_paths = sorted(entry["path"] for entry in manifests)
    by_class = {}
    by_xml = {}
    for path in texts:
        if Path(path).suffix == ".xml":
            by_xml.setdefault(Path(path).stem, []).append(path)
        if Path(path).suffix in {".java", ".kt"}:
            by_class.setdefault(Path(path).stem, []).append(path)
    bundles, uncovered = [], []
    app_paths = {item["path"] for item in inventory if item.get("ownership_hint") == "application"}
    ordered = sorted(texts, key=lambda path: (path not in manifest_paths, path not in app_paths, path))
    for primary in ordered:
        body = rendered[primary]
        if count(body) > config.bundle_token_budget:
            uncovered.append({"path": primary, "reason": "whole_file_exceeds_bundle_budget", "tokens_or_estimate": count(body)})
            continue
        identifiers = set(re.findall(r"\b[A-Za-z_$][\w$]*\b", texts[primary]))
        related = sorted({path for identifier in identifiers for path in by_class.get(identifier, [])})
        # Include referenced XML resources when discoverable using R.xml / @xml syntax.
        resources = set(re.findall(r"(?:R\.xml\.|@xml/)([A-Za-z0-9_]+)", texts[primary]))
        related += sorted({path for name in resources for path in by_xml.get(name, [])})
        selected, omitted, context_chars = [primary], [], 0
        for path in dict.fromkeys(manifest_paths + related):
            if path == primary:
                continue
            addition = "\n\n" + rendered[path]
            if context_chars + len(addition) <= config.context_char_budget and count(body + addition) <= config.bundle_token_budget:
                selected.append(path)
                body += addition
                context_chars += len(addition)
            else:
                omitted.append(path)
        bundles.append({"id": digest(body.encode()), "primary": primary, "files": selected,
                        "omitted_related_files": omitted, "tokens_or_estimate": count(body), "content": body})
    settings = config.model_dump(mode="json", exclude={"input_dir", "output_dir", "models"})
    identity = {"pipeline_version": "0.1.0", "inventory": inventory, "settings": settings, "apk_sha256": (provenance or {}).get("apk_sha256"), "decompilation_status": (provenance or {}).get("status")}
    run_id = digest(json.dumps(identity, sort_keys=True).encode())
    destination = output / run_id / "ingest"
    destination.mkdir(parents=True, exist_ok=True)
    bundled_files = {path for bundle in bundles for path in bundle["files"]}
    coverage = {"inventory_count": len(inventory), "loaded_files": len(texts), "bundle_count": len(bundles),
                "bundled_unique_files": len(bundled_files), "uncovered": uncovered,
                "skipped": [item for item in inventory if item["status"] == "skipped"], "warnings": warnings,
                "total_bundle_tokens_or_estimate": sum(bundle["tokens_or_estimate"] for bundle in bundles),
                "tokenizer": config.tokenizer, "is_estimate": config.tokenizer == "utf8_bytes",
                "note": "Ingestion coverage is not vulnerability-analysis coverage. Native binaries are not analyzed."}
    write_json(destination / "metadata.json", {"run_id": run_id, "pipeline_version": "0.1.0", "settings": settings, "decompilation": provenance})
    write_json(destination / "manifest.json", manifests)
    write_json(destination / "inventory.json", inventory)
    write_json(destination / "coverage.json", coverage)
    (destination / "bundles.jsonl").write_text("".join(json.dumps(bundle, sort_keys=True) + "\n" for bundle in bundles), encoding="utf-8")
    return destination, coverage
