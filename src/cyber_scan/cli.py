import argparse
import json
import httpx
import subprocess
import zipfile
from pathlib import Path
from pydantic import ValidationError
from .config import load_config
from .ingest.apk import download_apk, decompile
from .ingest.pipeline import ingest, write_json
from .models import create_client
from .models.openai_compatible import ModelError


def main(argv=None):
    parser = argparse.ArgumentParser(description="APK ingestion and model connectivity; scanning is a subsequent milestone")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate-config", "ingest", "model-smoke"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        if name == "model-smoke":
            command.add_argument("--role", choices=["teacher", "student"], required=True)
            command.add_argument("--output", type=Path, required=True)
    download = commands.add_parser("download")
    download.add_argument("--url", required=True)
    download.add_argument("--output", type=Path, required=True)
    download.add_argument("--sha256")
    decode = commands.add_parser("decompile")
    decode.add_argument("--apk", type=Path, required=True)
    decode.add_argument("--output", type=Path, required=True)
    decode.add_argument("--jadx", default="jadx")
    decode.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        if args.command == "download":
            print(download_apk(args.url, args.output, args.sha256))
        elif args.command == "decompile":
            print(decompile(args.apk, args.output, args.jadx, args.timeout))
        else:
            config = load_config(args.config)
            if args.command == "validate-config":
                print("Configuration valid. Credentials and model availability have not been checked.")
            elif args.command == "ingest":
                destination, coverage = ingest(config)
                print(json.dumps({"output": str(destination), "coverage": coverage}, indent=2))
            else:
                if args.role not in config.models:
                    raise ValueError(f"No model configured for {args.role}")
                if args.output.exists():
                    raise ValueError("Smoke-test output already exists")
                messages = [{"role": "user", "content": "Reply with exactly OK."}]
                response = create_client(config.models[args.role]).generate(messages)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                write_json(args.output, {"config": config.models[args.role].model_dump(), "messages": messages,
                                         "response": response.model_dump(), "is_vulnerability_scan": False})
                if response.finish_reason not in (None, "stop") or response.text.strip() != "OK":
                    raise ValueError("Provider responded but smoke assertion failed; inspect saved output")
                print(f"Model connectivity verified; saved {args.output}")
    except ValidationError as exc:
        # Pydantic errors can echo user-entered secrets, so only report field locations.
        parser.exit(2, "Invalid configuration/schema fields: " + ", ".join(".".join(map(str, error["loc"])) for error in exc.errors()) + "\n")
    except httpx.HTTPError:
        parser.exit(2, "Download request failed; check URL and network access.\n")
    except (ValueError, OSError, ModelError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        parser.exit(2, str(exc) + "\n")
