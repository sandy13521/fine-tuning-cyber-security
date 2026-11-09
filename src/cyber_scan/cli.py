import argparse
import json
import httpx
import subprocess
import zipfile
from pathlib import Path
from pydantic import ValidationError
from .config import ModelConfig, load_config
from .distill import prepare_distill
from .ingest.apk import download_apk, decompile
from .ingest.pipeline import ingest, write_json
from .models import create_client
from .models.openai_compatible import ModelError
from .scan.plan import build_plan
from .scan.prompts import lesson_appendix
from .scan.runner import run_scan
from .schemas import LessonSet


def main(argv=None):
    parser = argparse.ArgumentParser(description="Reproducible APK ingestion and evidence-linked static scans")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate-config", "ingest", "model-smoke"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        if name == "model-smoke":
            command.add_argument("--role", choices=["teacher", "student"], required=True)
            command.add_argument("--output", type=Path, required=True)
    plan = commands.add_parser("plan-scan")
    plan.add_argument("--config", type=Path, required=True)
    plan.add_argument("--ingest-dir", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--config", type=Path, required=True)
    scan.add_argument("--plan", type=Path, required=True)
    scan.add_argument("--output", type=Path, required=True)
    scan.add_argument("--role", choices=["teacher", "student"], default="teacher")
    scan.add_argument("--resume", action="store_true")
    scan.add_argument("--retry-failed", action="store_true")
    scan.add_argument("--max-requests", type=int)
    scan.add_argument("--delay-seconds", type=float, default=0)
    scan.add_argument("--local-model", type=Path, help="Local Transformers chat checkpoint")
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument("--lessons", type=Path, help="Append the saved teacher checklist")
    mode.add_argument("--adapter", type=Path, help="Load a trained adapter with --local-model")
    dataset = commands.add_parser("distill-data", help="Export teacher responses as supervised examples")
    dataset.add_argument("--plan", type=Path, required=True)
    dataset.add_argument("--teacher-run", type=Path, required=True)
    dataset.add_argument("--output", type=Path, required=True)
    review = dataset.add_mutually_exclusive_group(required=True)
    review.add_argument("--review", type=Path, help="JSON mapping unit IDs to approved finding indices")
    review.add_argument("--allow-unreviewed", action="store_true", help="Export provisional positive labels")
    train = commands.add_parser("distill-train", help="Train a local LoRA or QLoRA adapter")
    train.add_argument("--base-model", type=Path, required=True)
    train.add_argument("--dataset", type=Path, action="append", required=True)
    train.add_argument("--output", type=Path, required=True)
    train.add_argument("--epochs", type=int, default=1)
    train.add_argument("--max-length", type=int, default=8192)
    train.add_argument("--qlora", action="store_true")
    train.add_argument("--allow-unreviewed", action="store_true", help="Train on provisional labels for a pilot")
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
        elif args.command == "distill-data":
            manifest = prepare_distill(args.plan, args.teacher_run, args.output, args.review,
                                       allow_unreviewed=args.allow_unreviewed)
            print(json.dumps(manifest, indent=2))
        elif args.command == "distill-train":
            from .models.local import train_adapter
            manifest = train_adapter(args.base_model, args.dataset, args.output, epochs=args.epochs,
                                     max_length=args.max_length, qlora=args.qlora,
                                     allow_unreviewed=args.allow_unreviewed)
            print(json.dumps(manifest, indent=2))
        else:
            config = load_config(args.config)
            if args.command == "plan-scan":
                report = build_plan(config, args.ingest_dir, args.output)
                print(json.dumps({key: value for key, value in report.items()
                                  if key not in {"skipped", "decompilation"}}, indent=2))
            elif args.command == "scan":
                if args.max_requests is not None and args.max_requests <= 0:
                    raise ValueError("--max-requests must be positive")
                if args.delay_seconds < 0 or args.delay_seconds > 60:
                    raise ValueError("--delay-seconds must be between 0 and 60")
                if args.role != "student" and (args.lessons or args.local_model or args.adapter):
                    raise ValueError("--lessons, --local-model and --adapter require --role student")
                if args.adapter and not args.local_model:
                    raise ValueError("--adapter requires --local-model")
                appendix = ""
                if args.lessons:
                    appendix = lesson_appendix(LessonSet.model_validate_json(args.lessons.read_bytes()).lessons)
                client = None
                if args.local_model:
                    from .models.local import LocalStudentClient
                    settings = config.models.get("student")
                    model = ModelConfig(
                        model=args.local_model.resolve().name, base_url="https://localhost",
                        api_key_env="LOCAL_STUDENT_UNUSED", temperature=0, retries=0,
                        max_output_tokens=settings.max_output_tokens if settings else 1500,
                    )
                    config.models["student"] = model
                    client = LocalStudentClient(model, args.local_model.resolve(), args.adapter)
                report = run_scan(config, args.plan, args.output, args.role, args.resume,
                                  args.retry_failed, args.max_requests, args.delay_seconds, client=client,
                                  progress=lambda item: print(json.dumps(item), flush=True),
                                  system_appendix=appendix, model_identity=client.identity if client else None)
                print(json.dumps({key: report[key] for key in
                                  ("status", "planned_units", "completed_units", "accepted_unique_findings", "usage")}, indent=2))
                if report['status'] != 'completed':
                    parser.exit(1, "Scan incomplete; inspect summary.json and resume.\n")
            elif args.command == "validate-config":
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
