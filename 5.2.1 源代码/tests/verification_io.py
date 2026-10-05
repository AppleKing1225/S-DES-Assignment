"""Write new verification records without replacing historical evidence."""
import argparse
import json
import platform
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def output_path(prefix: str) -> Path:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New JSON path; existing files are refused.")
    args = parser.parse_args()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    destination = args.output or PROJECT_ROOT / "verification" / "runs" / f"{prefix}_{timestamp}.json"
    if destination.exists():
        parser.error(f"Output already exists; choose another path: {destination}")
    return destination


def save_record(destination: Path, results: dict) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "recorded_at": datetime.now().astimezone().isoformat(),
        "python": platform.python_version(), "platform": platform.platform(), **results,
    }
    # Exclusive creation protects against races and preserves previous evidence.
    with destination.open("x", encoding="utf-8") as output:
        json.dump(record, output, ensure_ascii=False, indent=2)
    print("Results:", destination.resolve())


def require(condition: bool, message: str) -> None:
    """Keep checks active even when Python is launched with -O."""
    if not condition:
        raise AssertionError(message)
