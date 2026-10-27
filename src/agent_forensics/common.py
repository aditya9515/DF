from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import rfc8785

ROOT = Path(__file__).resolve().parents[2]


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def canonical(value):
    return rfc8785.dumps(value)


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_jsonl(path):
    return [json.loads(s) for s in Path(path).read_text(encoding="utf-8").splitlines() if s.strip()]


def append_jsonl(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as out:
        out.write(json.dumps(value, ensure_ascii=False) + "\n")


def file_hash(path):
    with open(path, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()
