"""Evidence storage and independent verification. Verification never trusts SQLite."""

import base64
import json
import shutil
import sqlite3
import re
from pathlib import Path
import zipfile
from contextlib import closing
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .common import ROOT, append_jsonl, canonical, file_hash, read_jsonl, save_json, sha, utc

ZERO = "0" * 64


def keys(root=ROOT):
    private = Path(root) / ".private/signing.pem"
    public = Path(root) / "results/public_key.pem"
    private.parent.mkdir(parents=True, exist_ok=True)
    public.parent.mkdir(parents=True, exist_ok=True)
    if private.exists():
        key = serialization.load_pem_private_key(private.read_bytes(), password=None)
    else:
        if public.exists():
            raise ValueError("Public key exists without private key; use a separate workspace for fresh inference.")
        key = Ed25519PrivateKey.generate()
        private.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if public.exists() and public.read_bytes() != pem:
        raise ValueError("Signing key does not match trusted public key")
    public.write_bytes(pem)
    return key, pem


def signed(payload, key):
    return {"payload": payload, "signature": base64.b64encode(key.sign(canonical(payload))).decode("ascii")}


def validate_signature(record, public):
    public.verify(base64.b64decode(record["signature"], validate=True), canonical(record["payload"]))


def custody(action, artifact, root=ROOT):
    root = Path(root)
    if (root / "results/public_key.pem").exists() and not (root / ".private/signing.pem").exists():
        # A recipient must not impersonate the original collector after delivery.
        # Keep the submitted custody chain intact and use a separate operator key.
        return custody(action, artifact, root / "output/operator_audit")
    key, pem = keys(root)
    path = Path(root) / "results/custody.jsonl"
    previous = read_jsonl(path)[-1] if path.exists() and path.stat().st_size else None
    entry = {
        "schema_version": 1,
        "timestamp": utc(),
        "actor": "local-operator",
        "action": action,
        "artifact": str(artifact),
        "previous": sha(previous) if previous else ZERO,
    }
    if Path(artifact).is_file():
        entry["artifact_sha256"] = file_hash(artifact)
    append_jsonl(path, signed(entry, key))


class Recorder:
    def __init__(self, session_id, config, root=ROOT, enabled=True):
        if not isinstance(session_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}", session_id):
            raise ValueError("Session ID must be a bounded filesystem-safe identifier")
        self.root = Path(root)
        self.session_id = session_id
        self.enabled = enabled
        self.events = []
        self.previous = ZERO
        self.key, self.pem = keys(self.root)
        self.directory = self.root / "results/evidence" / session_id
        if enabled:
            if self.directory.exists():
                raise FileExistsError(f"Refusing to overwrite evidence: {self.directory}")
            self.directory.mkdir(parents=True)
            (self.directory / "public_key.pem").write_bytes(self.pem)
        self.emit("session_start", "runner", config)

    def emit(self, event_type, actor, payload, parents=None):
        if not self.enabled:
            return None
        seq = len(self.events) + 1
        event = {
            "schema_version": 1,
            "event_id": f"{self.session_id}:{seq:06d}",
            "session_id": self.session_id,
            "sequence": seq,
            "timestamp": utc(),
            "type": event_type,
            "actor": actor,
            "payload": json.loads(json.dumps(payload)),
            "parent_ids": parents or [],
            "previous_hash": self.previous,
        }
        event["hash"] = sha(event)
        self.previous = event["hash"]
        self.events.append(event)
        append_jsonl(self.directory / "events.jsonl", event)
        if seq % 10 == 0:
            self.checkpoint()
        return event["event_id"]

    def checkpoint(self):
        payload = {
            "schema_version": 1,
            "session_id": self.session_id,
            "event_count": len(self.events),
            "head_hash": self.previous,
            "timestamp": utc(),
        }
        append_jsonl(self.directory / "checkpoints.jsonl", signed(payload, self.key))

    def finish(self, status, outcome):
        if not self.enabled:
            return
        self.emit("session_end", "runner", {"status": status, **outcome})
        self.checkpoint()
        manifest = signed(
            {
                "schema_version": 1,
                "session_id": self.session_id,
                "event_count": len(self.events),
                "head_hash": self.previous,
                "status": status,
                "timestamp": utc(),
                "public_key_sha256": __import__("hashlib").sha256(self.pem).hexdigest(),
            },
            self.key,
        )
        save_json(self.directory / "manifest.json", manifest)
        db_path = self.root / "results/catalog.sqlite"
        with closing(sqlite3.connect(db_path)) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, status TEXT, event_count INTEGER, directory TEXT)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, session_id TEXT, sequence INTEGER, kind TEXT, json TEXT)"
            )
            db.execute(
                "CREATE TRIGGER IF NOT EXISTS no_event_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'events are append only'); END"
            )
            db.execute(
                "CREATE TRIGGER IF NOT EXISTS no_event_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'events are append only'); END"
            )
            db.execute(
                "INSERT INTO sessions VALUES (?,?,?,?)",
                (self.session_id, status, len(self.events), str(self.directory.relative_to(self.root))),
            )
            db.executemany(
                "INSERT INTO events VALUES (?,?,?,?,?)",
                [(e["event_id"], self.session_id, e["sequence"], e["type"], json.dumps(e)) for e in self.events],
            )
        custody("collection_finalized", self.directory / "manifest.json", self.root)


def verify(path, trusted_public_key):
    """Read directory or flat ZIP; caller must supply an independently trusted key."""
    path = Path(path)
    result = {"valid": False, "complete": False, "first_failure": None, "errors": [], "event_count": 0}
    try:
        if path.is_file():
            with zipfile.ZipFile(path) as archive:
                if len(archive.namelist()) != len(set(archive.namelist())):
                    raise ValueError("Duplicate ZIP entry")
                content = {
                    n: archive.read(n).decode("utf-8")
                    for n in ("events.jsonl", "checkpoints.jsonl", "manifest.json", "public_key.pem")
                }
        else:
            content = {
                n: (path / n).read_text(encoding="utf-8")
                for n in ("events.jsonl", "checkpoints.jsonl", "manifest.json", "public_key.pem")
            }
        pem = Path(trusted_public_key).read_bytes()
        if content["public_key.pem"].encode() != pem:
            raise ValueError("Embedded key differs from trusted key")
        public = serialization.load_pem_public_key(pem)
        if not isinstance(public, Ed25519PublicKey):
            raise ValueError("Trusted key must be Ed25519")
        manifest = json.loads(content["manifest.json"])
        validate_signature(manifest, public)
        m = manifest["payload"]
        if m["schema_version"] != 1:
            raise ValueError("Unsupported manifest schema")
        if m["public_key_sha256"] != __import__("hashlib").sha256(pem).hexdigest():
            raise ValueError("Key fingerprint mismatch")
        events = [json.loads(line) for line in content["events.jsonl"].splitlines() if line.strip()]
        result["event_count"] = len(events)
        previous = ZERO
        known = set()
        for seq, event in enumerate(events, 1):
            result["first_failure"] = seq
            if event["sequence"] != seq or event["event_id"] != f"{m['session_id']}:{seq:06d}":
                raise ValueError("Sequence or event ID mismatch")
            if event["session_id"] != m["session_id"] or event["schema_version"] != 1:
                raise ValueError("Session or schema mismatch")
            if event["previous_hash"] != previous:
                raise ValueError("Previous hash mismatch")
            if not set(event["parent_ids"]).issubset(known):
                raise ValueError("Invalid causal parent")
            if sha({k: v for k, v in event.items() if k != "hash"}) != event["hash"]:
                raise ValueError("Event hash mismatch")
            previous = event["hash"]
            known.add(event["event_id"])
        result["first_failure"] = None
        if not events or events[0]["type"] != "session_start" or events[-1]["type"] != "session_end":
            raise ValueError("Session boundary missing")
        if len(events) != m["event_count"] or previous != m["head_hash"]:
            raise ValueError("Signed manifest count or head mismatch")
        checkpoints = [json.loads(line) for line in content["checkpoints.jsonl"].splitlines() if line.strip()]
        counts = []
        for cp in checkpoints:
            validate_signature(cp, public)
            p = cp["payload"]
            n = p["event_count"]
            if (
                p["session_id"] != m["session_id"]
                or not 1 <= n <= len(events)
                or events[n - 1]["hash"] != p["head_hash"]
            ):
                raise ValueError("Checkpoint mismatch")
            counts.append(n)
        if counts != list(range(10, len(events) + 1, 10)) + [len(events)]:
            raise ValueError("Missing, repeated or reordered checkpoints")
        if m["status"] not in ("completed", "failed"):
            raise ValueError("Unknown final status")
        if events[-1]["payload"]["status"] != m["status"]:
            raise ValueError("Final status mismatch")
        result.update(valid=True, complete=m["status"] == "completed", status=m["status"], session_id=m["session_id"])
    except Exception as exc:
        result["errors"].append(f"{type(exc).__name__}: {exc}")
    return result


def export_bundle(directory, destination, root=ROOT):
    directory = Path(directory)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in ("events.jsonl", "checkpoints.jsonl", "manifest.json", "public_key.pem"):
            archive.write(directory / name, name)
        custody_path = Path(root) / "results/custody.jsonl"
        if custody_path.exists():
            archive.write(custody_path, "custody_snapshot.jsonl")
    custody("evidence_exported", destination, root)
    return destination


def archive_interrupted(directory, root=ROOT):
    root = Path(root).resolve()
    directory = Path(directory).resolve()
    if not directory.is_relative_to(root / "results/evidence"):
        raise ValueError("Interrupted evidence must be inside the workspace evidence directory")
    destination = Path(root) / "results/interrupted" / (Path(directory).name + "-" + utc().replace(":", ""))
    if not destination.resolve().is_relative_to(root / "results/interrupted"):
        raise ValueError("Unsafe interruption archive destination")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(directory), destination)
    # The database is a rebuildable index, not the evidence authority. Preserve an
    # existing index before resuming an interruption after finalization.
    db = Path(root) / "results/catalog.sqlite"
    if db.exists():
        with closing(sqlite3.connect(db)) as connection:
            present = connection.execute("SELECT 1 FROM sessions WHERE id=?", (Path(directory).name,)).fetchone()
        if present:
            shutil.move(str(db), destination / "previous_catalog.sqlite")
            rebuild_catalog(root)


def rebuild_catalog(root=ROOT):
    root = Path(root)
    with closing(sqlite3.connect(root / "results/catalog.sqlite")) as db, db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, status TEXT, event_count INTEGER, directory TEXT)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, session_id TEXT, sequence INTEGER, kind TEXT, json TEXT)"
        )
        for folder in (root / "results/evidence").glob("*"):
            if not (folder / "manifest.json").exists():
                continue
            m = json.loads((folder / "manifest.json").read_text())["payload"]
            db.execute(
                "INSERT INTO sessions VALUES (?,?,?,?)",
                (folder.name, m["status"], m["event_count"], str(folder.relative_to(root))),
            )
            events = read_jsonl(folder / "events.jsonl")
            db.executemany(
                "INSERT INTO events VALUES (?,?,?,?,?)",
                [(e["event_id"], folder.name, e["sequence"], e["type"], json.dumps(e)) for e in events],
            )


def verify_custody(path, trusted_public_key):
    errors = []
    count = 0
    previous = ZERO
    try:
        public = serialization.load_pem_public_key(Path(trusted_public_key).read_bytes())
        for record in read_jsonl(path):
            validate_signature(record, public)
            if record["payload"]["previous"] != previous:
                raise ValueError("Custody chain mismatch")
            previous = sha(record)
            count += 1
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    return {"valid": not errors and count > 0, "records": count, "errors": errors}
