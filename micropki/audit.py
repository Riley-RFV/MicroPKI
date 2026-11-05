import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("pki_audit")

_LOCK = threading.Lock()
GENESIS = "0" * 64

def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _read_last_hash(chain_path: Path) -> str:
    if not chain_path.is_file():
        return GENESIS
    try:
        txt = chain_path.read_text().strip().splitlines()
    except Exception:
        return GENESIS
    if not txt:
        return GENESIS
    return txt[-1]

def _write_last_hash(chain_path: Path, h: str) -> None:
    chain_path.parent.mkdir(parents=True, exist_ok=True)
    with open(chain_path, "a", encoding="utf-8") as f:
        f.write(h + "\n")

class AuditLog:
    def __init__(self, log_path: Path, chain_path: Optional[Path] = None):
        self.log_path = Path(log_path)
        self.chain_path = Path(chain_path) if chain_path else self.log_path.parent / "chain.dat"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, record: dict) -> dict:
        with _LOCK:
            prev = _read_last_hash(self.chain_path)
            body = {
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                "level": record.get("level", "AUDIT"),
                "operation": record["operation"],
                "status": record.get("status", "success"),
                "message": record.get("message", ""),
                "metadata": record.get("metadata", {}),
                "integrity": {"prev_hash": prev},
            }
            body["integrity"]["hash"] = hashlib.sha256(_canonical(body)).hexdigest()
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")
            _write_last_hash(self.chain_path, body["integrity"]["hash"])
            return body

    def log(self, operation: str, *, status: str = "success",
            message: str = "", level: str = "AUDIT", **metadata) -> dict:
        sens = ("passphrase", "password", "secret", "key_data",
                "private_key", "token")
        clean = {k: v for k, v in metadata.items()
                 if not any(s in k.lower() for s in sens)}
        return self._append({
            "level": level, "operation": operation, "status": status,
            "message": message, "metadata": clean,
        })

def verify_audit(log_path: Path, chain_path: Optional[Path] = None) -> dict:
    log_path = Path(log_path)
    chain_path = Path(chain_path) if chain_path else log_path.parent / "chain.dat"

    if not log_path.is_file():
        return {"ok": False, "error": f"audit log not found: {log_path}",
                "records": 0}

    prev_expected = GENESIS
    records = 0
    bad_at = None
    reason = None
    with open(log_path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            records += 1
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                return {"ok": False, "error": f"line {lineno}: invalid JSON: {e}",
                        "records": records, "bad_line": lineno}
            integ = obj.get("integrity", {})
            prev = integ.get("prev_hash")
            claimed = integ.get("hash")
            if prev != prev_expected:
                bad_at, reason = lineno, f"prev_hash mismatch (expected {prev_expected[:8]}..., got {str(prev)[:8]}...)"
                break
            body = dict(obj)
            integ_copy = dict(body.get("integrity", {}))
            integ_copy.pop("hash", None)
            body["integrity"] = integ_copy
            recomputed = hashlib.sha256(_canonical(body)).hexdigest()
            if recomputed != claimed:
                bad_at, reason = lineno, "hash mismatch (record tampered)"
                break
            prev_expected = claimed

    if bad_at is not None:
        return {"ok": False, "error": f"line {bad_at}: {reason}",
                "records": records, "bad_line": bad_at}

    if chain_path.is_file():
        saved = _read_last_hash(chain_path)
        if saved != prev_expected:
            return {"ok": False,
                    "error": f"chain.dat mismatch (saved {saved[:8]}..., computed {prev_expected[:8]}...)",
                    "records": records}

    return {"ok": True, "records": records, "last_hash": prev_expected}

def query_audit(log_path: Path, *, from_ts: Optional[str] = None,
                to_ts: Optional[str] = None, level: Optional[str] = None,
                operation: Optional[str] = None,
                serial: Optional[str] = None,
                verify: bool = False) -> list[dict]:
    log_path = Path(log_path)
    if not log_path.is_file():
        return []
    out = []
    prev_expected = GENESIS
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            integ = obj.get("integrity", {})
            if verify:
                body = dict(obj)
                integ_copy = dict(body.get("integrity", {}))
                integ_copy.pop("hash", None)
                body["integrity"] = integ_copy
                recomputed = hashlib.sha256(_canonical(body)).hexdigest()
                if integ.get("prev_hash") != prev_expected or recomputed != integ.get("hash"):
                    obj["_integrity_ok"] = False
                else:
                    obj["_integrity_ok"] = True
                prev_expected = integ.get("hash")

            ts = obj.get("timestamp", "")
            if from_ts and ts < from_ts:
                continue
            if to_ts and ts > to_ts:
                continue
            if level and obj.get("level") != level:
                continue
            if operation and operation not in obj.get("operation", ""):
                continue
            if serial:
                meta = obj.get("metadata", {})
                if str(meta.get("serial", "")).lower() != serial.lower():
                    continue
            out.append(obj)
    return out
