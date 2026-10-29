import secrets
import time

from .logger import log_event
import logging

logger = logging.getLogger("pki_audit")


def _candidate() -> int:
    ts = int(time.time()) & 0xFFFFFFFF
    rnd = secrets.randbits(32)
    return (ts << 32) | rnd


def generate_serial(conn=None, max_retries: int = 10) -> int:
    for attempt in range(max_retries):
        value = _candidate()
        if value <= 0:
            continue
        if conn is None:
            return value
        from .database import serial_exists
        if not serial_exists(conn, value):
            return value
        log_event(logger, logging.WARNING, "Serial collision, retrying",
                  attempt=attempt + 1)
    raise RuntimeError(f"Failed to generate a unique serial after {max_retries} retries")


def to_hex(value: int) -> str:
    return format(value, "x")


def from_hex(s: str) -> int:
    return int(s.lower().removeprefix("0x"), 16)
