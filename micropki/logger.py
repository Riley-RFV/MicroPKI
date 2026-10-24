import logging
import json
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

class CustomFormater(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "module": record.module,
            "function": record.funcName,
            "message": record.getMessage()}

        if hasattr(record, 'extra_data'):
            log_entry.update(record.extra_data)
        
        return json.dumps(log_entry)

def setup_logger(log_path: str | None = None, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("pki_audit")
    logger.setLevel(level)
    
    if getattr(logger, "_configured_path", object()) == log_path and logger.handlers:
        return logger
    for h in list(logger.handlers):
        logger.removeHandler(h)
    logger._configured_path = log_path

    formatter = CustomFormater()

    if log_path:
        log_file = Path(log_path).expanduser()
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    else:
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(level)
        stderr_handler.setFormatter(formatter)
        logger.addHandler(stderr_handler)

    return logger

def log_event(logger: logging.Logger, level: int, message: str, **kwargs):
    sens_data = ['passphrase', 'password', 'key_data', 'private_key', 'secret', 'token']
    clean_kwargs = {k: v for k, v in kwargs.items() if not any(marker in k.lower() for marker in sens_data)}
    
    record = logger.makeRecord(
        logger.name, level, "", 0, message, (), None, func="", extra={"extra_data": clean_kwargs}
    )
    logger.handle(record)
