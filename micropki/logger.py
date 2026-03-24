import logging
import json
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

class CustomFormater(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "function": record.funcName,
            "message": record.getMessage()}

        if hasattr(record, 'extra_data'):
            log_entry.update(record.extra_data)
        
        return json.dumps(log_entry)

def setup_logger(log_path: str = "audit.log", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("pki_audit")
    logger.setLevel(level)
    
    if logger.handlers:
        return logger

    log_file = Path(log_path)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    handler = RotatingFileHandler(
        log_file, 
        maxBytes=10*1024*1024, 
        backupCount=5,
        encoding='utf-8'
    )
    handler.setLevel(level)
    handler.setFormatter(CustomFormater())
    
    logger.addHandler(handler)
    
    cmd_handler = logging.StreamHandler(sys.stderr)
    cmd_handler.setLevel(logging.ERROR)
    cmd_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(cmd_handler)

    return logger

def log_event(logger: logging.Logger, level: int, message: str, **kwargs):
    sens_data = ['passphrase', 'password', 'key_data', 'private_key']
    clean_kwargs = {k: v for k, v in kwargs.items() if k.lower() not in sens_data}
    
    record = logger.makeRecord(
        logger.name, level, "", 0, message, (), None, func="", extra={"extra_data": clean_kwargs}
    )
    logger.handle(record)
