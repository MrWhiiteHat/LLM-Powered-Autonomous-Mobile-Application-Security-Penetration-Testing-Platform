"""
Logging utility for Mobile Security Agent
"""
import logging
import sys
from pathlib import Path
from datetime import datetime

from config import LOG_DIR


def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
    """Create a configured logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    # Ensure stdout/stderr safely handle UTF-8 / non-ASCII on Windows
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    # Console handler with color formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_fmt = logging.Formatter(
        "\033[36m[%(asctime)s]\033[0m \033[33m%(name)s\033[0m - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
    )
    console_handler.setFormatter(console_fmt)

    # File handler
    log_file = LOG_DIR / f"msa_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "[%(asctime)s] %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_fmt)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
