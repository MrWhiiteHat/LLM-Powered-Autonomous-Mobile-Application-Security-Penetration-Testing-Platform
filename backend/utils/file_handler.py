"""
File handler utility for APK/IPA uploads
"""
import os
import shutil
import zipfile
import hashlib
from pathlib import Path
from typing import Optional

from config import UPLOAD_DIR, ALLOWED_EXTENSIONS, MAX_UPLOAD_SIZE_MB
from utils.logger import get_logger

logger = get_logger("FileHandler")


class FileHandler:
    """Handles APK/IPA file operations."""

    @staticmethod
    def validate_file(filename: str, file_size: int) -> tuple[bool, str]:
        """Validate uploaded file."""
        ext = Path(filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            return False, f"Invalid file type: {ext}. Allowed: {ALLOWED_EXTENSIONS}"

        max_bytes = MAX_UPLOAD_SIZE_MB * 1024 * 1024
        if file_size > max_bytes:
            return False, f"File too large: {file_size} bytes. Max: {MAX_UPLOAD_SIZE_MB}MB"

        return True, "Valid"

    @staticmethod
    def save_upload(filename: str, content: bytes) -> Path:
        """Save uploaded file and return path."""
        safe_name = "".join(c for c in filename if c.isalnum() or c in "._-")
        upload_path = UPLOAD_DIR / safe_name
        upload_path.write_bytes(content)
        logger.info(f"Saved upload: {upload_path} ({len(content)} bytes)")
        return upload_path

    @staticmethod
    def compute_hashes(file_path: Path) -> dict:
        """Compute file hashes for integrity."""
        data = file_path.read_bytes()
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "file_size": len(data),
        }

    @staticmethod
    def extract_apk(apk_path: Path) -> Optional[Path]:
        """Extract APK contents."""
        extract_dir = apk_path.parent / apk_path.stem
        try:
            with zipfile.ZipFile(str(apk_path), "r") as zf:
                zf.extractall(str(extract_dir))
            logger.info(f"Extracted APK to: {extract_dir}")
            return extract_dir
        except Exception as e:
            logger.error(f"Failed to extract APK: {e}")
            return None

    @staticmethod
    def cleanup(path: Path):
        """Remove file or directory."""
        if path.is_dir():
            shutil.rmtree(str(path), ignore_errors=True)
        elif path.is_file():
            path.unlink(missing_ok=True)
        logger.info(f"Cleaned up: {path}")

    @staticmethod
    def get_file_type(file_path: Path) -> str:
        """Determine platform from file extension."""
        ext = file_path.suffix.lower()
        if ext == ".apk":
            return "android"
        elif ext == ".ipa":
            return "ios"
        elif ext == ".xapk":
            return "android"
        return "unknown"
