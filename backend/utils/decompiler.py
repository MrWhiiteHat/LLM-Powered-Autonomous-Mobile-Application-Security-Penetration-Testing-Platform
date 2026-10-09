"""
Jadx Decompiler Integration
Decompiles APK files to clean Java/Kotlin source using jadx CLI.
Gracefully falls back when jadx is not installed.
"""
import os
import shutil
import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger("Decompiler")


class JadxDecompiler:
    """Wrapper for jadx CLI decompiler."""
    
    def __init__(self):
        self.jadx_path = self._find_jadx()
        self.cache_dir = Path(tempfile.gettempdir()) / "msa_decompiled"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.available = self.jadx_path is not None
    
    def _find_jadx(self) -> Optional[str]:
        """Find jadx binary on system PATH."""
        # Try shutil.which first
        jadx = shutil.which("jadx")
        if jadx:
            return jadx
        # Try common locations on Windows
        common_paths = [
            Path.home() / "jadx" / "bin" / "jadx.bat",
            Path("C:/jadx/bin/jadx.bat"),
            Path(os.environ.get("JADX_HOME", "")) / "bin" / "jadx.bat" if os.environ.get("JADX_HOME") else None,
        ]
        for p in common_paths:
            if p and p.exists():
                return str(p)
        logger.warning("jadx not found on PATH. Decompilation disabled. Install jadx and add to PATH to enable AST analysis.")
        return None
    
    def decompile(self, apk_path: Path) -> Optional[Path]:
        """Decompile APK to Java source files.
        
        Returns the output directory containing decompiled .java files,
        or None if decompilation fails or jadx is unavailable.
        Uses SHA-256 hash-based caching to avoid re-decompilation.
        """
        if not self.available:
            return None
        
        try:
            # Hash-based cache key
            apk_hash = hashlib.sha256(apk_path.read_bytes()[:65536]).hexdigest()[:16]
            output_dir = self.cache_dir / f"{apk_path.stem}_{apk_hash}"
            
            # Check cache
            if output_dir.exists() and any(output_dir.rglob("*.java")):
                logger.info(f"Using cached decompilation: {output_dir}")
                return output_dir
            
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Decompiling {apk_path.name} with jadx...")
            cmd = [
                self.jadx_path,
                "--no-res",           # Skip resources (faster)
                "--no-debug-info",    # Skip debug info
                "--threads-count", "4",
                "--output-dir", str(output_dir),
                str(apk_path)
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            
            if result.returncode != 0:
                logger.warning(f"jadx exited with code {result.returncode}: {result.stderr[:500]}")
            
            java_files = list(output_dir.rglob("*.java"))
            if java_files:
                logger.info(f"Decompilation complete: {len(java_files)} Java source files")
                return output_dir
            else:
                logger.warning("jadx produced no Java files")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("jadx decompilation timed out (300s limit)")
            return None
        except Exception as e:
            logger.error(f"Decompilation error: {e}")
            return None
    
    def get_source_files(self, output_dir: Path) -> list:
        """Walk decompiled source tree and return list of {file, content} dicts."""
        sources = []
        try:
            for java_file in output_dir.rglob("*.java"):
                try:
                    content = java_file.read_text(encoding="utf-8", errors="ignore")
                    rel_path = str(java_file.relative_to(output_dir))
                    sources.append({"file": rel_path, "content": content})
                except Exception:
                    pass
            for kt_file in output_dir.rglob("*.kt"):
                try:
                    content = kt_file.read_text(encoding="utf-8", errors="ignore")
                    rel_path = str(kt_file.relative_to(output_dir))
                    sources.append({"file": rel_path, "content": content})
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Error reading source files: {e}")
        return sources
    
    def cleanup(self, output_dir: Path):
        """Remove decompiled output directory."""
        try:
            if output_dir and output_dir.exists() and output_dir.is_relative_to(self.cache_dir):
                shutil.rmtree(output_dir, ignore_errors=True)
        except Exception:
            pass
