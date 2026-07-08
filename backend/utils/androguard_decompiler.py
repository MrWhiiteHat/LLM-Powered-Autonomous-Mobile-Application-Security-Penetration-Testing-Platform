"""
Androguard Decompiler Integration
Pure-Python APK -> Java source decompilation using androguard's DAD decompiler.
Requires no external binaries (unlike jadx), so it works anywhere the Python
dependency is installed. Writes .java files into a cache directory that mirrors
the layout produced by JadxDecompiler, so downstream consumers (StaticAnalyzer,
ASTAnalyzer) require no changes.
"""
import hashlib
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger("AndroguardDecompiler")

try:
    from androguard.misc import AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except Exception as _e:  # ImportError or transitive dependency failure
    ANDROGUARD_AVAILABLE = False
    logger.warning(f"androguard not available: {_e}. Pure-Python decompilation disabled.")

# Framework/runtime class prefixes that produce no useful app-level signal and
# would bloat the corpus. We skip these when writing source files.
_SKIP_PREFIXES = (
    "Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/", "Ljava/", "Ljavax/",
    "Ljunit/", "Lorg/junit/", "Ldalvik/", "Lcom/google/android/gms/",
)


class AndroguardDecompiler:
    """Decompiles APKs to Java source using androguard's DAD decompiler."""

    def __init__(self):
        self.available = ANDROGUARD_AVAILABLE
        self.cache_dir = Path(tempfile.gettempdir()) / "msa_decompiled_ag"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _class_to_relpath(self, class_name: str) -> str:
        """Convert an androguard class descriptor 'Lde/ecspride/Foo;' -> 'de/ecspride/Foo.java'."""
        name = class_name
        if name.startswith("L"):
            name = name[1:]
        if name.endswith(";"):
            name = name[:-1]
        # Nested/inner classes ($) map to the outer file name to avoid odd paths;
        # keep them separate is also fine, but a single file per top-level class
        # keeps output closer to jadx.
        name = name.replace("$", "__")
        return name + ".java"

    def decompile(self, apk_path: Path) -> Optional[Path]:
        """Decompile an APK to Java source files.

        Returns the output directory containing decompiled .java files, or None
        if androguard is unavailable or decompilation produced nothing.
        Uses SHA-256 (first 64KB) hash-based caching to avoid re-decompilation.
        """
        if not self.available:
            return None

        try:
            apk_hash = hashlib.sha256(apk_path.read_bytes()[:65536]).hexdigest()[:16]
            output_dir = self.cache_dir / f"{apk_path.stem}_{apk_hash}"

            if output_dir.exists() and any(output_dir.rglob("*.java")):
                logger.info(f"Using cached androguard decompilation: {output_dir}")
                return output_dir

            output_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Decompiling {apk_path.name} with androguard (DAD)...")

            _, _, dx = AnalyzeAPK(str(apk_path))

            written = 0
            for class_analysis in dx.get_classes():
                cname = class_analysis.name
                if any(cname.startswith(p) for p in _SKIP_PREFIXES):
                    continue
                try:
                    vm_class = class_analysis.get_vm_class()
                    if vm_class is None:
                        continue
                    source = vm_class.get_source()
                except Exception:
                    source = None
                if not source or not source.strip():
                    continue
                try:
                    rel = self._class_to_relpath(cname)
                    target = output_dir / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(source, encoding="utf-8", errors="ignore")
                    written += 1
                except Exception:
                    continue

            if written:
                logger.info(f"androguard decompilation complete: {written} Java source files")
                return output_dir

            logger.warning("androguard produced no Java source files")
            return None

        except Exception as e:
            logger.error(f"androguard decompilation error: {e}")
            return None

    def cleanup(self, output_dir: Path):
        """Remove a decompiled output directory (only within our cache)."""
        try:
            if output_dir and output_dir.exists() and output_dir.is_relative_to(self.cache_dir):
                shutil.rmtree(output_dir, ignore_errors=True)
        except Exception:
            pass
