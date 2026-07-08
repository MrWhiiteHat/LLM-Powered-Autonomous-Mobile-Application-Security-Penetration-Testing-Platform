"""
Unified decompiler selection.

Provides a single entry point used by both the API orchestrator (main.py) and
the evaluation harness, so the decompilation strategy is defined in exactly one
place. Preference order (highest fidelity first):

    1. jadx        - best fidelity, requires the jadx binary on PATH
    2. androguard  - pure-Python fallback, no external binary required
    3. (none)      - callers fall back to raw string extraction

Set the environment variable ``MSA_DISABLE_ANDROGUARD=1`` to force the
androguard tier off (used to capture a "before" baseline for benchmarking).
"""
import os
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger("Decompile")


def decompile_apk(file_path: Path, platform: str = "android") -> tuple[Optional[Path], str]:
    """Decompile an APK using the best available engine.

    Returns a tuple of (decompiled_dir, engine_name). ``decompiled_dir`` is None
    when no engine succeeded (callers then fall back to raw strings), and
    ``engine_name`` is one of "jadx", "androguard", or "none".
    """
    if platform != "android":
        return None, "none"

    # Tier 1: jadx (external binary, highest fidelity)
    try:
        from utils.decompiler import JadxDecompiler
        jadx = JadxDecompiler()
        if jadx.available:
            out = jadx.decompile(file_path)
            if out:
                return out, "jadx"
            logger.info("jadx available but produced no output; trying androguard")
    except Exception as e:
        logger.warning(f"jadx tier failed: {e}")

    # Tier 2: androguard (pure-Python fallback)
    if os.getenv("MSA_DISABLE_ANDROGUARD", "").strip() not in ("1", "true", "yes"):
        try:
            from utils.androguard_decompiler import AndroguardDecompiler
            ag = AndroguardDecompiler()
            if ag.available:
                out = ag.decompile(file_path)
                if out:
                    return out, "androguard"
                logger.info("androguard available but produced no output")
        except Exception as e:
            logger.warning(f"androguard tier failed: {e}")
    else:
        logger.info("androguard tier disabled via MSA_DISABLE_ANDROGUARD")

    # Tier 3: nothing — caller uses raw string extraction
    return None, "none"
