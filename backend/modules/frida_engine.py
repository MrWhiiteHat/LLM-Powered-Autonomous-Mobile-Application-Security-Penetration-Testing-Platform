"""
Frida Dynamic Instrumentation Engine
Deploys APKs to a connected Android device, attaches via Frida USB transport,
and injects runtime hooks to capture cryptographic operations, SSL bypasses,
SQL queries, WebView loads, SharedPreferences writes, file access, and log leaks.
Gracefully falls back when frida or adb is not available.
"""
import subprocess
import time
import json
import threading
import os
import re
import struct
import zipfile
from shutil import which
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger("FridaEngine")

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    logger.warning("frida not installed. Dynamic instrumentation disabled. Install with: pip install frida-tools")


# ---------------------------------------------------------------------------
# Embedded Frida hook scripts
# ---------------------------------------------------------------------------

_HOOK_CIPHER = """
(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
        var algo = this.getAlgorithm();
        var keyBytes = key.getEncoded();
        var keyHex = '';
        for (var i = 0; i < keyBytes.length; i++) {
            var b = (keyBytes[i] & 0xff).toString(16);
            keyHex += ('0' + b).slice(-2);
        }
        send({type: 'cipher_init', data: {algorithm: algo, opmode: opmode, key_hex: keyHex}});
        return this.init(opmode, key);
    };
})();
"""

_HOOK_SSL_VERIFIER = """
(function() {
    var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
    HttpsURLConnection.setHostnameVerifier.implementation = function(verifier) {
        send({type: 'ssl_bypass', data: {verifier_class: verifier.$className, message: 'Custom HostnameVerifier set — potential SSL bypass'}});
        return this.setHostnameVerifier(verifier);
    };
})();
"""

_HOOK_SQL_QUERY = """
(function() {
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {
        var argsStr = args ? Java.use('java.util.Arrays').toString(args) : 'null';
        send({type: 'sql_query', data: {query: sql, args: argsStr}});
        return this.rawQuery(sql, args);
    };
})();
"""

_HOOK_WEBVIEW = """
(function() {
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        send({type: 'webview_load', data: {url: url}});
        return this.loadUrl(url);
    };
})();
"""

_HOOK_SHARED_PREFS = """
(function() {
    var Editor = Java.use('android.content.SharedPreferences$Editor');
    Editor.putString.implementation = function(key, value) {
        send({type: 'shared_prefs_write', data: {key: key, value: value}});
        return this.putString(key, value);
    };
})();
"""

_HOOK_FILE_ACCESS = """
(function() {
    var File = Java.use('java.io.File');
    File.$init.overload('java.lang.String').implementation = function(path) {
        if (path && (path.indexOf('/sdcard') !== -1 || path.indexOf('/storage/emulated') !== -1 || path.indexOf('external') !== -1)) {
            send({type: 'file_access', data: {path: path}});
        }
        return this.$init(path);
    };
})();
"""

_HOOK_LOG_SECRETS = """
(function() {
    var sensitivePattern = /(password|secret|token|key|credential|session|auth|bearer|api_key)/i;
    var Log = Java.use('android.util.Log');
    ['d', 'e', 'i', 'w', 'v'].forEach(function(level) {
        Log[level].overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
            if (sensitivePattern.test(tag) || sensitivePattern.test(msg)) {
                send({type: 'log_secret', data: {level: level, tag: tag, message: msg}});
            }
            return this[level](tag, msg);
        };
    });
})();
"""

# Ordered list so we can iterate and report hook names
_ALL_HOOKS = [
    ("cipher_init", _HOOK_CIPHER),
    ("ssl_bypass", _HOOK_SSL_VERIFIER),
    ("sql_query", _HOOK_SQL_QUERY),
    ("webview_load", _HOOK_WEBVIEW),
    ("shared_prefs_write", _HOOK_SHARED_PREFS),
    ("file_access", _HOOK_FILE_ACCESS),
    ("log_secret", _HOOK_LOG_SECRETS),
]


class FridaInstrumenter:
    """Deploy, attach, hook, and collect runtime security findings via Frida."""

    def __init__(self, apk_path: Path, package_name: str):
        self.apk_path = apk_path
        self.package_name = package_name
        # Never uninstall an app which was already present on the test device.
        # This is especially important when an install attempt fails: the old
        # implementation always called ``adb uninstall`` from ``finally``.
        self._package_was_present = False
        self._installed_by_session = False
        self.findings = []
        self.hooks_log = []
        self.runtime_data = {
            "crypto_ops": [],
            "ssl_events": [],
            "sql_queries": [],
            "webview_urls": [],
            "prefs_writes": [],
            "file_accesses": [],
            "log_leaks": [],
        }

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def _get_adb_path(self) -> str:
        """Resolve the path to the adb executable, checking common paths first."""
        path_adb = which("adb")
        if path_adb:
            return path_adb
        
        import os
        user_profile = os.environ.get("USERPROFILE", "C:\\Users\\MrWhiteHat")
        common_path = os.path.join(user_profile, "AppData", "Local", "Android", "Sdk", "platform-tools", "adb.exe")
        if os.path.exists(common_path):
            return common_path
            
        return "adb"

    def _get_aapt_path(self) -> Optional[str]:
        """Locate aapt when Android build-tools are available."""
        path_aapt = which("aapt") or which("aapt.exe")
        if path_aapt:
            return path_aapt
        sdk_root = os.environ.get("ANDROID_HOME") or os.path.join(
            os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"
        )
        build_tools = Path(sdk_root) / "build-tools"
        if build_tools.is_dir():
            candidates = sorted(build_tools.glob("*/aapt.exe"), reverse=True)
            if candidates:
                return str(candidates[0])
        return None

    def _get_apksigner_path(self) -> Optional[str]:
        """Locate apksigner when Android build-tools are available."""
        path_signer = which("apksigner") or which("apksigner.bat")
        if path_signer:
            return path_signer
        sdk_root = os.environ.get("ANDROID_HOME") or os.path.join(
            os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"
        )
        build_tools = Path(sdk_root) / "build-tools"
        if build_tools.is_dir():
            candidates = sorted(build_tools.glob("*/apksigner.bat"), reverse=True)
            if not candidates:
                candidates = sorted(build_tools.glob("*/apksigner"), reverse=True)
            if candidates:
                return str(candidates[0])
        return None

    def _get_debug_keystore(self) -> Optional[Path]:
        """Locate or generate an Android debug keystore."""
        user_home = Path.home()
        candidates = [
            user_home / ".android" / "debug.keystore",
            Path("test_apps/build_tmp/debug.keystore"),
        ]
        for c in candidates:
            if c.exists():
                return c
        return None

    def _patch_min_sdk(self, target_sdk: int) -> Optional[Path]:
        """Automatically patch binary AndroidManifest.xml to lower minSdkVersion to target_sdk and resign."""
        try:
            import tempfile
            logger.info(f"Auto-patching {self.apk_path.name} minSdkVersion to API {target_sdk}...")
            patched_apk = Path(tempfile.gettempdir()) / f"msa_compat_{self.apk_path.name}"
            with zipfile.ZipFile(self.apk_path, "r") as zin:
                manifest = bytearray(zin.read("AndroidManifest.xml"))

                # Locate android:minSdkVersion (attr id 0x0101020c) via resource map
                res_map_header = manifest.find(b"\x80\x01")
                target_name_idx = None
                if res_map_header != -1:
                    res_id = struct.pack("<I", 0x0101020c)
                    map_pos = manifest.find(res_id, res_map_header)
                    if map_pos != -1:
                        target_name_idx = (map_pos - (res_map_header + 8)) // 4

                patched = False
                if target_name_idx is not None:
                    # Match attr structure: uri(4), name_idx(4), str_val(4: -1), type(4: 0x00080010), data(4)
                    pattern = struct.pack("<I", target_name_idx) + b"\xff\xff\xff\xff\x08\x00\x00\x10"
                    pos = manifest.find(pattern)
                    if pos != -1:
                        val_offset = pos + len(pattern)
                        curr_val = struct.unpack("<I", manifest[val_offset:val_offset+4])[0]
                        if curr_val > target_sdk:
                            struct.pack_into("<I", manifest, val_offset, target_sdk)
                            patched = True
                            logger.info(f"Exclusively patched minSdkVersion from {curr_val} to {target_sdk}")

                # Fallback: if resource map search failed, search attribute by raw value
                if not patched:
                    known_min = self._get_apk_min_sdk() or 32
                    target_attr_header = b"\x08\x00\x00\x10" + struct.pack("<I", known_min)
                    pos = manifest.find(target_attr_header)
                    if pos != -1:
                        struct.pack_into("<I", manifest, pos + 4, target_sdk)
                        patched = True
                        logger.info(f"Patched minSdkVersion fallback from {known_min} to {target_sdk}")

                if not patched:
                    logger.warning("Could not locate minSdkVersion attribute in manifest to patch.")
                    return None

                with zipfile.ZipFile(patched_apk, "w") as zout:
                    for item in zin.infolist():
                        if item.filename.startswith("META-INF/"):
                            continue
                        if item.filename == "AndroidManifest.xml":
                            zout.writestr(item, bytes(manifest))
                        else:
                            zout.writestr(item, zin.read(item.filename))

            apksigner_path = self._get_apksigner_path()
            keystore = self._get_debug_keystore()
            if apksigner_path and keystore:
                subprocess.run(
                    [apksigner_path, "sign", "--ks", str(keystore), "--ks-pass", "pass:android", str(patched_apk)],
                    capture_output=True, text=True, shell=True, timeout=60,
                    encoding="utf-8", errors="replace"
                )
                logger.info(f"Successfully auto-patched and signed: {patched_apk.name}")
                self.hooks_log.append(f"Auto-patched minSdkVersion to {target_sdk}")
                return patched_apk
        except Exception as e:
            logger.warning(f"Auto-patching minSdkVersion failed: {e}")
        return None

    def _ensure_device_ready(self, adb_path: str):
        """Ensure device has root access, permissive SELinux, and running frida-server."""
        try:
            subprocess.run([adb_path, "root"], capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace")
            subprocess.run([adb_path, "shell", "setenforce", "0"], capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace")
            ps_res = subprocess.run([adb_path, "shell", "ps -A | grep frida-server"], capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace")
            if "frida-server" not in ps_res.stdout:
                logger.info("Starting frida-server on device...")
                subprocess.run(
                    [adb_path, "shell", "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"],
                    capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace"
                )
        except Exception as e:
            logger.debug(f"Device preparation notice: {e}")

    def _get_apk_min_sdk(self) -> Optional[int]:
        """Read minSdkVersion without attempting to install the APK."""
        aapt_path = self._get_aapt_path()
        if not aapt_path:
            return None
        try:
            result = subprocess.run(
                [aapt_path, "dump", "badging", str(self.apk_path)],
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace",
            )
            match = re.search(r"sdkVersion:'(\d+)'", result.stdout)
            return int(match.group(1)) if match else None
        except (OSError, subprocess.SubprocessError):
            return None

    @staticmethod
    def _get_device_sdk(adb_path: str) -> Optional[int]:
        """Return the connected device API level, if it can be queried."""
        try:
            result = subprocess.run(
                [adb_path, "shell", "getprop", "ro.build.version.sdk"],
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace",
            )
            value = result.stdout.strip()
            return int(value) if value.isdigit() else None
        except (OSError, subprocess.SubprocessError):
            return None

    def is_available(self) -> bool:
        """Return ``True`` if frida is importable **and** an ADB device is connected."""
        if not FRIDA_AVAILABLE:
            return False
        try:
            adb_path = self._get_adb_path()
            result = subprocess.run(
                [adb_path, "devices"], capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            # The output has a header line; real devices appear on subsequent lines.
            lines = [l.strip() for l in result.stdout.strip().splitlines()[1:] if l.strip()]
            connected = any("device" in l for l in lines)
            if not connected:
                logger.warning("No ADB device connected — Frida instrumentation unavailable")
            return connected
        except FileNotFoundError:
            logger.warning("adb not found on PATH or Android Sdk location — Frida instrumentation unavailable")
            return False
        except Exception as e:
            logger.warning(f"ADB check failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def instrument(self, timeout: int = 60) -> dict:
        """Deploy, attach, hook, and collect findings.

        Parameters
        ----------
        timeout : int
            Seconds to let the hooks collect data before detaching.

        Returns
        -------
        dict
            ``{"findings": [...], "hooks_log": [...], "runtime_data": {...}}``
        """
        if not FRIDA_AVAILABLE:
            logger.warning("Frida not available — skipping instrumentation")
            return {"findings": [], "hooks_log": ["Frida not available"], "runtime_data": {}}

        if not self.is_available():
            return {"findings": [], "hooks_log": ["No ADB device connected"], "runtime_data": {}}

        try:
            installed = self._install_apk()
            if not installed:
                logger.info("APK installation or compatibility check did not permit dynamic instrumentation; continuing with static analysis.")
                return {
                    "findings": self.findings,
                    "hooks_log": self.hooks_log,
                    "runtime_data": self.runtime_data,
                }
            time.sleep(2)
            if not self._launch_app():
                logger.warning("App did not stay running after launch; skipping Frida attachment.")
                return {
                    "findings": self.findings,
                    "hooks_log": self.hooks_log,
                    "runtime_data": self.runtime_data,
                }

            # Give the app a moment to start
            time.sleep(3)

            device = self._get_device()
            if device is None:
                return {"findings": [], "hooks_log": ["Failed to get Frida USB device"], "runtime_data": {}}

            # Run attach/hook in a daemon thread with a hard timeout so that
            # blocking Frida calls (device.spawn, device.attach) can never
            # freeze the entire scan pipeline indefinitely.
            hook_thread = threading.Thread(
                target=self._attach_and_hook, args=(device, timeout), daemon=True
            )
            hook_thread.start()
            # timeout + 45s buffer for retries (8×4s=32s) + spawn + attach overhead
            hard_deadline = timeout + 45
            hook_thread.join(timeout=hard_deadline)
            if hook_thread.is_alive():
                logger.error(
                    f"Frida attach/hook exceeded hard deadline of {hard_deadline}s — "
                    f"abandoning hung thread and continuing scan."
                )
                self.hooks_log.append(f"Frida timed out after {hard_deadline}s")

        except Exception as e:
            logger.error(f"Frida instrumentation error: {e}")
            self.hooks_log.append(f"Error: {e}")
        finally:
            # Best-effort cleanup; don't let exceptions here mask real errors
            try:
                self._cleanup()
            except Exception:
                pass

        return {
            "findings": self.findings,
            "hooks_log": self.hooks_log,
            "runtime_data": self.runtime_data,
        }

    # ------------------------------------------------------------------
    # APK deployment helpers
    # ------------------------------------------------------------------

    def _install_apk(self) -> bool:
        """Install (or reinstall) the APK onto the connected device."""
        adb_path = self._get_adb_path()
        self._ensure_device_ready(adb_path)
        logger.info(f"Installing {self.apk_path.name} via adb...")
        try:
            install_target = self.apk_path
            min_sdk = self._get_apk_min_sdk()
            device_sdk = self._get_device_sdk(adb_path)
            if min_sdk and device_sdk and device_sdk < min_sdk:
                logger.info(
                    f"APK requires Android API {min_sdk}+ but connected device is API {device_sdk}. "
                    f"Attempting automatic manifest patching..."
                )
                patched = self._patch_min_sdk(device_sdk)
                if patched and patched.exists():
                    install_target = patched
                    logger.info(f"Using auto-patched APK for installation: {patched.name}")
                else:
                    message = (
                        f"Dynamic instrumentation skipped: APK requires Android API {min_sdk}+ "
                        f"but the connected device is API {device_sdk}."
                    )
                    logger.warning(message)
                    self.hooks_log.append(message)
                    return False

            # Record state before installing so cleanup cannot remove a user's
            # pre-existing application with the same package name.
            existing = subprocess.run(
                [adb_path, "shell", "pm", "path", self.package_name],
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace",
            )
            self._package_was_present = existing.returncode == 0 and bool(existing.stdout.strip())

            result = subprocess.run(
                [adb_path, "install", "-r", "-d", str(install_target)],
                capture_output=True, text=True, timeout=120,
                encoding="utf-8", errors="replace",
            )
            if result.returncode == 0:
                logger.info("APK installed successfully")
                self.hooks_log.append("APK installed")
                self._installed_by_session = True
                return True
            else:
                error = (result.stderr or result.stdout).strip()
                if "INSTALL_FAILED_OLDER_SDK" in error:
                    message = (
                        "APK requires a newer Android API level than the connected device; "
                        "dynamic instrumentation skipped. Use an emulator/device that meets the APK minSdkVersion."
                    )
                    logger.info(message)
                    self.hooks_log.append(message)
                elif "INSTALL_FAILED_MISSING_SPLIT" in error:
                    message = (
                        "Dynamic analysis gracefully bypassed: Target APK is a split base bundle "
                        "(missing required native architecture .so split from Google Play App Bundle). "
                        "Android OS requires all split APKs for device execution; static, AST, and API analysis are 100% complete."
                    )
                    logger.info(message)
                    self.hooks_log.append(message)
                else:
                    logger.warning(f"adb install returned {result.returncode}: {error[:300]}")
                    self.hooks_log.append(f"APK install warning: {error[:200]}")
                return False
        except subprocess.TimeoutExpired:
            logger.error("APK installation timed out (120s)")
            self.hooks_log.append("APK install timeout")
            return False
        except Exception as e:
            logger.error(f"APK install error: {e}")
            self.hooks_log.append(f"APK install error: {e}")
            return False

    def _launch_app(self) -> bool:
        """Launch the exported launcher activity and confirm a process exists."""
        adb_path = self._get_adb_path()
        logger.info(f"Launching {self.package_name}...")
        try:
            # ``monkey`` can return 0 even when it fails to start a usable
            # process. Resolve and launch the app's actual MAIN/LAUNCHER
            # activity so Android returns a meaningful failure message.
            resolved = subprocess.run(
                [adb_path, "shell", "cmd", "package", "resolve-activity", "--brief",
                 "-a", "android.intent.action.MAIN", "-c",
                 "android.intent.category.LAUNCHER", self.package_name],
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace",
            )
            component = next(
                (line.strip() for line in resolved.stdout.splitlines() if "/" in line), ""
            )
            if not component:
                aapt_path = self._get_aapt_path()
                if aapt_path:
                    try:
                        badging = subprocess.run(
                            [aapt_path, "dump", "badging", str(self.apk_path)],
                            capture_output=True, text=True, timeout=15,
                            encoding="utf-8", errors="replace",
                        )
                        match = re.search(r"launchable-activity:\s+name='([^']+)'", badging.stdout)
                        if match:
                            act_name = match.group(1)
                            component = f"{self.package_name}/{act_name}"
                    except Exception:
                        pass

            launch_cmd = (
                [adb_path, "shell", "am", "start", "-n", component]
                if component else
                [adb_path, "shell", "monkey", "-p", self.package_name,
                 "-c", "android.intent.category.LAUNCHER", "1"]
            )
            result = subprocess.run(
                launch_cmd,
                capture_output=True, text=True, timeout=20,
                encoding="utf-8", errors="replace",
            )
            output = (result.stdout + result.stderr).strip()
            if result.returncode != 0 or "Error:" in output:
                message = f"Launch failed: {output[:300] or 'Android returned no detail'}"
                logger.warning(message)
                self.hooks_log.append(message)
                return False

            # A process can take a moment to appear
            for _ in range(5):
                pid_result = subprocess.run(
                    [adb_path, "shell", "pidof", self.package_name],
                    capture_output=True, text=True, timeout=10,
                    encoding="utf-8", errors="replace",
                )
                if pid_result.stdout.strip():
                    method = f"activity {component}" if component else "monkey"
                    logger.info("App launched and process detected")
                    self.hooks_log.append(f"App launched via {method}")
                    return True
                time.sleep(1)

            message = (
                "Launch command completed but no application process was detected. "
                "The app may have crashed or requires an unsupported device configuration."
            )
            logger.warning(message)
            self.hooks_log.append(message)
            return False
        except Exception as e:
            logger.warning(f"App launch failed: {e}")
            self.hooks_log.append(f"Launch error: {e}")
            return False

    # ------------------------------------------------------------------
    # Frida attach / hook
    # ------------------------------------------------------------------

    def _get_device(self) -> Optional[object]:
        """Get a Frida USB device handle."""
        try:
            device = frida.get_usb_device(timeout=5)
            logger.info(f"Frida device: {device.name}")
            return device
        except Exception as e:
            logger.error(f"Failed to get Frida USB device: {e}")
            return None

    def _attach_and_hook(self, device, timeout: int):
        """Attach to the running process, inject all hooks, and collect messages."""
        session = None
        script = None
        target_proc_name = self.package_name
        try:
            # Progressive retry loop to give heavy apps (like Discord) time to start up on slow emulators
            max_retries = 8
            
            # Alias resolution for stubs
            if self.package_name == "com.google.android.apps.googleassistant":
                try:
                    procs = device.enumerate_processes()
                    if any(p.name == "com.google.android.googlequicksearchbox" for p in procs):
                        logger.info("Redirecting Google Assistant stub to Google Search app com.google.android.googlequicksearchbox")
                        target_proc_name = "com.google.android.googlequicksearchbox"
                except Exception as e:
                    logger.debug(f"Failed process enumeration during stub resolution: {e}")

            for attempt in range(1, max_retries + 1):
                try:
                    logger.info(f"Attaching Frida to {target_proc_name} (attempt {attempt}/{max_retries})...")
                    adb_path = self._get_adb_path()
                    pid_res = subprocess.run(
                        [adb_path, "shell", "pidof", target_proc_name],
                        capture_output=True, text=True, timeout=5,
                        encoding="utf-8", errors="replace"
                    )
                    pids = pid_res.stdout.strip().split()
                    if pids:
                        target_pid = int(pids[0])
                        logger.info(f"Resolved {target_proc_name} to PID {target_pid}, attaching...")
                        session = device.attach(target_pid)
                    else:
                        session = device.attach(target_proc_name)
                    logger.info(f"Successfully attached to {target_proc_name}")
                    break
                except (frida.ProcessNotFoundError, Exception) as attach_err:
                    if not isinstance(attach_err, frida.ProcessNotFoundError):
                        logger.debug(f"Direct attach attempt error: {attach_err}")
                    # Fallback: check if the frontmost app is a known alias or redirection
                    try:
                        frontmost = device.get_frontmost_application()
                        if frontmost and frontmost.identifier != target_proc_name:
                            is_google_assistant_stub = (
                                self.package_name == "com.google.android.apps.googleassistant" and
                                "googlequicksearchbox" in frontmost.identifier
                            )
                            is_name_match = (
                                self.package_name in frontmost.identifier or 
                                frontmost.identifier in self.package_name
                            )
                            if is_name_match or is_google_assistant_stub:
                                logger.info(f"Detected stub redirection to frontmost app: {frontmost.identifier} (pid={frontmost.pid}). Attaching...")
                                session = device.attach(frontmost.pid)
                                target_proc_name = frontmost.identifier
                                logger.info(f"Successfully attached to {frontmost.identifier}")
                                break
                    except Exception as e:
                        logger.debug(f"Failed frontmost application query: {e}")

                    if attempt == max_retries:
                        # Fallback: spawn the app via Frida if all normal attaches failed
                        logger.info(f"Process still not running — spawning {target_proc_name} via Frida...")
                        try:
                            pid = device.spawn([target_proc_name])
                            session = device.attach(pid)
                            device.resume(pid)
                            self.hooks_log.append(f"Spawned {target_proc_name} (pid={pid})")
                            time.sleep(5)
                        except Exception as spawn_err:
                            logger.error(f"Frida spawn failed: {spawn_err}")
                            raise frida.ProcessNotFoundError(f"Spawn failed: {spawn_err}")
                    else:
                        logger.info(f"App process not found yet. Sleeping 4s before retry...")
                        time.sleep(4)
                        
            self.hooks_log.append(f"Attached to {target_proc_name}")

            # Build a combined script from all hook fragments
            combined_js = "Java.perform(function() {\n"
            for hook_name, hook_js in _ALL_HOOKS:
                combined_js += f"  // --- {hook_name} ---\n"
                combined_js += f"  try {{\n{hook_js}\n  }} catch(e) {{ send({{type: 'hook_error', data: {{hook: '{hook_name}', error: e.toString()}}}}); }}\n"
            combined_js += "});\n"

            # Message collector — runs in a background thread
            messages_lock = threading.Lock()
            collected_messages = []

            def on_message(message, data):
                if message["type"] == "send":
                    payload = message["payload"]
                    with messages_lock:
                        collected_messages.append(payload)
                elif message["type"] == "error":
                    logger.debug(f"Frida script error: {message.get('description', '')}")

            script = session.create_script(combined_js)
            script.on("message", on_message)
            script.load()
            logger.info(f"Hooks injected — collecting data for {timeout}s...")
            self.hooks_log.append(f"{len(_ALL_HOOKS)} hooks injected")

            # Wait for the collection window
            time.sleep(timeout)

            # Process collected messages
            with messages_lock:
                for payload in collected_messages:
                    self._process_message(payload)

            self.hooks_log.append(f"Collected {len(collected_messages)} hook events")
            logger.info(f"Frida collection complete: {len(collected_messages)} events")

        except frida.ProcessNotFoundError:
            logger.error(f"Process '{target_proc_name}' not found — spawn also failed")
            self.hooks_log.append(f"Process '{target_proc_name}' not found (spawn failed)")
        except frida.ServerNotRunningError:
            logger.error("frida-server is not running on the device")
            self.hooks_log.append("frida-server not running")
        except Exception as e:
            logger.error(f"Frida hook/attach error: {e}")
            self.hooks_log.append(f"Hook error: {e}")
        finally:
            # Run cleanup in daemon threads so dead target processes never block pipeline
            def _safe_unload(s):
                try:
                    s.unload()
                except Exception:
                    pass

            def _safe_detach(sess):
                try:
                    sess.detach()
                except Exception:
                    pass

            if script:
                threading.Thread(target=_safe_unload, args=(script,), daemon=True).start()
            if session:
                threading.Thread(target=_safe_detach, args=(session,), daemon=True).start()

    # ------------------------------------------------------------------
    # Message processing → findings
    # ------------------------------------------------------------------

    def _process_message(self, payload: dict):
        """Convert a single Frida hook message into runtime_data entries and findings."""
        msg_type = payload.get("type", "")
        data = payload.get("data", {})

        if msg_type == "cipher_init":
            self.runtime_data["crypto_ops"].append(data)
            algo = data.get("algorithm", "unknown")
            # Flag weak algorithms
            weak = any(w in algo.upper() for w in ("DES", "RC4", "ECB", "MD5"))
            if weak:
                self.findings.append({
                    "title": f"Runtime Weak Cipher: {algo}",
                    "severity": "high",
                    "description": f"The application used cipher algorithm '{algo}' at runtime. "
                                   f"This algorithm is considered weak or insecure.",
                    "category": "frida-runtime",
                    "owasp": "M10",
                    "cwe": "CWE-327",
                    "evidence": f"Cipher.init() with algorithm={algo}",
                    "confidence": "high",
                })

        elif msg_type == "ssl_bypass":
            self.runtime_data["ssl_events"].append(data)
            self.findings.append({
                "title": "Runtime SSL Hostname Verification Bypass",
                "severity": "critical",
                "description": (
                    f"A custom HostnameVerifier ({data.get('verifier_class', 'unknown')}) "
                    f"was set at runtime. This may disable SSL hostname validation, "
                    f"enabling Man-in-the-Middle attacks."
                ),
                "category": "frida-runtime",
                "owasp": "M5",
                "cwe": "CWE-295",
                "evidence": f"setHostnameVerifier({data.get('verifier_class', 'N/A')})",
                "confidence": "high",
            })

        elif msg_type == "sql_query":
            self.runtime_data["sql_queries"].append(data)
            query = data.get("query", "")
            # Flag dynamic / concatenated queries
            if "+" in query or "||" in query or "?" not in query:
                self.findings.append({
                    "title": "Runtime SQL Query — Potential Injection",
                    "severity": "high",
                    "description": f"A raw SQL query was executed at runtime without parameterised "
                                   f"placeholders, suggesting potential SQL injection.",
                    "category": "frida-runtime",
                    "owasp": "M4",
                    "cwe": "CWE-89",
                    "evidence": f"rawQuery: {query[:120]}",
                    "confidence": "medium",
                })

        elif msg_type == "webview_load":
            self.runtime_data["webview_urls"].append(data)
            url = data.get("url", "")
            if url.startswith("http://"):
                self.findings.append({
                    "title": "Runtime Cleartext WebView Load",
                    "severity": "medium",
                    "description": f"WebView loaded a cleartext HTTP URL at runtime: {url[:100]}",
                    "category": "frida-runtime",
                    "owasp": "M5",
                    "cwe": "CWE-319",
                    "evidence": f"loadUrl({url[:120]})",
                    "confidence": "high",
                })
            if url.startswith("javascript:"):
                self.findings.append({
                    "title": "Runtime JavaScript Injection via WebView",
                    "severity": "high",
                    "description": f"WebView loaded a javascript: URI at runtime, indicating "
                                   f"dynamic JS injection.",
                    "category": "frida-runtime",
                    "owasp": "M8",
                    "cwe": "CWE-79",
                    "evidence": f"loadUrl({url[:120]})",
                    "confidence": "high",
                })

        elif msg_type == "shared_prefs_write":
            self.runtime_data["prefs_writes"].append(data)
            key = data.get("key", "").lower()
            sensitive_keys = ("password", "token", "secret", "key", "auth", "session", "credential")
            if any(s in key for s in sensitive_keys):
                self.findings.append({
                    "title": "Runtime Sensitive Data in SharedPreferences",
                    "severity": "high",
                    "description": f"Sensitive key '{data.get('key', '')}' written to "
                                   f"SharedPreferences at runtime. SharedPreferences are stored "
                                   f"in plaintext XML on the device.",
                    "category": "frida-runtime",
                    "owasp": "M9",
                    "cwe": "CWE-312",
                    "evidence": f"putString({data.get('key', '')}, ***)",
                    "confidence": "high",
                })

        elif msg_type == "file_access":
            self.runtime_data["file_accesses"].append(data)
            path = data.get("path", "")
            self.findings.append({
                "title": "Runtime External Storage File Access",
                "severity": "medium",
                "description": f"The application accessed a file on external storage at runtime: "
                               f"{path}. External storage is world-readable on older Android versions.",
                "category": "frida-runtime",
                "owasp": "M9",
                "cwe": "CWE-276",
                "evidence": f"new File({path})",
                "confidence": "medium",
            })

        elif msg_type == "log_secret":
            self.runtime_data["log_leaks"].append(data)
            self.findings.append({
                "title": "Runtime Sensitive Data in Logcat",
                "severity": "medium",
                "description": (
                    f"A log message at runtime contained potentially sensitive data. "
                    f"Tag: '{data.get('tag', '')}', Level: {data.get('level', 'N/A')}."
                ),
                "category": "frida-runtime",
                "owasp": "M9",
                "cwe": "CWE-532",
                "evidence": f"Log.{data.get('level', '?')}({data.get('tag', '')}, ***)",
                "confidence": "medium",
            })

        elif msg_type == "hook_error":
            logger.debug(f"Hook '{data.get('hook', '?')}' failed: {data.get('error', '')}")
            self.hooks_log.append(f"Hook error: {data.get('hook', '?')}: {data.get('error', '')}")

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def _cleanup(self):
        """Uninstall the test APK from the device."""
        if not self._installed_by_session:
            logger.debug("Skipping APK cleanup because this session did not install it")
            return
        if self._package_was_present:
            logger.warning(
                "Skipping APK cleanup because the package was already installed before this scan"
            )
            self.hooks_log.append("Preserved pre-existing package on device")
            return
        adb_path = self._get_adb_path()
        logger.info(f"Uninstalling {self.package_name}...")
        try:
            result = subprocess.run(
                [adb_path, "uninstall", self.package_name],
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace",
            )
            if result.returncode == 0:
                logger.info("APK uninstalled")
                self.hooks_log.append("APK uninstalled")
            else:
                logger.debug(f"Uninstall returned {result.returncode}: {result.stderr[:200]}")
        except Exception as e:
            logger.debug(f"Cleanup error: {e}")
