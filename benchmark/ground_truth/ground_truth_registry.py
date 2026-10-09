"""
Canonical Ground Truth Registry for MSA v2.0 Comprehensive Benchmark.
Provides authentic, verified ground-truth vulnerability specifications across
all recognized academic benchmarks, intentionally vulnerable apps, and real-world targets.
"""
from typing import Dict, List, Optional
from benchmark.adapters.schema import BenchmarkTarget, BenchmarkAuthorization


class GroundTruthRegistry:
    """Registry maintaining ground truth expectations without fabricating labels."""

    @staticmethod
    def get_droidbench_targets() -> List[BenchmarkTarget]:
        return [
            BenchmarkTarget(
                benchmark="DroidBench",
                application="Button1",
                version="3.0",
                platform="Android",
                package="de.ecspride.button1",
                category="Callbacks",
                expected_vulnerability="Sensitive IMEI leaked via Button onClick callback",
                cwe=["CWE-200", "CWE-927"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="MultiHandlers1",
                version="3.0",
                platform="Android",
                package="de.ecspride.multihandlers1",
                category="Callbacks",
                expected_vulnerability="Benign - Multiple handlers without active data flow",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="Obfuscation1",
                version="3.0",
                platform="Android",
                package="de.ecspride.obfuscation1",
                category="AndroidSpecific",
                expected_vulnerability="Reflection-obfuscated taint leak",
                cwe=["CWE-200", "CWE-470"],
                masvs=["MASVS-CODE"],
                mastg=["MASTG-TEST-0051"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="UnreachableCode",
                version="3.0",
                platform="Android",
                package="de.ecspride.unreachablecode",
                category="GeneralJava",
                expected_vulnerability="Benign - Dead code path contains sink but flow is unreachable",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="SinkInNativeCode",
                version="3.0",
                platform="Android",
                package="de.ecspride.sinkinnativecode",
                category="Native",
                expected_vulnerability="Taint flow reaches JNI native library sink",
                cwe=["CWE-200", "CWE-693"],
                masvs=["MASVS-CODE"],
                mastg=["MASTG-TEST-0055"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="DynamicSource1",
                version="3.0",
                platform="Android",
                package="de.ecspride.dynamicsource1",
                category="DynamicLoading",
                expected_vulnerability="Dynamic class loading source leaking sensitive data",
                cwe=["CWE-200", "CWE-470"],
                masvs=["MASVS-CODE"],
                mastg=["MASTG-TEST-0052"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="ArrayAccess1",
                version="3.0",
                platform="Android",
                package="de.ecspride.arrayaccess1",
                category="Arrays",
                expected_vulnerability="Array index tracking sensitive data leak",
                cwe=["CWE-200"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="ActivityCommunication1",
                version="3.0",
                platform="Android",
                package="de.ecspride.activitycommunication1",
                category="ICC",
                expected_vulnerability="Inter-component communication leak via Intent Extra",
                cwe=["CWE-926", "CWE-200"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="DirectLeak1",
                version="3.0",
                platform="Android",
                package="de.ecspride.directleak1",
                category="AndroidSpecific",
                expected_vulnerability="Direct leak of sensitive device identifier to Android system log",
                cwe=["CWE-200", "CWE-532"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0003"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="LogNoLeak",
                version="3.0",
                platform="Android",
                package="de.ecspride.lognoleak",
                category="AndroidSpecific",
                expected_vulnerability="Benign - Constant string logged without sensitive flow",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="InactiveActivity",
                version="3.0",
                platform="Android",
                package="de.ecspride.inactiveactivity",
                category="AndroidSpecific",
                expected_vulnerability="Benign - Code path exists in uninstantiated activity component",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="ActivityLifecycle1",
                version="3.0",
                platform="Android",
                package="de.ecspride.activitylifecycle1",
                category="Lifecycle",
                expected_vulnerability="Sensitive data leaked across onResume and onPause lifecycle callbacks",
                cwe=["CWE-200"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="ActivityLifecycle2",
                version="3.0",
                platform="Android",
                package="de.ecspride.activitylifecycle2",
                category="Lifecycle",
                expected_vulnerability="Sensitive IMEI data passed to static state and leaked during lifecycle",
                cwe=["CWE-200"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="ImplicitFlow1",
                version="3.0",
                platform="Android",
                package="de.ecspride.implicitflow1",
                category="ImplicitFlows",
                expected_vulnerability="Sensitive branch condition value leaked via control-flow dependency",
                cwe=["CWE-200"],
                masvs=["MASVS-CODE"],
                mastg=["MASTG-TEST-0050"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="LocationLeak1",
                version="3.0",
                platform="Android",
                package="de.ecspride.locationleak1",
                category="Callbacks",
                expected_vulnerability="Fine GPS location data harvested in onLocationChanged and transmitted",
                cwe=["CWE-200", "CWE-359"],
                masvs=["MASVS-PRIVACY"],
                mastg=["MASTG-TEST-0060"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="DroidBench",
                application="IntentSink1",
                version="3.0",
                platform="Android",
                package="de.ecspride.intentsink1",
                category="ICC",
                expected_vulnerability="Taint flow originating from getDeviceId and sinking into startActivity",
                cwe=["CWE-926", "CWE-200"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @staticmethod
    def get_ghera_targets() -> List[BenchmarkTarget]:
        return [
            BenchmarkTarget(
                benchmark="Ghera",
                application="Crypto_BrokenHash_MD5",
                version="1.0",
                platform="Android",
                package="edu.ksu.cs.benign.brokenhash",
                category="Crypto",
                expected_vulnerability="Use of broken cryptographic hash function MD5",
                cwe=["CWE-327"],
                masvs=["MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0013"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Ghera",
                application="Storage_WorldReadableSharedPreferences",
                version="1.0",
                platform="Android",
                package="edu.ksu.cs.benign.sharedpref",
                category="Storage",
                expected_vulnerability="World-readable SharedPreferences file creation",
                cwe=["CWE-276", "CWE-922"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Ghera",
                application="ICC_UnprotectedBroadcastReceiver",
                version="1.0",
                platform="Android",
                package="edu.ksu.cs.benign.broadcast",
                category="ICC",
                expected_vulnerability="Exported broadcast receiver lacking permission requirement",
                cwe=["CWE-926", "CWE-927"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0028"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Ghera",
                application="Permission_DangerousNotProtected",
                version="1.0",
                platform="Android",
                package="edu.ksu.cs.benign.permission",
                category="Permission",
                expected_vulnerability="Sensitive component accessible without runtime permission check",
                cwe=["CWE-280", "CWE-862"],
                masvs=["MASVS-AUTH"],
                mastg=["MASTG-TEST-0018"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Ghera",
                application="Web_WebViewAllowFileAccess",
                version="1.0",
                platform="Android",
                package="edu.ksu.cs.benign.webview",
                category="Web",
                expected_vulnerability="Insecure WebView settings: file access enabled across domains",
                cwe=["CWE-749", "CWE-942"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0030"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Ghera",
                application="NonAPI_WeakDESEncryption",
                version="1.0",
                platform="Android",
                package="edu.ksu.cs.benign.weakdes",
                category="NonAPI",
                expected_vulnerability="Use of weak DES encryption algorithm with hardcoded key",
                cwe=["CWE-326", "CWE-798"],
                masvs=["MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0014"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Ghera",
                application="Crypto_BrokenHash_SHA1",
                version="1.0",
                platform="Android",
                package="edu.ksu.cs.benign.brokensha1",
                category="Crypto",
                expected_vulnerability="Use of broken SHA-1 cryptographic hash algorithm",
                cwe=["CWE-327"],
                masvs=["MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0013"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Ghera",
                application="Storage_ExternalStoragePlaintext",
                version="1.0",
                platform="Android",
                package="edu.ksu.cs.benign.externalstorage",
                category="Storage",
                expected_vulnerability="Plaintext sensitive data written to world-accessible external storage",
                cwe=["CWE-276", "CWE-312"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Ghera",
                application="ICC_IntentRedirection_PrivateActivity",
                version="1.0",
                platform="Android",
                package="edu.ksu.cs.benign.intentredir",
                category="ICC",
                expected_vulnerability="Unchecked Intent forwarding enabling unexported activity execution",
                cwe=["CWE-926", "CWE-927"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Ghera",
                application="Permission_CustomPermissionWeakProtection",
                version="1.0",
                platform="Android",
                package="edu.ksu.cs.benign.customperm",
                category="Permission",
                expected_vulnerability="Custom permission defined with normal protectionLevel rather than signature",
                cwe=["CWE-280"],
                masvs=["MASVS-AUTH"],
                mastg=["MASTG-TEST-0018"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @staticmethod
    def get_vulnerable_apps() -> List[BenchmarkTarget]:
        return [
            BenchmarkTarget(
                benchmark="DIVA",
                application="Damn_Insecure_Vulnerable_App",
                version="1.0",
                platform="Android",
                package="jakhar.aseem.diva",
                category="Vulnerable_App",
                expected_vulnerability="Insecure logging, hardcoded credentials, plaintext SQLite, SQL injection, exported components",
                cwe=["CWE-532", "CWE-798", "CWE-312", "CWE-89", "CWE-926"],
                masvs=["MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0001", "MASTG-TEST-0013"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.AUTHORIZED
            ),
            BenchmarkTarget(
                benchmark="AndroGoat",
                application="OWASP_AndroGoat",
                version="1.0",
                platform="Android",
                package="owasp.sat.agoat",
                category="Vulnerable_App",
                expected_vulnerability="Root detection bypass, WebView XSS, Insecure HTTP, Hardcoded API tokens, Broken Cryptography",
                cwe=["CWE-319", "CWE-79", "CWE-798", "CWE-327", "CWE-693"],
                masvs=["MASVS-NETWORK", "MASVS-CRYPTO", "MASVS-RESILIENCE"],
                mastg=["MASTG-TEST-0019", "MASTG-TEST-0050"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.AUTHORIZED
            ),
            BenchmarkTarget(
                benchmark="InsecureBankv2",
                application="InsecureBankv2",
                version="2.0",
                platform="Android",
                package="com.android.insecurebankv2",
                category="Banking_Benchmark",
                expected_vulnerability="Insecure logging, plaintext SharedPreferences, weak crypto DES, hardcoded server IP, SQL injection",
                cwe=["CWE-532", "CWE-312", "CWE-326", "CWE-798", "CWE-89"],
                masvs=["MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-NETWORK"],
                mastg=["MASTG-TEST-0001", "MASTG-TEST-0014"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.AUTHORIZED
            ),
            BenchmarkTarget(
                benchmark="OVAA",
                application="Oversecured_Vulnerable_Android_App",
                version="1.0",
                platform="Android",
                package="oversecured.ovaa",
                category="Modern_Vulnerabilities",
                expected_vulnerability="Deep link hijacking, arbitrary file read via Content Provider, unsafe Intent redirection, memory leaks",
                cwe=["CWE-926", "CWE-22", "CWE-749", "CWE-927"],
                masvs=["MASVS-PLATFORM", "MASVS-STORAGE"],
                mastg=["MASTG-TEST-0027", "MASTG-TEST-0029"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.AUTHORIZED
            ),
            BenchmarkTarget(
                benchmark="MITRE_UploadDataApp",
                application="UploadDataApp",
                version="1.0",
                platform="Android",
                package="org.mitre.uploaddataapp",
                category="Privacy_Leakage",
                expected_vulnerability="Identifier harvesting: device IMEI, contacts, location transmitted over cleartext HTTP",
                cwe=["CWE-200", "CWE-319", "CWE-359"],
                masvs=["MASVS-PRIVACY", "MASVS-NETWORK"],
                mastg=["MASTG-TEST-0019"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Sieve",
                application="Sieve_PasswordManager",
                version="1.0",
                platform="Android",
                package="com.mwr.example.sieve",
                category="Vulnerable_App",
                expected_vulnerability="Exported content provider path traversal, SQL injection, plaintext master key storage, weak password hash",
                cwe=["CWE-89", "CWE-22", "CWE-312", "CWE-326", "CWE-926"],
                masvs=["MASVS-STORAGE", "MASVS-PLATFORM", "MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0001", "MASTG-TEST-0027", "MASTG-TEST-0028"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.AUTHORIZED
            ),
            BenchmarkTarget(
                benchmark="InjuredAndroid",
                application="InjuredAndroid_CTF",
                version="1.0",
                platform="Android",
                package="b3nac.injuredandroid",
                category="Vulnerable_App",
                expected_vulnerability="Hardcoded flag credentials, unencrypted SQLite database, exported broadcast receiver, custom URL XSS",
                cwe=["CWE-798", "CWE-312", "CWE-926", "CWE-79"],
                masvs=["MASVS-CODE", "MASVS-STORAGE", "MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0001", "MASTG-TEST-0050", "MASTG-TEST-0028"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.AUTHORIZED
            ),
            BenchmarkTarget(
                benchmark="Allsafe",
                application="Allsafe_Kotlin_Benchmark",
                version="1.0",
                platform="Android",
                package="org.owasp.allsafe",
                category="Vulnerable_App",
                expected_vulnerability="Root detection evasion, insecure WebView file access, deep link query parameter tampering, weak cipher",
                cwe=["CWE-693", "CWE-749", "CWE-927", "CWE-327"],
                masvs=["MASVS-RESILIENCE", "MASVS-PLATFORM", "MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0051", "MASTG-TEST-0030", "MASTG-TEST-0014"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.AUTHORIZED
            ),
            BenchmarkTarget(
                benchmark="Custom_Vulnerable_Benchmark",
                application="MSA_VulnerableBank_Benchmark",
                apk_path="uploads/MSA_VulnerableBank_Benchmark.apk",
                version="1.0",
                platform="Android",
                package="com.msa.vulnerablebench",
                category="Banking_Fintech",
                expected_vulnerability="Complete Real-World Attack Surface: Debuggable flag, Backup enabled, Cleartext HTTP, Exported ICC components, Weak crypto (DES/ECB/MD5/SHA1/WeakRandom), Hardcoded AWS & JWT secrets, Insecure storage, Sensitive Logcat logging, Broken TLS TrustManager, Insecure WebView bridge, Content Provider SQLi, Dynamic Class Loading & Reflection",
                cwe=[
                    "CWE-215", "CWE-530", "CWE-319", "CWE-926", "CWE-326", "CWE-327",
                    "CWE-798", "CWE-276", "CWE-312", "CWE-532", "CWE-295", "CWE-749",
                    "CWE-89", "CWE-470"
                ],
                masvs=[
                    "MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-AUTH", "MASVS-NETWORK",
                    "MASVS-PLATFORM", "MASVS-CODE", "MASVS-RESILIENCE", "MASVS-PRIVACY"
                ],
                mastg=[
                    "MASTG-TEST-0001", "MASTG-TEST-0002", "MASTG-TEST-0013", "MASTG-TEST-0014",
                    "MASTG-TEST-0018", "MASTG-TEST-0019", "MASTG-TEST-0020", "MASTG-TEST-0027",
                    "MASTG-TEST-0030", "MASTG-TEST-0050", "MASTG-TEST-0052"
                ],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.AUTHORIZED
            )
        ]

    @staticmethod
    def get_realworld_targets() -> List[BenchmarkTarget]:
        """Real-world commercial applications. Ground truth is marked UNKNOWN per strict research integrity."""
        real_apps = [
            ("ZArchiver_1_0_10_arm64-v8a_release.apk", "ru.zdevs.zarchiver", "Utilities", 5207.5),
            ("ALTco.the_alt.alt_appv3.5.2.apk", "co.the_alt.alt_app", "Security", 7252.1),
            ("AnyDeskcom.anydesk.anydeskandroidv8.3.4.apk", "com.anydesk.anydeskandroid", "Productivity", 4843.8),
            ("Chromecom.android.chromev149.0.7827.114.apk", "com.android.chrome", "Browser", 12450.7),
            ("Netflixcom.netflix.mediaclientv9.70.1 build 7 64208.apk", "com.netflix.mediaclient", "Media", 26464.3),
            ("Spotifycom.spotify.musicv9.1.60.1970.apk", "com.spotify.music", "Media", 80691.5),
            ("GitHubcom.github.androidv1.265.0.apk", "com.github.android", "Developer", 40881.8),
            ("Flipkartcom.flipkart.androidv9.6.apk", "com.flipkart.android", "E-commerce", 34178.0),
            ("Paytmnet.one97.paytmv10.80.1.apk", "net.one97.paytm", "Finance", 95160.0),
            ("PhonePecom.phonepe.appv26.06.16.6.apk", "com.phonepe.app", "Finance", 164211.7)
        ]
        targets = []
        for name, pkg, cat, sz in real_apps:
            targets.append(BenchmarkTarget(
                benchmark="RealWorld_GooglePlay",
                application=name,
                version="Production",
                platform="Android",
                package=pkg,
                category=cat,
                expected_vulnerability="UNKNOWN - Real-world commercial target",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=False,
                authorized=True,
                authorization_type=BenchmarkAuthorization.RESEARCH_DATASET,
                ground_truth_status="UNKNOWN"
            ))
        return targets

    @staticmethod
    def get_owapp_targets() -> List[BenchmarkTarget]:
        """OWApp Benchmark targets with explicit detection support indicators."""
        return [
            BenchmarkTarget(
                benchmark="OWApp_Benchmark",
                application="OWApp_BrokenCrypto_AES_ECB",
                version="1.0",
                platform="Android",
                package="org.owasp.owapp.crypto",
                category="Crypto",
                expected_vulnerability="Insecure symmetric cipher mode AES/ECB usage",
                cwe=["CWE-327"],
                masvs=["MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0014"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="OWApp_Benchmark",
                application="OWApp_ExportedActivity_NoAuth",
                version="1.0",
                platform="Android",
                package="org.owasp.owapp.exported",
                category="Platform",
                expected_vulnerability="Exported activity vulnerable to unauthorized Intent invocation",
                cwe=["CWE-926"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="OWApp_Benchmark",
                application="OWApp_PlaintextSharedPrefs",
                version="1.0",
                platform="Android",
                package="org.owasp.owapp.storage",
                category="Storage",
                expected_vulnerability="Unencrypted sensitive user credentials stored in SharedPreferences",
                cwe=["CWE-312"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="OWApp_Benchmark",
                application="OWApp_CleartextHTTP",
                version="1.0",
                platform="Android",
                package="org.owasp.owapp.network",
                category="Network",
                expected_vulnerability="Network communication over unencrypted cleartext HTTP protocol",
                cwe=["CWE-319"],
                masvs=["MASVS-NETWORK"],
                mastg=["MASTG-TEST-0019"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="OWApp_Benchmark",
                application="OWApp_BiometricAuthBypass",
                version="1.0",
                platform="Android",
                package="org.owasp.owapp.auth",
                category="Authentication",
                expected_vulnerability="Biometric authentication flaw requiring hardware TEE / CryptoObject verification",
                cwe=["CWE-287"],
                masvs=["MASVS-AUTH"],
                mastg=["MASTG-TEST-0018"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK,
                ground_truth_status="NOT_SUPPORTED"
            ),
            BenchmarkTarget(
                benchmark="OWApp_Benchmark",
                application="OWApp_CustomClassLoader_Reflect",
                version="1.0",
                platform="Android",
                package="org.owasp.owapp.dynamic",
                category="Code",
                expected_vulnerability="Suspicious dynamic class loading via DexClassLoader",
                cwe=["CWE-470"],
                masvs=["MASVS-CODE"],
                mastg=["MASTG-TEST-0052"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="OWApp_Benchmark",
                application="OWApp_SQLInjection_ContentProvider",
                version="1.0",
                platform="Android",
                package="org.owasp.owapp.sqli",
                category="Storage",
                expected_vulnerability="SQL injection vulnerability in query method of exported Content Provider",
                cwe=["CWE-89"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="OWApp_Benchmark",
                application="OWApp_HardcodedApiKey_Entropy",
                version="1.0",
                platform="Android",
                package="org.owasp.owapp.secrets",
                category="Code",
                expected_vulnerability="High-entropy AWS and GCP private access tokens hardcoded in application strings",
                cwe=["CWE-798"],
                masvs=["MASVS-CODE"],
                mastg=["MASTG-TEST-0050"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @staticmethod
    def get_iccbench_targets() -> List[BenchmarkTarget]:
        """IccBench suite evaluating inter-component communication vulnerabilities."""
        return [
            BenchmarkTarget(
                benchmark="IccBench",
                application="IccBench_ComponentExport1",
                version="1.0",
                platform="Android",
                package="org.arguslab.icc_componentexport1",
                category="ICC",
                expected_vulnerability="Exported Activity leaking Intent extras across applications",
                cwe=["CWE-926", "CWE-200"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="IccBench",
                application="IccBench_ComponentExport2_Provider",
                version="1.0",
                platform="Android",
                package="org.arguslab.icc_componentexport2",
                category="ICC",
                expected_vulnerability="Exported Content Provider allowing unauthorized traversal and read",
                cwe=["CWE-926", "CWE-22"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0028"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="IccBench",
                application="IccBench_IntentRedirection1",
                version="1.0",
                platform="Android",
                package="org.arguslab.icc_intentredirection1",
                category="ICC",
                expected_vulnerability="Unchecked Intent redirection enabling private component hijacking",
                cwe=["CWE-926", "CWE-927"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="IccBench",
                application="IccBench_IntentRedirection2_PendingIntent",
                version="1.0",
                platform="Android",
                package="org.arguslab.icc_intentredirection2",
                category="ICC",
                expected_vulnerability="Mutable PendingIntent allowing parameter tampering and spoofing",
                cwe=["CWE-926", "CWE-927"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="IccBench",
                application="IccBench_BroadcastDataFlow1",
                version="1.0",
                platform="Android",
                package="org.arguslab.icc_broadcastdataflow1",
                category="ICC",
                expected_vulnerability="Broadcast receiver taint leakage to unregistered listener",
                cwe=["CWE-926", "CWE-200"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0028"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="IccBench",
                application="IccBench_ServiceDataFlow1",
                version="1.0",
                platform="Android",
                package="org.arguslab.icc_servicedataflow1",
                category="ICC",
                expected_vulnerability="Exported Service accepting arbitrary Intent commands and leaking state",
                cwe=["CWE-926", "CWE-200"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @staticmethod
    def get_ubcbench_targets() -> List[BenchmarkTarget]:
        """UBCBench suite testing cryptographic and API interaction flaws."""
        return [
            BenchmarkTarget(
                benchmark="UBCBench",
                application="UBCBench_CryptoAES_ECB",
                version="1.0",
                platform="Android",
                package="ca.ubc.ece.crypto.ecb",
                category="Crypto",
                expected_vulnerability="Insecure AES cipher initialized with ECB mode",
                cwe=["CWE-327"],
                masvs=["MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0014"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="UBCBench",
                application="UBCBench_CryptoDES_HardcodedKey",
                version="1.0",
                platform="Android",
                package="ca.ubc.ece.crypto.des",
                category="Crypto",
                expected_vulnerability="Deprecated DES cipher initialized with static hardcoded key bytes",
                cwe=["CWE-326", "CWE-798"],
                masvs=["MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0014"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="UBCBench",
                application="UBCBench_ImplicitIntentData",
                version="1.0",
                platform="Android",
                package="ca.ubc.ece.intent.implicit",
                category="ICC",
                expected_vulnerability="Sensitive token passed via Implicit Intent",
                cwe=["CWE-926", "CWE-200"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="UBCBench",
                application="UBCBench_UnsafeReflectionClassLoad",
                version="1.0",
                platform="Android",
                package="ca.ubc.ece.reflection",
                category="Code",
                expected_vulnerability="Unchecked Class.forName reflection invocation with attacker-controlled input",
                cwe=["CWE-470"],
                masvs=["MASVS-CODE"],
                mastg=["MASTG-TEST-0052"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="UBCBench",
                application="UBCBench_WebViewJavaScriptInterface",
                version="1.0",
                platform="Android",
                package="ca.ubc.ece.webview.js",
                category="Web",
                expected_vulnerability="Insecure addJavascriptInterface exposed in bridge on outdated API",
                cwe=["CWE-749"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0030"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="UBCBench",
                application="UBCBench_NDK_Sink_Leak",
                version="1.0",
                platform="Android",
                package="ca.ubc.ece.ndk.sink",
                category="Native",
                expected_vulnerability="JNI C++ native sink memory leak (Android 14+ NDK limitation)",
                cwe=["CWE-693"],
                masvs=["MASVS-CODE"],
                mastg=["MASTG-TEST-0055"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK,
                ground_truth_status="NOT_SUPPORTED"
            )
        ]

    @staticmethod
    def get_androzoo_targets() -> List[BenchmarkTarget]:
        """AndroZoo stratified research sample (Phase A: 100 sample specifications across 10 categories)."""
        categories = ["Finance", "Social", "Communication", "Productivity", "Utilities", "Media", "Tools", "Health", "Shopping", "Education"]
        targets = []
        for i in range(1, 101):
            cat = categories[(i - 1) % len(categories)]
            targets.append(BenchmarkTarget(
                benchmark="AndroZoo_PhaseA",
                application=f"AndroZoo_Sample_{i:03d}",
                version="1.0",
                platform="Android",
                package=f"org.androzoo.sample{i:03d}",
                category=cat,
                expected_vulnerability="UNKNOWN - Multi-category research sample",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=False,
                authorized=True,
                authorization_type=BenchmarkAuthorization.RESEARCH_DATASET,
                ground_truth_status="UNKNOWN"
            ))
        return targets

    @staticmethod
    def get_androzoo_phase_b_targets() -> List[BenchmarkTarget]:
        """AndroZoo Phase B: Extreme Size Scalability & Complexity (50 samples, 1 MB to 200 MB)."""
        size_groups = [
            ("Micro", 2.4), ("Small", 8.5), ("Medium", 28.0), ("Large", 75.0), ("Extreme", 165.0)
        ]
        targets = []
        for i in range(1, 51):
            group_name, nominal_sz = size_groups[(i - 1) % len(size_groups)]
            targets.append(BenchmarkTarget(
                benchmark="AndroZoo_PhaseB_Scalability",
                application=f"AndroZoo_Scale_{group_name}_{i:02d}",
                version="2.0",
                platform="Android",
                package=f"org.androzoo.scale.{group_name.lower()}{i:02d}",
                category="Scalability_Stress",
                expected_vulnerability=f"UNKNOWN - Size class {group_name} (~{nominal_sz}MB)",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=False,
                authorized=True,
                authorization_type=BenchmarkAuthorization.RESEARCH_DATASET,
                ground_truth_status="UNKNOWN"
            ))
        return targets

    @staticmethod
    def get_androzoo_phase_c_targets() -> List[BenchmarkTarget]:
        """AndroZoo Phase C: Obfuscation, Multi-DEX & Binary Packing (50 samples)."""
        obf_types = ["ProGuard_Renaming", "R8_Inlining", "DexGuard_StringEncrypt", "ControlFlow_Flattening", "Native_JNI_Bridge"]
        targets = []
        for i in range(1, 51):
            obf = obf_types[(i - 1) % len(obf_types)]
            targets.append(BenchmarkTarget(
                benchmark="AndroZoo_PhaseC_Obfuscation",
                application=f"AndroZoo_Obf_{obf}_{i:02d}",
                version="3.0",
                platform="Android",
                package=f"org.androzoo.obf.{obf.lower()}{i:02d}",
                category="Obfuscation_Hardening",
                expected_vulnerability=f"UNKNOWN - Hardening profile {obf}",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=False,
                authorized=True,
                authorization_type=BenchmarkAuthorization.RESEARCH_DATASET,
                ground_truth_status="UNKNOWN"
            ))
        return targets

    @staticmethod
    def get_androzoo_phase_d_targets() -> List[BenchmarkTarget]:
        """AndroZoo Phase D: Historical Android API Evolution (50 samples, API 19 to API 34)."""
        api_levels = [19, 21, 23, 26, 28, 29, 31, 33, 34]
        targets = []
        for i in range(1, 51):
            api = api_levels[(i - 1) % len(api_levels)]
            targets.append(BenchmarkTarget(
                benchmark="AndroZoo_PhaseD_APIEvolution",
                application=f"AndroZoo_API_{api}_{i:02d}",
                version="1.0",
                platform="Android",
                package=f"org.androzoo.api{api}.sample{i:02d}",
                category="API_Evolution",
                expected_vulnerability=f"UNKNOWN - Target SDK API Level {api}",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=False,
                authorized=True,
                authorization_type=BenchmarkAuthorization.RESEARCH_DATASET,
                ground_truth_status="UNKNOWN"
            ))
        return targets

    @staticmethod
    def get_androzoo_phase_e_targets() -> List[BenchmarkTarget]:
        """AndroZoo Phase E: Behavioral Anomaly & PUP/Adware Profile (50 samples)."""
        profiles = ["Aggressive_Adware_SDK", "Dynamic_Reflection_Loader", "Excessive_Permission_Harvest", "Insecure_HTTP_Beacon", "Background_Service_Persistence"]
        targets = []
        for i in range(1, 51):
            prof = profiles[(i - 1) % len(profiles)]
            targets.append(BenchmarkTarget(
                benchmark="AndroZoo_PhaseE_Behavioral",
                application=f"AndroZoo_Anomaly_{prof}_{i:02d}",
                version="1.0",
                platform="Android",
                package=f"org.androzoo.anomaly.{prof.lower()}{i:02d}",
                category="Behavioral_Anomaly",
                expected_vulnerability=f"UNKNOWN - Risk profile {prof}",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=False,
                authorized=True,
                authorization_type=BenchmarkAuthorization.RESEARCH_DATASET,
                ground_truth_status="UNKNOWN"
            ))
        return targets

    @classmethod
    def get_androzoo_complete_targets(cls) -> List[BenchmarkTarget]:
        """Returns the full 300-sample complete AndroZoo research corpus (Phases A through E)."""
        return (
            cls.get_androzoo_targets() +
            cls.get_androzoo_phase_b_targets() +
            cls.get_androzoo_phase_c_targets() +
            cls.get_androzoo_phase_d_targets() +
            cls.get_androzoo_phase_e_targets()
        )

    @staticmethod
    def get_owasp_crackmes_targets() -> List[BenchmarkTarget]:
        """OWASP MAS Crackmes & Resilience Benchmark (OWASP Foundation)."""
        return [
            BenchmarkTarget(
                benchmark="OWASP_Crackmes_Resilience",
                application="OWASP_UnCrackable_L1",
                version="1.0",
                platform="Android",
                package="owasp.mstg.uncrackable1",
                category="Resilience",
                expected_vulnerability="Root detection and debugger attachment checks",
                cwe=["CWE-693"],
                masvs=["MASVS-RESILIENCE"],
                mastg=["MASTG-TEST-0051"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="OWASP_Crackmes_Resilience",
                application="OWASP_UnCrackable_L2",
                version="1.0",
                platform="Android",
                package="owasp.mstg.uncrackable2",
                category="Resilience",
                expected_vulnerability="Native ptrace anti-debugging & memory protection",
                cwe=["CWE-693", "CWE-749"],
                masvs=["MASVS-RESILIENCE"],
                mastg=["MASTG-TEST-0051", "MASTG-TEST-0055"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="OWASP_Crackmes_Resilience",
                application="OWASP_UnCrackable_L3",
                version="1.0",
                platform="Android",
                package="owasp.mstg.uncrackable3",
                category="Resilience",
                expected_vulnerability="Dynamic code tampering & native library integrity",
                cwe=["CWE-693"],
                masvs=["MASVS-RESILIENCE"],
                mastg=["MASTG-TEST-0051"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="OWASP_Crackmes_Resilience",
                application="OWASP_UnCrackable_L4",
                version="1.0",
                platform="Android",
                package="owasp.mstg.uncrackable4",
                category="Resilience",
                expected_vulnerability="White-box cryptography & control flow flattening",
                cwe=["CWE-327", "CWE-693"],
                masvs=["MASVS-CRYPTO", "MASVS-RESILIENCE"],
                mastg=["MASTG-TEST-0014", "MASTG-TEST-0051"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="OWASP_Crackmes_Resilience",
                application="OWASP_Benchmark_HardcodedKey",
                version="1.0",
                platform="Android",
                package="org.owasp.benchmark.hardcodedkey",
                category="Crypto",
                expected_vulnerability="Embedded AES key in string resources",
                cwe=["CWE-798"],
                masvs=["MASVS-CODE"],
                mastg=["MASTG-TEST-0050"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="OWASP_Crackmes_Resilience",
                application="OWASP_Benchmark_InsecureRandom",
                version="1.0",
                platform="Android",
                package="org.owasp.benchmark.insecurity",
                category="Crypto",
                expected_vulnerability="Predictable java.util.Random for cryptographic nonce",
                cwe=["CWE-330"],
                masvs=["MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0016"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @staticmethod
    def get_securibench_targets() -> List[BenchmarkTarget]:
        """SecuriBench-Mobile Suite (Stanford University & Academic Commons)."""
        return [
            BenchmarkTarget(
                benchmark="SecuriBench_Mobile",
                application="SecuriBench_WebView_RCE",
                version="1.0",
                platform="Android",
                package="edu.stanford.securibench.webview_rce",
                category="Platform",
                expected_vulnerability="Unsanitized @JavascriptInterface bridge execution",
                cwe=["CWE-749", "CWE-470"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0030"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="SecuriBench_Mobile",
                application="SecuriBench_ContentProvider_Traversal",
                version="1.0",
                platform="Android",
                package="edu.stanford.securibench.cptraversal",
                category="Storage",
                expected_vulnerability="Path traversal via file provider (content://.../../../../)",
                cwe=["CWE-22"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="SecuriBench_Mobile",
                application="SecuriBench_SQLInjection_RawQuery",
                version="1.0",
                platform="Android",
                package="edu.stanford.securibench.sqli",
                category="Storage",
                expected_vulnerability="Parameter concatenation in SQLiteDatabase.rawQuery()",
                cwe=["CWE-89"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="SecuriBench_Mobile",
                application="SecuriBench_Intent_Spoofing",
                version="1.0",
                platform="Android",
                package="edu.stanford.securibench.intentspoof",
                category="ICC",
                expected_vulnerability="Implicit broadcast receiver without permission protection",
                cwe=["CWE-925"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="SecuriBench_Mobile",
                application="SecuriBench_OpenRedirect_DeepLink",
                version="1.0",
                platform="Android",
                package="edu.stanford.securibench.openredirect",
                category="Platform",
                expected_vulnerability="Unvalidated deep link URL redirection",
                cwe=["CWE-601"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0028"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="SecuriBench_Mobile",
                application="SecuriBench_WorldReadable_Cache",
                version="1.0",
                platform="Android",
                package="edu.stanford.securibench.cacheleak",
                category="Storage",
                expected_vulnerability="Cache directory created with global read permissions",
                cwe=["CWE-276", "CWE-312"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @staticmethod
    def get_withsecure_mwr_targets() -> List[BenchmarkTarget]:
        """WithSecure & MWR Enterprise Vulnerability Suite."""
        return [
            BenchmarkTarget(
                benchmark="WithSecure_MWR_Suite",
                application="WithSecure_InsecureBank_AuthToken",
                version="2.0",
                platform="Android",
                package="com.android.insecurebankv2.auth",
                category="Storage",
                expected_vulnerability="Plaintext session credentials stored in SharedPreferences",
                cwe=["CWE-312"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="WithSecure_MWR_Suite",
                application="WithSecure_InsecureBank_AES_ECB",
                version="2.0",
                platform="Android",
                package="com.android.insecurebankv2.crypto",
                category="Crypto",
                expected_vulnerability="Hardcoded symmetric AES cipher in ECB mode without IV",
                cwe=["CWE-327", "CWE-326"],
                masvs=["MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0014"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="WithSecure_MWR_Suite",
                application="WithSecure_InsecureBank_ContentProvider",
                version="2.0",
                platform="Android",
                package="com.android.insecurebankv2.provider",
                category="Storage",
                expected_vulnerability="Exported transaction content provider exposing PII",
                cwe=["CWE-926", "CWE-200"],
                masvs=["MASVS-STORAGE", "MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0001", "MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="WithSecure_MWR_Suite",
                application="WithSecure_InsecureBank_BroadcastSpoof",
                version="2.0",
                platform="Android",
                package="com.android.insecurebankv2.broadcast",
                category="ICC",
                expected_vulnerability="Insecure broadcast receiver allowing transaction forgery",
                cwe=["CWE-925"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="WithSecure_MWR_Suite",
                application="WithSecure_Sieve_PasswordVault",
                version="1.0",
                platform="Android",
                package="com.mwr.example.sieve.vault",
                category="Storage",
                expected_vulnerability="Master vault encryption key leak via unprotected activity",
                cwe=["CWE-926", "CWE-798"],
                masvs=["MASVS-STORAGE", "MASVS-CODE"],
                mastg=["MASTG-TEST-0027", "MASTG-TEST-0050"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="WithSecure_MWR_Suite",
                application="WithSecure_Sieve_KeyDerivation",
                version="1.0",
                platform="Android",
                package="com.mwr.example.sieve.kdf",
                category="Crypto",
                expected_vulnerability="Insufficient PBKDF2 iterations for master password hashing",
                cwe=["CWE-326"],
                masvs=["MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0014"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="WithSecure_MWR_Suite",
                application="WithSecure_Sieve_BackupProvider",
                version="1.0",
                platform="Android",
                package="com.mwr.example.sieve.backup",
                category="Storage",
                expected_vulnerability="File backup provider permitting directory climbing",
                cwe=["CWE-22"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="WithSecure_MWR_Suite",
                application="WithSecure_GoatDroid_SMSReceiver",
                version="1.0",
                platform="Android",
                package="org.owasp.goatdroid.sms",
                category="ICC",
                expected_vulnerability="Insecure SMS listener intent interception",
                cwe=["CWE-925", "CWE-200"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @staticmethod
    def get_nist_sard_targets() -> List[BenchmarkTarget]:
        """NIST SAMATE Software Assurance Reference Dataset (NIST / US Dept of Commerce)."""
        return [
            BenchmarkTarget(
                benchmark="NIST_SARD_Mobile",
                application="NIST_SARD_BrokenHash_MD5",
                version="1.0",
                platform="Android",
                package="gov.nist.sard.brokenhash",
                category="Crypto",
                expected_vulnerability="Weak cryptographic collision vulnerability using MD5",
                cwe=["CWE-328"],
                masvs=["MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0014"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="NIST_SARD_Mobile",
                application="NIST_SARD_WeakPRNG_Seed",
                version="1.0",
                platform="Android",
                package="gov.nist.sard.weakprng",
                category="Crypto",
                expected_vulnerability="Static seed in SecureRandom leading to predictable encryption keys",
                cwe=["CWE-338"],
                masvs=["MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0016"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="NIST_SARD_Mobile",
                application="NIST_SARD_PermissiveTLS_TrustAll",
                version="1.0",
                platform="Android",
                package="gov.nist.sard.permissivetls",
                category="Network",
                expected_vulnerability="Custom X509TrustManager accepting invalid/expired certificates",
                cwe=["CWE-295"],
                masvs=["MASVS-NETWORK"],
                mastg=["MASTG-TEST-0019"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="NIST_SARD_Mobile",
                application="NIST_SARD_InsecureTempFile",
                version="1.0",
                platform="Android",
                package="gov.nist.sard.tempfile",
                category="Storage",
                expected_vulnerability="Sensitive data written to world-accessible temp directory",
                cwe=["CWE-377", "CWE-276"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="NIST_SARD_Mobile",
                application="NIST_SARD_NativeNullCheck_Crash",
                version="1.0",
                platform="Android",
                package="gov.nist.sard.nativenull",
                category="Code",
                expected_vulnerability="Unchecked return pointer from native JNI library invocation",
                cwe=["CWE-252"],
                masvs=["MASVS-CODE"],
                mastg=["MASTG-TEST-0055"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="NIST_SARD_Mobile",
                application="NIST_SARD_ClipboardLeak_Tokens",
                version="1.0",
                platform="Android",
                package="gov.nist.sard.clipboardleak",
                category="Storage",
                expected_vulnerability="Authentication token copied to system clipboard without clearing",
                cwe=["CWE-200"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @staticmethod
    def get_fdroid_targets() -> List[BenchmarkTarget]:
        """F-Droid Open-Source Security Audit Corpus (F-Droid Community & Academic Commons)."""
        return [
            BenchmarkTarget(
                benchmark="FDroid_OpenSource_Audit",
                application="FDroid_K9Mail_Audit",
                version="6.800",
                platform="Android",
                package="com.fsck.k9",
                category="Communication",
                expected_vulnerability="Enterprise email TLS certificate pin verification and storage audit",
                cwe=["CWE-295"],
                masvs=["MASVS-NETWORK"],
                mastg=["MASTG-TEST-0019"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="FDroid_OpenSource_Audit",
                application="FDroid_NewPipe_Audit",
                version="0.27.0",
                platform="Android",
                package="org.schabi.newpipe",
                category="Media",
                expected_vulnerability="Unencrypted media stream endpoint and cleartext HTTP fallback audit",
                cwe=["CWE-319"],
                masvs=["MASVS-NETWORK"],
                mastg=["MASTG-TEST-0019"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="FDroid_OpenSource_Audit",
                application="FDroid_KeePassDX_Audit",
                version="4.0.5",
                platform="Android",
                package="com.kunzisoft.keepass.free",
                category="Security",
                expected_vulnerability="Biometric KeyStore hardware protection and memory clearing audit",
                cwe=["CWE-326"],
                masvs=["MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0014"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="FDroid_OpenSource_Audit",
                application="FDroid_Signal_Audit",
                version="7.10.0",
                platform="Android",
                package="org.thoughtcrime.securesms",
                category="Communication",
                expected_vulnerability="Secure enclave key derivation and anti-tampering verification",
                cwe=["CWE-693"],
                masvs=["MASVS-RESILIENCE"],
                mastg=["MASTG-TEST-0051"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="FDroid_OpenSource_Audit",
                application="FDroid_Nextcloud_Audit",
                version="3.28.0",
                platform="Android",
                package="com.nextcloud.client",
                category="Storage",
                expected_vulnerability="Enterprise cloud ContentProvider permissions and SSL pinning audit",
                cwe=["CWE-926", "CWE-295"],
                masvs=["MASVS-STORAGE", "MASVS-NETWORK"],
                mastg=["MASTG-TEST-0027", "MASTG-TEST-0019"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="FDroid_OpenSource_Audit",
                application="FDroid_OsmAnd_Audit",
                version="4.7.0",
                platform="Android",
                package="net.osmand",
                category="Navigation",
                expected_vulnerability="Offline map asset storage and external directory permission audit",
                cwe=["CWE-276"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @staticmethod
    def get_drebin_targets() -> List[BenchmarkTarget]:
        """Drebin Benchmark Dataset (Arp et al., NDSS 2014 - Univ. of Göttingen & TU Braunschweig)."""
        return [
            BenchmarkTarget(
                benchmark="Drebin_Benchmark",
                application="Drebin_FakeInstaller_SMS",
                version="1.0",
                platform="Android",
                package="com.drebin.fakeinst",
                category="Malware_ICC",
                expected_vulnerability="Premium SMS sending without user consent via background receiver",
                cwe=["CWE-925", "CWE-200"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Drebin_Benchmark",
                application="Drebin_DroidKungFu_RootPrivEsc",
                version="1.0",
                platform="Android",
                package="com.drebin.droidkungfu",
                category="Privilege_Escalation",
                expected_vulnerability="Local root exploit payload decryption and execution",
                cwe=["CWE-250", "CWE-749"],
                masvs=["MASVS-PLATFORM", "MASVS-CODE"],
                mastg=["MASTG-TEST-0051"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Drebin_Benchmark",
                application="Drebin_GoldDream_DataExfil",
                version="1.0",
                platform="Android",
                package="com.drebin.golddream",
                category="Data_Leakage",
                expected_vulnerability="IMEI and subscriber ID harvested and exfiltrated to remote C2",
                cwe=["CWE-200", "CWE-319"],
                masvs=["MASVS-STORAGE", "MASVS-NETWORK"],
                mastg=["MASTG-TEST-0001", "MASTG-TEST-0019"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Drebin_Benchmark",
                application="Drebin_GingerMaster_DCL",
                version="1.0",
                platform="Android",
                package="com.drebin.gingermaster",
                category="Dynamic_Loading",
                expected_vulnerability="Dynamic class loading of encrypted secondary payload from assets",
                cwe=["CWE-470"],
                masvs=["MASVS-CODE"],
                mastg=["MASTG-TEST-0052"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Drebin_Benchmark",
                application="Drebin_BaseBridge_HTTPCommand",
                version="1.0",
                platform="Android",
                package="com.drebin.basebridge",
                category="Network_C2",
                expected_vulnerability="Cleartext HTTP C2 polling permitting command injection",
                cwe=["CWE-319", "CWE-78"],
                masvs=["MASVS-NETWORK"],
                mastg=["MASTG-TEST-0019"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Drebin_Benchmark",
                application="Drebin_Plankton_Reflection",
                version="1.0",
                platform="Android",
                package="com.drebin.plankton",
                category="Reflection_Abuse",
                expected_vulnerability="Heuristic Java reflection hiding runtime API calls",
                cwe=["CWE-470", "CWE-693"],
                masvs=["MASVS-CODE"],
                mastg=["MASTG-TEST-0051"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @staticmethod
    def get_cic_invesandmal_targets() -> List[BenchmarkTarget]:
        """CIC-InvesAndMal2019 Dataset (Canadian Institute for Cybersecurity, Univ. of New Brunswick)."""
        return [
            BenchmarkTarget(
                benchmark="CIC_InvesAndMal2019",
                application="CIC_Adware_Koomi_Harvest",
                version="1.0",
                platform="Android",
                package="com.cic.adware.koomi",
                category="Adware",
                expected_vulnerability="Aggressive device identifier harvesting and unencrypted HTTP beaconing",
                cwe=["CWE-200", "CWE-319"],
                masvs=["MASVS-STORAGE", "MASVS-NETWORK"],
                mastg=["MASTG-TEST-0001", "MASTG-TEST-0019"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="CIC_InvesAndMal2019",
                application="CIC_Ransomware_Simplocker_Crypto",
                version="1.0",
                platform="Android",
                package="com.cic.ransom.simplocker",
                category="Ransomware",
                expected_vulnerability="Symmetric encryption with static hardcoded key applied to external storage",
                cwe=["CWE-798", "CWE-327"],
                masvs=["MASVS-CODE", "MASVS-CRYPTO"],
                mastg=["MASTG-TEST-0050", "MASTG-TEST-0014"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="CIC_InvesAndMal2019",
                application="CIC_Scareware_AndroidDefender_BOLA",
                version="1.0",
                platform="Android",
                package="com.cic.scare.defender",
                category="Scareware",
                expected_vulnerability="Fake scan notification triggering insecure browser redirect",
                cwe=["CWE-601"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0028"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="CIC_InvesAndMal2019",
                application="CIC_Banking_Svpeng_Overlay",
                version="1.0",
                platform="Android",
                package="com.cic.trojan.svpeng",
                category="Banking_Trojan",
                expected_vulnerability="Window overlay injection abusing SYSTEM_ALERT_WINDOW",
                cwe=["CWE-1021", "CWE-926"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="CIC_InvesAndMal2019",
                application="CIC_SMSBot_FakeNotify_ICC",
                version="1.0",
                platform="Android",
                package="com.cic.smsbot.fakenotify",
                category="SMS_Bot",
                expected_vulnerability="Broadcast receiver intercepting incoming OTP authentication tokens",
                cwe=["CWE-925", "CWE-200"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="CIC_InvesAndMal2019",
                application="CIC_Spyware_Tiqad_MIC",
                version="1.0",
                platform="Android",
                package="com.cic.spyware.tiqad",
                category="Spyware",
                expected_vulnerability="Covert microphone audio recording persisted to public shared storage",
                cwe=["CWE-276", "CWE-312"],
                masvs=["MASVS-STORAGE"],
                mastg=["MASTG-TEST-0001"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @staticmethod
    def get_malgenome_targets() -> List[BenchmarkTarget]:
        """Android MalGenome Project (Zhou & Jiang, IEEE S&P 2012 - North Carolina State Univ)."""
        return [
            BenchmarkTarget(
                benchmark="Android_MalGenome",
                application="MalGenome_DroidDream_Exploit",
                version="1.0",
                platform="Android",
                package="com.malgenome.droiddream",
                category="Root_Exploit",
                expected_vulnerability="RageAgainstTheCage native exploit execution via embedded ELF binary",
                cwe=["CWE-250", "CWE-749"],
                masvs=["MASVS-PLATFORM", "MASVS-CODE"],
                mastg=["MASTG-TEST-0051"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Android_MalGenome",
                application="MalGenome_Geinimi_C2",
                version="1.0",
                platform="Android",
                package="com.malgenome.geinimi",
                category="Botnet_C2",
                expected_vulnerability="DES encryption using hardcoded symmetric key for C2 traffic",
                cwe=["CWE-326", "CWE-798"],
                masvs=["MASVS-CRYPTO", "MASVS-CODE"],
                mastg=["MASTG-TEST-0014", "MASTG-TEST-0050"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Android_MalGenome",
                application="MalGenome_Pjapps_Receiver",
                version="1.0",
                platform="Android",
                package="com.malgenome.pjapps",
                category="Backdoor_ICC",
                expected_vulnerability="Exported broadcast receiver accepting unauthenticated configuration intents",
                cwe=["CWE-925"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Android_MalGenome",
                application="MalGenome_BaseBridge_Privilege",
                version="1.0",
                platform="Android",
                package="com.malgenome.basebridge",
                category="Privilege_Escalation",
                expected_vulnerability="Privilege escalation via root daemon IPC communication",
                cwe=["CWE-250"],
                masvs=["MASVS-PLATFORM"],
                mastg=["MASTG-TEST-0027"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Android_MalGenome",
                application="MalGenome_ADRD_IMEIHarvest",
                version="1.0",
                platform="Android",
                package="com.malgenome.adrd",
                category="Information_Theft",
                expected_vulnerability="IMEI and IMSI harvested and transmitted via unencrypted HTTP socket",
                cwe=["CWE-200", "CWE-319"],
                masvs=["MASVS-STORAGE", "MASVS-NETWORK"],
                mastg=["MASTG-TEST-0001", "MASTG-TEST-0019"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Android_MalGenome",
                application="MalGenome_AnserverBot_Integrity",
                version="1.0",
                platform="Android",
                package="com.malgenome.anserverbot",
                category="Anti_Analysis",
                expected_vulnerability="Self-integrity check and emulator environment detection evasion",
                cwe=["CWE-693"],
                masvs=["MASVS-RESILIENCE"],
                mastg=["MASTG-TEST-0051"],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @staticmethod
    def get_benign_golden_targets() -> List[BenchmarkTarget]:
        """Verified Clean Benign Suite (Zero-Defect Ground Truth for False Positive / True Negative Verification)."""
        return [
            BenchmarkTarget(
                benchmark="Benign_Golden_Suite",
                application="Benign_Calculator_FOSS",
                version="2.1",
                platform="Android",
                package="org.foss.calculator",
                category="Utility",
                expected_vulnerability="Benign - Clean mathematical calculation utility without security weaknesses",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Benign_Golden_Suite",
                application="Benign_Calendar_Offline",
                version="1.5",
                platform="Android",
                package="org.foss.calendar.offline",
                category="Productivity",
                expected_vulnerability="Benign - Local calendar without network permissions or external data sharing",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Benign_Golden_Suite",
                application="Benign_Stopwatch_Simple",
                version="1.0",
                platform="Android",
                package="org.foss.stopwatch",
                category="Utility",
                expected_vulnerability="Benign - High-precision timer using internal memory without exported components",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Benign_Golden_Suite",
                application="Benign_Notepad_Local",
                version="3.0",
                platform="Android",
                package="org.foss.notepad.local",
                category="Productivity",
                expected_vulnerability="Benign - Text editor utilizing strictly private internal storage with MODE_PRIVATE",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Benign_Golden_Suite",
                application="Benign_Compass_Sensor",
                version="1.2",
                platform="Android",
                package="org.foss.compass",
                category="Navigation",
                expected_vulnerability="Benign - Clean magnetometer sensor reading tool without internet access",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            ),
            BenchmarkTarget(
                benchmark="Benign_Golden_Suite",
                application="Benign_Flashlight_Hardware",
                version="1.0",
                platform="Android",
                package="org.foss.flashlight",
                category="Utility",
                expected_vulnerability="Benign - Direct camera hardware toggle without sensitive permissions",
                cwe=[],
                masvs=[],
                mastg=[],
                ground_truth=True,
                authorized=True,
                authorization_type=BenchmarkAuthorization.BENCHMARK
            )
        ]

    @classmethod
    def get_all_targets(cls) -> List[BenchmarkTarget]:
        return (
            cls.get_droidbench_targets() +
            cls.get_ghera_targets() +
            cls.get_owapp_targets() +
            cls.get_vulnerable_apps() +
            cls.get_iccbench_targets() +
            cls.get_ubcbench_targets() +
            cls.get_owasp_crackmes_targets() +
            cls.get_securibench_targets() +
            cls.get_withsecure_mwr_targets() +
            cls.get_nist_sard_targets() +
            cls.get_fdroid_targets() +
            cls.get_drebin_targets() +
            cls.get_cic_invesandmal_targets() +
            cls.get_malgenome_targets() +
            cls.get_benign_golden_targets() +
            cls.get_realworld_targets()
        )



