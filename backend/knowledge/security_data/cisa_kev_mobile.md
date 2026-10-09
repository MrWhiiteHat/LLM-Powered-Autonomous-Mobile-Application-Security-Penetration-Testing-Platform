# CISA Known Exploited Vulnerabilities - Mobile Platform subset

This catalog lists vulnerabilities that have active exploits in the wild affecting mobile platforms.

## CVE-2026-10520: Ivanti Sentry - Ivanti Sentry OS Command Injection Vulnerability
**Description**: Ivanti Sentry (formerly known as MobileIron Sentry) contains an OS command injection vulnerability which could allow a remote unauthenticated user to achieve root-level remote code execution. This vulnerability can be successfully exploited in cases where the Sentry appliance is in an unmanaged state with its endpoints externally reachable. The use of mTLS with EPMM or restricted HTTPS access through Neurons for MDM makes interfaces inaccessible to external actors.

## CVE-2026-11645: Google Chromium V8 - Google Chromium V8 Out-of-Bounds Read and Write Vulnerability
**Description**: Google Chromium V8 out-of-bounds read and write vulnerability that could allow a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2026-45247: Mirasvit Mirasvit Full Page Cache Warmer - Mirasvit Full Page Cache Warmer Deserialization of Untrusted Data Vulnerability
**Description**: Mirasvit Full Page Cache Warmer contains a deserialization of untrusted data vulnerability that could allow unauthenticated attackers to achieve remote code execution by supplying a crafted serialized PHP object in the CacheWarmer cookie.

## CVE-2025-48595: Android Framework - Android Framework Integer Overflow Vulnerability
**Description**: Android Framework contains an integer overflow vulnerability that allows for code execution that could allow for local privilege escalation.

## CVE-2026-6973: Ivanti Endpoint Manager Mobile (EPMM) - Ivanti Endpoint Manager Mobile (EPMM) Improper Input Validation Vulnerability
**Description**: Ivanti Endpoint Manager Mobile (EPMM) contains an improper input validation vulnerability that allows a remotely authenticated user with administrative access to achieve remote code execution.

## CVE-2024-7399: Samsung MagicINFO 9 Server - Samsung MagicINFO 9 Server Path Traversal Vulnerability
**Description**: Samsung MagicINFO 9 Server contains a path traversal vulnerability that could allow an attacker to write arbitrary files as system authority.

## CVE-2026-1340: Ivanti Endpoint Manager Mobile (EPMM) - Ivanti Endpoint Manager Mobile (EPMM) Code Injection Vulnerability
**Description**: Ivanti Endpoint Manager Mobile (EPMM) contains a code injection vulnerability that could allow attackers to achieve unauthenticated remote code execution.

## CVE-2026-5281: Google Dawn - Google Dawn Use-After-Free Vulnerability
**Description**: Google Dawn contains an use-after-free vulnerability that could allow a remote attacker who had compromised the renderer process to execute arbitrary code via a crafted HTML page. This vulnerability could affect multiple Chromium-based products including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2025-54068: Laravel Livewire - Laravel Livewire Code Injection Vulnerability
**Description**: Laravel Livewire contain a code injection vulnerability that could allow unauthenticated attackers to achieve remote command execution in specific scenarios.

## CVE-2025-43510: Apple Multiple Products - Apple Multiple Products Improper Locking Vulnerability
**Description**: Apple watchOS, iOS, iPadOS, macOS, visionOS, and tvOS contain an improper locking vulnerability that could allow a malicious application to cause unexpected changes in memory shared between processes.

## CVE-2025-43520: Apple Multiple Products - Apple Multiple Products Classic Buffer Overflow Vulnerability
**Description**: Apple watchOS, iOS, iPadOS, macOS, visionOS, and tvOS contain a classic buffer overflow vulnerability which could allow a malicious application to cause unexpected system termination or write kernel memory.

## CVE-2025-31277: Apple Multiple Products - Apple Multiple Products Buffer Overflow Vulnerability
**Description**: Apple Safari, iOS, watchOS, visionOS, iPadOS, macOS, and tvOS contain a buffer overflow vulnerability that could allow the processing of maliciously crafted web content which may lead to memory corruption.

## CVE-2026-3910: Google Chromium V8 - Google Chromium V8 Improper Restriction of Operations Within the Bounds of a Memory Buffer Vulnerability
**Description**: Google Chromium V8 contains an improper restriction of operations within the bounds of a memory buffer vulnerability that could allow a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2026-3909: Google Skia - Google Skia Out-of-Bounds Write Vulnerability
**Description**: Google Skia contains an out-of-bounds write vulnerability that could allow a remote attacker to perform out of bounds memory access via a crafted HTML page. This vulnerability affects Google Chrome and ChromeOS, Android, Flutter, and possibly other products.

## CVE-2023-43000: Apple Multiple Products - Apple Multiple products Use-After-Free Vulnerability
**Description**: Apple macOS, iOS, iPadOS, and Safari 16.6 contain a use-after-free vulnerability due to the processing of maliciously crafted web content that may lead to memory corruption.

## CVE-2021-30952: Apple Multiple Products - Apple Multiple Products Integer Overflow or Wraparound Vulnerability
**Description**: Apple tvOS, macOS, Safari, iPadOS and watchOS contain an integer overflow or wraparound vulnerability due to the processing of maliciously crafted web content that may lead to arbitrary code execution.

## CVE-2023-41974: Apple iOS and iPadOS - Apple iOS and iPadOS Use-After-Free Vulnerability
**Description**: Apple iOS and iPadOS contain a use-after-free vulnerability. An app may be able to execute arbitrary code with kernel privileges.

## CVE-2026-21385: Qualcomm Multiple Chipsets - Qualcomm Multiple Chipsets Memory Corruption Vulnerability
**Description**: Multiple Qualcomm chipsets contain a memory corruption vulnerability while using alignments for memory allocation. 

## CVE-2026-2441: Google Chromium - Google Chromium CSS Use-After-Free Vulnerability
**Description**: Google Chromium CSS contains a use-after-free vulnerability that could allow a remote attacker to potentially exploit heap corruption via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2026-20700: Apple Multiple Products - Apple Multiple Buffer Overflow Vulnerability
**Description**: Apple iOS, macOS, tvOS, watchOS, and visionOS contain an improper restriction of operations within the bounds of a memory buffer vulnerability that could allow an attacker with memory write the capability to execute arbitrary code.

## CVE-2026-1281: Ivanti Endpoint Manager Mobile (EPMM) - Ivanti Endpoint Manager Mobile (EPMM) Code Injection Vulnerability
**Description**: Ivanti Endpoint Manager Mobile (EPMM) contains a code injection vulnerability that could allow attackers to achieve unauthenticated remote code execution.

## CVE-2026-24858: Fortinet Multiple Products - Fortinet Multiple Products Authentication Bypass Using an Alternate Path or Channel Vulnerability
**Description**: Fortinet FortiAnalyzer, FortiManager, FortiOS, and FortiProxy contain an authentication bypass using an alternate path or channel that could allow an attacker with a FortiCloud account and a registered device to log into other devices registered to other accounts, if FortiCloud SSO authentication is enabled on those devices.

## CVE-2025-14733: WatchGuard Firebox - WatchGuard Firebox Out of Bounds Write Vulnerability
**Description**: WatchGuard Fireware OS iked process contains an out of bounds write vulnerability in the OS iked process. This vulnerability may allow a remote unauthenticated attacker to execute arbitrary code and affects both the mobile user VPN with IKEv2 and the branch office VPN using IKEv2 when configured with a dynamic gateway peer.

## CVE-2025-59718: Fortinet Multiple Products - Fortinet Multiple Products Improper Verification of Cryptographic Signature Vulnerability
**Description**: Fortinet FortiOS, FortiSwitchMaster, FortiProxy, and FortiWeb contain an improper verification of cryptographic signature vulnerability that may allow an unauthenticated attacker to bypass the FortiCloud SSO login authentication via a crafted SAML message. Please be aware that CVE-2025-59719 pertains to the same problem and is mentioned in the same vendor advisory. Ensure to apply all patches mentioned in the advisory.

## CVE-2025-43529: Apple Multiple Products - Apple Multiple Products Use-After-Free WebKit Vulnerability
**Description**: Apple iOS, iPadOS, macOS, and other Apple products contain a use-after-free vulnerability in WebKit. Processing maliciously crafted web content may lead to memory corruption. This vulnerability could impact HTML parsers that use WebKit, including but not limited to Apple Safari and non-Apple products which rely on WebKit for HTML processing.

## CVE-2025-14174: Google Chromium - Google Chromium Out of Bounds Memory Access Vulnerability
**Description**: Google Chromium contains an out of bounds memory access vulnerability in ANGLE that could allow a remote attacker to perform out of bounds memory access via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2025-48633: Android Framework - Android Framework Information Disclosure Vulnerability
**Description**: Android Framework contains an unspecified vulnerability that allows for information disclosure.

## CVE-2025-48572: Android Framework - Android Framework Privilege Escalation Vulnerability
**Description**: Android Framework contains an unspecified vulnerability that allows for privilege escalation.

## CVE-2025-13223: Google Chromium V8 - Google Chromium V8 Type Confusion Vulnerability
**Description**: Google Chromium V8 contains a type confusion vulnerability that allows for heap corruption.

## CVE-2025-21042: Samsung Mobile Devices - Samsung Mobile Devices Out-of-Bounds Write Vulnerability
**Description**: Samsung mobile devices contain an out-of-bounds write vulnerability in libimagecodec.quram.so. This vulnerability could allow remote attackers to execute arbitrary code.

## CVE-2022-48503: Apple Multiple Products - Apple Multiple Products Unspecified Vulnerability
**Description**: Apple macOS, iOS, tvOS, Safari, and watchOS contain an unspecified vulnerability in JavaScriptCore that when processing web content may lead to arbitrary code execution. The impacted product could be end-of-life (EoL) and/or end-of-service (EoS). Users should discontinue product utilization.

## CVE-2025-21043: Samsung Mobile Devices - Samsung Mobile Devices Out-of-Bounds Write Vulnerability
**Description**: Samsung mobile devices contain an out-of-bounds write vulnerability in libimagecodec.quram.so which allows remote attackers to execute arbitrary code.

## CVE-2025-20352: Cisco IOS and IOS XE - Cisco IOS and IOS XE Software SNMP Denial of Service and Remote Code Execution Vulnerability
**Description**: Cisco IOS and IOS XE contains a stack-based buffer overflow vulnerability in the Simple Network Management Protocol (SNMP) subsystem that could allow for denial of service or remote code execution. A successful exploit could allow a low-privileged attacker to cause the affected system to reload, resulting in a DoS condition, or allow a high-privileged attacker to execute arbitrary code as the root user and obtain full control of the affected system.

## CVE-2025-10585: Google Chromium V8 - Google Chromium V8 Type Confusion Vulnerability
**Description**: Google Chromium contains a type confusion vulnerability in the V8 JavaScript and WebAssembly engine.

## CVE-2025-48543: Android Runtime - Android Runtime Use-After-Free Vulnerability
**Description**: Android Runtime contains a use-after-free vulnerability potentially allowing a chrome sandbox escape leading to local privilege escalation.

## CVE-2025-43300: Apple iOS, iPadOS, and macOS - Apple iOS, iPadOS, and macOS Out-of-Bounds Write Vulnerability
**Description**: Apple iOS, iPadOS, and macOS contain an out-of-bounds write vulnerability in the Image I/O framework.

## CVE-2025-6558: Google Chromium - Google Chromium ANGLE and GPU Improper Input Validation Vulnerability
**Description**: Google Chromium contains an improper input validation vulnerability in ANGLE and GPU. This vulnerability could allow a remote attacker to potentially perform a sandbox escape via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2025-6554: Google Chromium V8 - Google Chromium V8 Type Confusion Vulnerability
**Description**: Google Chromium V8 contains a type confusion vulnerability that could allow a remote attacker to perform arbitrary read/write via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2019-6693: Fortinet FortiOS - Fortinet FortiOS Use of Hard-Coded Credentials Vulnerability
**Description**: Fortinet FortiOS contains a use of hard-coded credentials vulnerability that could allow an attacker to cipher sensitive data in FortiOS configuration backup file via knowledge of the hard-coded key. 

## CVE-2025-43200: Apple Multiple Products - Apple Multiple Products Unspecified Vulnerability
**Description**: Apple iOS, iPadOS, macOS, watchOS, and visionOS, contain an unspecified vulnerability when processing a maliciously crafted photo or video shared via an iCloud Link.

## CVE-2025-5419: Google Chromium V8 - Google Chromium V8 Out-of-Bounds Read and Write Vulnerability
**Description**: Google Chromium V8 contains an out-of-bounds read and write vulnerability that could allow a remote attacker to potentially exploit heap corruption via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2025-21479: Qualcomm Multiple Chipsets - Qualcomm Multiple Chipsets Incorrect Authorization Vulnerability
**Description**: Multiple Qualcomm chipsets contain an incorrect authorization vulnerability. This vulnerability allows for memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

## CVE-2025-21480: Qualcomm Multiple Chipsets - Qualcomm Multiple Chipsets Incorrect Authorization Vulnerability
**Description**: Multiple Qualcomm chipsets contain an incorrect authorization vulnerability. This vulnerability allows for memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

## CVE-2025-27038: Qualcomm Multiple Chipsets - Qualcomm Multiple Chipsets Use-After-Free Vulnerability
**Description**: Multiple Qualcomm chipsets contain a use-after-free vulnerability. This vulnerability allows for memory corruption while rendering graphics using Adreno GPU drivers in Chrome.

## CVE-2025-4632: Samsung MagicINFO 9 Server - Samsung MagicINFO 9 Server Path Traversal Vulnerability
**Description**: Samsung MagicINFO 9 Server contains a path traversal vulnerability that allows an attacker to write arbitrary file as system authority.

## CVE-2025-4428: Ivanti Endpoint Manager Mobile (EPMM) - Ivanti Endpoint Manager Mobile (EPMM) Code Injection Vulnerability
**Description**: Ivanti Endpoint Manager Mobile (EPMM) contains a code injection vulnerability in the API component that allows an authenticated attacker to remotely execute arbitrary code via crafted API requests. This vulnerability results from an insecure implementation of the Hibernate Validator open-source library, as represented by CVE-2025-35036.

## CVE-2025-4427: Ivanti Endpoint Manager Mobile (EPMM) - Ivanti Endpoint Manager Mobile (EPMM) Authentication Bypass Vulnerability
**Description**: Ivanti Endpoint Manager Mobile (EPMM) contains an authentication bypass vulnerability in the API component that allows an attacker to access protected resources without proper credentials via crafted API requests. This vulnerability results from an insecure implementation of the Spring Framework open-source library.

## CVE-2025-31201: Apple Multiple Products - Apple Multiple Products Arbitrary Read and Write Vulnerability
**Description**: Apple iOS, iPadOS, macOS, and other Apple products contain an arbitrary read and write vulnerability that allows an attacker to bypass Pointer Authentication.

## CVE-2025-31200: Apple Multiple Products - Apple Multiple Products Memory Corruption Vulnerability
**Description**: Apple iOS, iPadOS, macOS, and other Apple products contain a memory corruption vulnerability that allows for code execution when processing an audio stream in a maliciously crafted media file.

## CVE-2025-2783: Google Chromium Mojo - Google Chromium Mojo Sandbox Escape Vulnerability
**Description**: Google Chromium Mojo on Windows contains a sandbox escape vulnerability caused by a logic error, which results from an incorrect handle being provided in unspecified circumstances. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2025-24472: Fortinet FortiOS and FortiProxy - Fortinet FortiOS and FortiProxy Authentication Bypass Vulnerability
**Description**:  Fortinet FortiOS and FortiProxy contain an authentication bypass vulnerability that allows a remote attacker to gain super-admin privileges via crafted CSF proxy requests.

## CVE-2025-24201: Apple Multiple Products - Apple Multiple Products WebKit Out-of-Bounds Write Vulnerability
**Description**: Apple iOS, iPadOS, macOS, and other Apple products contain an out-of-bounds write vulnerability in WebKit that may allow maliciously crafted web content to break out of Web Content sandbox. This vulnerability could impact HTML parsers that use WebKit, including but not limited to Apple Safari and non-Apple products which rely on WebKit for HTML processing.

## CVE-2025-24200: Apple iOS and iPadOS - Apple iOS and iPadOS Incorrect Authorization Vulnerability
**Description**: Apple iOS and iPadOS contains an incorrect authorization vulnerability that allows a physical attacker to disable USB Restricted Mode on a locked device.

## CVE-2025-24085: Apple Multiple Products - Apple Multiple Products Use-After-Free Vulnerability
**Description**: Apple iOS, macOS, and other Apple products contain a user-after-free vulnerability that could allow a malicious application to elevate privileges.

## CVE-2024-55591: Fortinet FortiOS and FortiProxy - Fortinet FortiOS and FortiProxy Authentication Bypass Vulnerability
**Description**: Fortinet FortiOS and FortiProxy contain an authentication bypass vulnerability that may allow an unauthenticated, remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.

## CVE-2024-55956: Cleo Multiple Products - Cleo Multiple Products Unauthenticated File Upload Vulnerability
**Description**: Cleo Harmony, VLTrader, and LexiCom, which are managed file transfer products, contain an unrestricted file upload vulnerability that could allow an unauthenticated user to import and execute arbitrary bash or PowerShell commands on the host system by leveraging the default settings of the Autorun directory.

## CVE-2024-50623: Cleo Multiple Products - Cleo Multiple Products Unrestricted File Upload Vulnerability
**Description**: Cleo Harmony, VLTrader, and LexiCom, which are managed file transfer products, contain an unrestricted file upload and download vulnerability that can lead to remote code execution with elevated privileges.

## CVE-2024-44309: Apple Multiple Products - Apple Multiple Products Cross-Site Scripting (XSS) Vulnerability
**Description**: Apple iOS, macOS, and other Apple products contain an unspecified vulnerability when processing maliciously crafted web content that may lead to a cross-site scripting (XSS) attack.

## CVE-2024-44308: Apple Multiple Products - Apple Multiple Products Code Execution Vulnerability
**Description**: Apple iOS, macOS, and other Apple products contain an unspecified vulnerability when processing maliciously crafted web content that may lead to arbitrary code execution.

## CVE-2024-43093: Android Framework - Android Framework Privilege Escalation Vulnerability
**Description**: Android Framework contains an unspecified vulnerability that allows for privilege escalation.

## CVE-2024-23113: Fortinet Multiple Products - Fortinet Multiple Products Format String Vulnerability
**Description**: Fortinet FortiOS, FortiPAM, FortiProxy, and FortiWeb contain a format string vulnerability that allows a remote, unauthenticated attacker to execute arbitrary code or commands via specially crafted requests.

## CVE-2024-43047: Qualcomm Multiple Chipsets  - Qualcomm Multiple Chipsets Use-After-Free Vulnerability
**Description**: Multiple Qualcomm chipsets contain a use-after-free vulnerability due to memory corruption in DSP Services while maintaining memory maps of HLOS memory. 

## CVE-2024-7965: Google Chromium V8 - Google Chromium V8 Inappropriate Implementation Vulnerability
**Description**: Google Chromium V8 contains an inappropriate implementation vulnerability that allows a remote attacker to potentially exploit heap corruption via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2024-7971: Google Chromium V8 - Google Chromium V8 Type Confusion Vulnerability
**Description**: Google Chromium V8 contains a type confusion vulnerability that allows a remote attacker to exploit heap corruption via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2024-36971: Android Kernel - Android Kernel Remote Code Execution Vulnerability
**Description**: Android contains an unspecified vulnerability in the kernel that allows for remote code execution. This vulnerability resides in Linux Kernel and could impact other products, including but not limited to Android OS.

## CVE-2024-32896: Android Pixel - Android Pixel Privilege Escalation Vulnerability
**Description**: Android Pixel contains an unspecified vulnerability in the firmware that allows for privilege escalation.

## CVE-2024-4610: Arm Mali GPU Kernel Driver - Arm Mali GPU Kernel Driver Use-After-Free Vulnerability
**Description**: Arm Bifrost and Valhall GPU kernel drivers contain a use-after-free vulnerability that allows a local, non-privileged user to make improper GPU memory processing operations to gain access to already freed memory.

## CVE-2024-24919: Check Point Quantum Security Gateways - Check Point Quantum Security Gateways Information Disclosure Vulnerability
**Description**: Check Point Quantum Security Gateways contain an unspecified information disclosure vulnerability. The vulnerability potentially allows an attacker to access information on Gateways connected to the internet, with IPSec VPN, Remote Access VPN or Mobile Access enabled. This issue affects several product lines from Check Point, including CloudGuard Network, Quantum Scalable Chassis, Quantum Security Gateways, and Quantum Spark Appliances.

## CVE-2024-5274: Google Chromium V8 - Google Chromium V8 Type Confusion Vulnerability
**Description**: Google Chromium V8 contains a type confusion vulnerability that allows a remote attacker to execute code via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2024-4947: Google Chromium V8 - Google Chromium V8 Type Confusion Vulnerability
**Description**: Google Chromium V8 contains a type confusion vulnerability that allows a remote attacker to execute code via a crafted HTML page.

## CVE-2024-4761: Google Chromium V8 - Google Chromium V8 Out-of-Bounds Memory Write Vulnerability
**Description**: Google Chromium V8 Engine contains an unspecified out-of-bounds memory write vulnerability via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera. 

## CVE-2024-4671: Google Chromium - Google Chromium Visuals Use-After-Free Vulnerability
**Description**: Google Chromium Visuals contains a use-after-free vulnerability that allows a remote attacker to exploit heap corruption via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2024-29748: Android Pixel - Android Pixel Privilege Escalation Vulnerability
**Description**: Android Pixel contains a privilege escalation vulnerability that allows an attacker to interrupt a factory reset triggered by a device admin app.

## CVE-2024-29745: Android Pixel - Android Pixel Information Disclosure Vulnerability
**Description**: Android Pixel contains an information disclosure vulnerability in the fastboot firmware used to support unlocking, flashing, and locking affected devices.

## CVE-2024-23225: Apple Multiple Products - Apple Multiple Products Memory Corruption Vulnerability
**Description**: Apple iOS, iPadOS, macOS, tvOS, watchOS, and visionOS kernel contain a memory corruption vulnerability that allows an attacker with arbitrary kernel read and write capability to bypass kernel memory protections.

## CVE-2024-23296: Apple Multiple Products - Apple Multiple Products Memory Corruption Vulnerability
**Description**: Apple iOS, iPadOS, macOS, tvOS, and watchOS RTKit contain a memory corruption vulnerability that allows an attacker with arbitrary kernel read and write capability to bypass kernel memory protections.

## CVE-2023-21237: Android Pixel - Android Pixel Information Disclosure Vulnerability 
**Description**: Android Pixel contains a vulnerability in the Framework component, where the UI may be misleading or insufficient, providing a means to hide a foreground service notification. This could enable a local attacker to disclose sensitive information.

## CVE-2021-36380: Sunhillo SureLine - Sunhillo SureLine OS Command Injection Vulnerablity
**Description**: Sunhillo SureLine contains an OS command injection vulnerability that allows an attacker to cause a denial-of-service or utilize the device for persistence on the network via shell metacharacters in ipAddr or dnsAddr in /cgi/networkDiag.cgi.

## CVE-2024-21762: Fortinet FortiOS - Fortinet FortiOS Out-of-Bound Write Vulnerability
**Description**: Fortinet FortiOS contains an out-of-bound write vulnerability that allows a remote unauthenticated attacker to execute code or commands via specially crafted HTTP requests.

## CVE-2023-4762: Google Chromium V8 - Google Chromium V8 Type Confusion Vulnerability
**Description**: Google Chromium V8 contains a type confusion vulnerability that allows a remote attacker to execute code via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2022-48618: Apple Multiple Products - Apple Multiple Products Memory Corruption Vulnerability
**Description**: Apple iOS, iPadOS, macOS, tvOS, and watchOS contain a time-of-check/time-of-use (TOCTOU) memory corruption vulnerability that allows an attacker with read and write capabilities to bypass Pointer Authentication.

## CVE-2024-23222: Apple Multiple Products - Apple Multiple Products WebKit Type Confusion Vulnerability
**Description**: Apple iOS, iPadOS, macOS, tvOS, and Safari WebKit contain a type confusion vulnerability that leads to code execution when processing maliciously crafted web content. This vulnerability could impact HTML parsers that use WebKit, including but not limited to Apple Safari and non-Apple products which rely on WebKit for HTML processing.

## CVE-2023-35082: Ivanti Endpoint Manager Mobile (EPMM) and MobileIron Core - Ivanti Endpoint Manager Mobile (EPMM) and MobileIron Core Authentication Bypass Vulnerability
**Description**: Ivanti Endpoint Manager Mobile (EPMM) and MobileIron Core contain an authentication bypass vulnerability that allows unauthorized users to access restricted functionality or resources of the application.

## CVE-2024-0519: Google Chromium V8 - Google Chromium V8 Out-of-Bounds Memory Access Vulnerability
**Description**: Google Chromium V8 Engine contains an out-of-bounds memory access vulnerability that allows a remote attacker to potentially exploit heap corruption via a crafted HTML page. This vulnerability could affect multiple web browsers that utilize Chromium, including, but not limited to, Google Chrome, Microsoft Edge, and Opera.

## CVE-2023-41990: Apple Multiple Products - Apple Multiple Products Code Execution Vulnerability
**Description**: Apple iOS, iPadOS, macOS, tvOS, and watchOS contain an unspecified vulnerability that allows for code execution when processing a font file.

## CVE-2023-7024: Google Chromium WebRTC - Google Chromium WebRTC Heap Buffer Overflow Vulnerability
**Description**: Google Chromium WebRTC, an open-source project providing web browsers with real-time communication, contains a heap buffer overflow vulnerability that allows a remote attacker to potentially exploit heap corruption via a crafted HTML page. This vulnerability could impact web browsers using WebRTC, including but not limited to Google Chrome.

## CVE-2023-47565: QNAP VioStor NVR - QNAP VioStor NVR OS Command Injection Vulnerability
**Description**: QNAP VioStar NVR contains an OS command injection vulnerability that allows authenticated users to execute commands via a network.

## CVE-2023-33107: Qualcomm Multiple Chipsets - Qualcomm Multiple Chipsets Integer Overflow Vulnerability
**Description**: Multiple Qualcomm chipsets contain an integer overflow vulnerability due to memory corruption in Graphics Linux while assigning shared virtual memory region during IOCTL call.

## CVE-2023-33106: Qualcomm Multiple Chipsets - Qualcomm Multiple Chipsets Use of Out-of-Range Pointer Offset Vulnerability
**Description**: Multiple Qualcomm chipsets contain a use of out-of-range pointer offset vulnerability due to memory corruption in Graphics while submitting a large list of sync points in an AUX command to the IOCTL_KGSL_GPU_AUX_COMMAND.

## CVE-2023-33063: Qualcomm Multiple Chipsets - Qualcomm Multiple Chipsets Use-After-Free Vulnerability
**Description**: Multiple Qualcomm chipsets contain a use-after-free vulnerability due to memory corruption in DSP Services during a remote call from HLOS to DSP.

## CVE-2022-22071: Qualcomm Multiple Chipsets - Qualcomm Multiple Chipsets Use-After-Free Vulnerability
**Description**: Multiple Qualcomm chipsets contain a use-after-free vulnerability when process shell memory is freed using IOCTL munmap call and process initialization is in progress.

## CVE-2023-42917: Apple Multiple Products - Apple Multiple Products WebKit Memory Corruption Vulnerability
**Description**: Apple iOS, iPadOS, macOS, and Safari WebKit contain a memory corruption vulnerability that leads to code execution when processing maliciously crafted web content. This vulnerability could impact HTML parsers that use WebKit, including but not limited to Apple Safari and non-Apple products which rely on WebKit for HTML processing.

## CVE-2023-42916: Apple Multiple Products - Apple Multiple Products WebKit Out-of-Bounds Read Vulnerability
**Description**: Apple iOS, iPadOS, macOS, and Safari WebKit contain an out-of-bounds read vulnerability that may disclose sensitive information when processing maliciously crafted web content. This vulnerability could impact HTML parsers that use WebKit, including but not limited to Apple Safari and non-Apple products which rely on WebKit for HTML processing.

## CVE-2023-6345: Google Chromium Skia - Google Skia Integer Overflow Vulnerability
**Description**: Google Chromium Skia contains an integer overflow vulnerability that allows a remote attacker, who has compromised the renderer process, to potentially perform a sandbox escape via a malicious file. This vulnerability affects Google Chrome and ChromeOS, Android, Flutter, and possibly other products.

## CVE-2023-20273: Cisco Cisco IOS XE Web UI - Cisco IOS XE Web UI Command Injection Vulnerability
**Description**: Cisco IOS XE contains a command injection vulnerability in the web user interface. When chained with CVE-2023-20198, the attacker can leverage the new local user to elevate privilege to root and write the implant to the file system. Cisco identified CVE-2023-20273 as the vulnerability exploited to deploy the implant. CVE-2021-1435, previously associated with the exploitation events, is no longer believed to be related to this activity.

## CVE-2023-20198: Cisco IOS XE Web UI - Cisco IOS XE Web UI Privilege Escalation Vulnerability
**Description**: Cisco IOS XE Web UI contains a privilege escalation vulnerability in the web user interface that could allow a remote, unauthenticated attacker to create an account with privilege level 15 access. The attacker can then use that account to gain control of the affected device.

## CVE-2023-20109: Cisco IOS and IOS XE - Cisco IOS and IOS XE Group Encrypted Transport VPN Out-of-Bounds Write Vulnerability
**Description**: Cisco IOS and IOS XE contain an out-of-bounds write vulnerability in the Group Encrypted Transport VPN (GET VPN) feature that could allow an authenticated, remote attacker who has administrative control of either a group member or a key server to execute malicious code or cause a device to crash.

## CVE-2023-42824: Apple iOS and iPadOS - Apple iOS and iPadOS Kernel Privilege Escalation Vulnerability
**Description**: Apple iOS and iPadOS contain an unspecified vulnerability that allows for local privilege escalation.

## CVE-2023-4211: Arm Mali GPU Kernel Driver - Arm Mali GPU Kernel Driver Use-After-Free Vulnerability
**Description**: Arm Mali GPU Kernel Driver contains a use-after-free vulnerability that allows a local, non-privileged user to make improper GPU memory processing operations to gain access to already freed memory.

## CVE-2023-5217: Google Chromium libvpx - Google Chromium libvpx Heap Buffer Overflow Vulnerability
**Description**: Google Chromium libvpx contains a heap buffer overflow vulnerability in vp8 encoding that allows a remote attacker to potentially exploit heap corruption via a crafted HTML page. This vulnerability could impact web browsers using libvpx, including but not limited to Google Chrome.

