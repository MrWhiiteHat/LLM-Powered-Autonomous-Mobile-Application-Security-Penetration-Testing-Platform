# MITRE ATT&CK Mobile Techniques

Reference catalog of mobile-relevant tactics, techniques, and procedures (TTPs).

## N/A: Scheduled Task/Job
Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. On Android and iOS, APIs and libraries exist to facilitate scheduling tasks to execute at a specified date, time, or interval.

On Android, the `WorkManager` API allows asynchronous tasks to be scheduled with the system. `WorkManager` was introduced to unify task scheduling on Android, using `JobScheduler`, `GcmNetworkManager`, and `AlarmManager` internally. `WorkManager` offers a lot of flexibility for scheduling, including periodically, one time, or constraint-based (e.g. only when the device is charging).(Citation: Android WorkManager)

On iOS, the `NSBackgroundActivityScheduler` API allows asynchronous tasks to be scheduled with the system. The tasks can be scheduled to be repeating or non-repeating, however, the system chooses when the tasks will be executed. The app can choose the interval for repeating tasks, or the delay between scheduling and execution for one-time tasks.(Citation: Apple NSBackgroundActivityScheduler)

## N/A: Code Injection
Adversaries may use code injection attacks to implant arbitrary code into the address space of a running application. Code is then executed or interpreted by that application. Adversaries utilizing this technique may exploit capabilities to load code in at runtime through dynamic libraries.

With root access, `ptrace` can be used to target specific applications and load shared libraries into its process memory.(Citation: Shunix Code Injection Mar 2016)(Citation: Fadeev Code Injection Aug 2018) By injecting code, an adversary may be able to gain access to higher permissions held by the targeted application by executing as the targeted application. In addition, the adversary may be able to evade detection or enable persistent access to a system under the guise of the application’s process.(Citation: Google Triada June 2019)


## N/A: Adversary-in-the-Middle
Adversaries may attempt to position themselves between two or more networked devices to support follow-on behaviors such as [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002) or [Endpoint Denial of Service](https://attack.mitre.org/techniques/T1642).  

 

[Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1638) can be achieved through several mechanisms. For example, a malicious application may register itself as a VPN client, effectively redirecting device traffic to adversary-owned resources. Registering as a VPN client requires user consent on both Android and iOS; additionally, a special entitlement granted by Apple is needed for iOS devices. Alternatively, a malicious application with escalation privileges may utilize those privileges to gain access to network traffic.   


 Specific to Android devices, adversary-in-the-disk is a type of AiTM attack where adversaries monitor and manipulate data that is exchanged between applications and external storage.(Citation: mitd_kaspersky)(Citation: mitd_checkpoint)(Citation: mitd_checkpoint_research) To accomplish this, a malicious application firsts requests for access to multimedia files on the device (`READ_EXTERNAL STORAGE` and `WRITE_EXTERNAL_STORAGE`), then the application reads data on the device and/or writes malware to the device. Though the request for access is common, when used maliciously, adversaries may access files and other sensitive data due to abusing the permission. Multiple applications were shown to be vulnerable against this attack; however, scrutiny of permissions and input validations may mitigate this attack.    

Outside of a mobile device, adversaries may be able to capture traffic by employing a rogue base station or Wi-Fi access point. These devices will allow adversaries to capture network traffic after it has left the device, while it is flowing to its destination. On a local network, enterprise techniques could be used, such as [ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002) or [DHCP Spoofing](https://attack.mitre.org/techniques/T1557/003).  

 

If applications properly encrypt their network traffic, sensitive data may not be accessible to adversaries, depending on the point of capture. For example, properly implementing Apple’s Application Transport Security (ATS) and Android’s Network Security Configuration (NSC) may prevent sensitive data leaks.(Citation: NSC_Android)

## N/A: Abuse Elevation Control Mechanism
Adversaries may circumvent mechanisms designed to control elevated privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can gain on a machine. Authorization has to be granted to specific users in order to perform tasks that are designated as higher risk. An adversary can use several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system. 

## N/A: Remote Access Software
Adversaries may use legitimate remote access software, such as `VNC`, `TeamViewer`, `AirDroid`, `AirMirror`, etc., to establish an interactive command and control channel to target mobile devices.  

Remote access applications may be installed and used post-compromise as an alternate communication channel for redundant access or as a way to establish an interactive remote session with the target device. They may also be used as a component of malware to establish a reverse connection to an adversary-controlled system or service. Installation of remote access tools may also include persistence.  

## N/A: Malicious SMS Message
Test

## N/A: Obtain Device Cloud Backups
An adversary who is able to obtain unauthorized access to or misuse authorized access to cloud backup services (e.g. Google's Android backup service or Apple's iCloud) could use that access to obtain sensitive data stored in device backups. For example, the Elcomsoft Phone Breaker product advertises the ability to retrieve iOS backup data from Apple's iCloud (Citation: Elcomsoft-EPPB). Elcomsoft also describes (Citation: Elcomsoft-WhatsApp) obtaining WhatsApp communication histories from backups stored in iCloud.

## N/A: Uninstall Malicious Application
Adversaries may include functionality in malware that uninstalls the malicious application from the device. This can be achieved by: 
 
* Abusing device owner permissions to perform silent uninstallation using device owner API calls. 
* Abusing root permissions to delete files from the filesystem. 
* Abusing the accessibility service. This requires sending an intent to the system to request uninstallation, and then abusing the accessibility service to click the proper places on the screen to confirm uninstallation.

## N/A: Indicator Removal on Host
Adversaries may delete, alter, or hide generated artifacts on a device, including files, jailbreak status, or the malicious application itself. These actions may interfere with event collection, reporting, or other notifications used to detect intrusion activity. This may compromise the integrity of mobile security solutions by causing notable events or information to go unreported.

## N/A: Supply Chain Compromise
Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.

Supply chain compromise can take place at any stage of the supply chain including:

* Manipulation of development tools
* Manipulation of a development environment
* Manipulation of source code repositories (public or private)
* Manipulation of source code in open-source dependencies
* Manipulation of software update/distribution mechanisms
* Compromised/infected system images
* Replacement of legitimate software with modified versions
* Sales of modified/counterfeit products to legitimate distributors
* Shipment interdiction

While supply chain compromise can impact any component of hardware or software, attackers looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels. Targeting may be specific to a desired victim set or malicious software may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.  Popular open source projects that are used as dependencies in many applications may also be targeted as a means to add malicious code to users of the dependency, specifically with the widespread usage of third-party advertising libraries.(Citation: Grace-Advertisement)(Citation: NowSecure-RemoteCode)

## N/A: Impersonate SS7 Nodes
Adversaries may exploit the lack of authentication in signaling system network nodes to track the location of mobile devices by impersonating a node.(Citation: Engel-SS7)(Citation: Engel-SS7-2008)(Citation: 3GPP-Security)(Citation: Positive-SS7)(Citation: CSRIC5-WG10-FinalReport) 

 

By providing the victim’s MSISDN (phone number) and impersonating network internal nodes to query subscriber information from other nodes, adversaries may use data collected from each hop to eventually determine the device’s geographical cell area or nearest cell tower.(Citation: Engel-SS7)

## N/A: Match Legitimate Name or Location
Adversaries may match or approximate the name or location of legitimate files or resources when naming/placing them. This is done for the sake of evading defenses and observation. This may be done by giving artifacts the name and icon of a legitimate, trusted application (i.e., Settings), or using a package name that matches legitimate, trusted applications (i.e., `com.google.android.gm`). 

Adversaries may also use the same icon of the file or application they are trying to mimic.


## T1425: Insecure Third-Party Libraries
No description available.

## N/A: Protected User Data
Adversaries may utilize standard operating system APIs to collect data from permission-backed data stores on a device, such as the calendar or contact list. These permissions need to be declared ahead of time. On Android, they must be included in the application’s manifest. On iOS, they must be included in the application’s `Info.plist` file.  

 

In almost all cases, the user is required to grant access to the data store that the application is trying to access. In recent OS versions, vendors have introduced additional privacy controls for users, such as the ability to grant permission to an application only while the application is being actively used by the user. 

 

If the device has been jailbroken or rooted, an adversary may be able to access [Protected User Data](https://attack.mitre.org/techniques/T1636) without the user’s knowledge or approval. 

## N/A: Asymmetric Cryptography
Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic, rather than relying on any inherent protections provided by a communication protocol. Asymmetric cryptography, also known as public key cryptography, uses a keypair per party: one public that can be freely distributed, and one private that should not be distributed. Due to how asymmetric algorithms work, the sender encrypts data with the receiver’s public key and the receiver decrypts the data with their private key. This ensures that only the intended recipient can read the encrypted data. Common public key encryption algorithms include RSA, ElGamal, and ECDSA.

For efficiency, many protocols (including SSL/TLS) use symmetric cryptography once a connection is established, but use asymmetric cryptography to establish or transmit a key. As such, these protocols are classified as [Asymmetric Cryptography](https://attack.mitre.org/techniques/T1521/002).

## N/A: Software Discovery
Adversaries may attempt to get a listing of applications that are installed on a device. Adversaries may use the information from [Software Discovery](https://attack.mitre.org/techniques/T1418) during automated discovery to shape follow-on behaviors, including whether or not to fully infect the target and/or attempts specific actions. 

 

Adversaries may attempt to enumerate applications for a variety of reasons, such as figuring out what security measures are present or to identify the presence of target applications. 

## N/A: Process Discovery
Adversaries may attempt to get information about running processes on a device. Information obtained could be used to gain an understanding of common software/applications running on devices within a network. Adversaries may use the information from [Process Discovery](https://attack.mitre.org/techniques/T1424) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. 

 

Recent Android security enhancements have made it more difficult to obtain a list of running processes. On Android 7 and later, there is no way for an application to obtain the process list without abusing elevated privileges. This is due to the Android kernel utilizing the `hidepid` mount feature. Prior to Android 7, applications could utilize the `ps` command or examine the `/proc` directory on the device.(Citation: Android-SELinuxChanges) 

 

In iOS, applications have previously been able to use the `sysctl` command to obtain a list of running processes. This functionality has been removed in later iOS versions. 

## N/A: Call Log
Adversaries may utilize standard operating system APIs to gather call log data. On Android, this can be accomplished using the Call Log Content Provider. iOS provides no standard API to access the call log. 

 

If the device has been jailbroken or rooted, an adversary may be able to access the [Call Log](https://attack.mitre.org/techniques/T1636/002) without the user’s knowledge or approval. 

## N/A: Security Software Discovery
Adversaries may attempt to get a listing of security applications and configurations that are installed on a device. This may include things such as mobile security products. Adversaries may use the information from [Security Software Discovery](https://attack.mitre.org/techniques/T1418/001) during automated discovery to shape follow-on behaviors, including whether or not to fully infect the target and/or attempt specific actions. 

## T1434: App Delivered via Email Attachment
No description available.

## N/A: Ptrace System Calls
Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process.  

Ptrace system call injection involves attaching to and modifying a running process. The ptrace system call enables a debugging process to observe and control another process (and each individual thread), including changing memory and register values.(Citation: PTRACE man) Ptrace system call injection is commonly performed by writing arbitrary code into a running process (e.g., by using `malloc`) then invoking that memory with `PTRACE_SETREGS` to set the register containing the next instruction to execute. Ptrace system call injection can also be done with `PTRACE_POKETEXT`/`PTRACE_POKEDATA`, which copy data to a specific address in the target process's memory (e.g., the current address of the next instruction).(Citation: PTRACE man)(Citation: Medium Ptrace JUL 2018)  

Ptrace system call injection may not be possible when targeting processes with high-privileges, and on some systems those that are non-child processes.(Citation: BH Linux Inject)  

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via ptrace system call injection may also evade detection from security products since the execution is masked under a legitimate process.

## N/A: Impair Defenses
Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may span both native defenses as well as supplemental capabilities installed by users or mobile endpoint administrators.

## N/A: Abuse Accessibility Features
Adversaries may abuse accessibility features in Android devices to steal sensitive data and to spread malware to other devices. Accessibility features in Android are designed to assist users with disabilities, performing a variety of tasks, such as using Action Blocks to control lightbulbs, and changing the device’s user interface, such as changing the font size and adjusting contract or colors.(Citation: Google_AndroidAcsOverview) 

One example of how adversaries abuse accessibility features is overlaying an HTML object mimicking a legitimate login screen. The user types their credentials in the overlay HTML object, which is then sent to the adversaries.(Citation: SahinSRLabs_FluBot_Dec2021)  

Another example is a malicious accessibility feature acting as a keylogger. The keylogger monitors changes on the EditText fields and sends it to the adversaries.(Citation: SahinSRLabs_FluBot_Dec2021) This method of attack is also described in [Keylogging](https://attack.mitre.org/techniques/T1417/001); whereas [Abuse Accessibility Features](https://attack.mitre.org/techniques/T1453) captures the overall abuse of accessibility features.  

## N/A: Exploitation of Remote Services
Adversaries may exploit remote services of enterprise servers, workstations, or other resources to gain unauthorized access to internal systems once inside of a network. Adversaries may exploit remote services by taking advantage of a mobile device’s access to an internal enterprise network through local connectivity or through a Virtual Private Network (VPN). Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system. 

An adversary may need to determine if the remote system is in a vulnerable state, which may be done through [Network Service Scanning](https://attack.mitre.org/techniques/T1423) or other Discovery methods. These look for common, vulnerable software that may be deployed in the network, the lack of certain patches that may indicate vulnerabilities, or security software that may be used to detect or contain remote exploitation. Servers are likely a high value target for lateral movement exploitation, but endpoint systems may also be at risk if they provide an advantage or access to additional resources.

Depending on the permissions level of the vulnerable remote service, an adversary may achieve [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1404) as a result of lateral movement exploitation as well. 

## N/A: Web Protocols
Adversaries may communicate using application layer protocols associated with web protocols traffic to avoid detection/network filtering by blending in with existing traffic. Commands to remote mobile devices, and often the results of those commands, will be embedded within the protocol traffic between the mobile client and server. 

Web protocols such as HTTP and HTTPS are used for web traffic as well as well as notification services native to mobile messaging services such as Google Cloud Messaging (GCM) and newly, Firebase Cloud Messaging (FCM), (GCM/FCM: two-way communication) and Apple Push Notification Service (APNS; one-way server-to-device).  Such notification services leverage HTTP/S via the respective API and are commonly abused on Android and iOS respectively in order blend in with routine device traffic making it difficult for enterprises to inspect. 

## N/A: Steal Application Access Token
Adversaries can steal user application access tokens as a means of acquiring credentials to access remote systems and resources. This can occur through social engineering or URI hijacking and typically requires user action to grant access, such as through a system “Open With” dialogue.  

Application access tokens are used to make authorized API requests on behalf of a user and are commonly used as a way to access resources in cloud-based applications and software-as-a-service (SaaS).(Citation: Auth0 - Why You Should Always Use Access Tokens to Secure APIs Sept 2019) OAuth is one commonly implemented framework used to issue tokens to users for access to systems. An application desiring access to cloud-based services or protected APIs can gain entry through OAuth 2.0 using a variety of authorization protocols. An example of a commonly-used sequence is Microsoft's Authorization Code Grant flow.(Citation: Microsoft Identity Platform Protocols May 2019)(Citation: Microsoft - OAuth Code Authorization flow - June 2019) An OAuth access token enables a third-party application to interact with resources containing user data in the ways requested without requiring user credentials.

## N/A: User Evasion
Adversaries may attempt to avoid detection by hiding malicious behavior from the user. By doing this, an adversary’s modifications would most likely remain installed on the device for longer, allowing the adversary to continue to operate on that device. 

While there are many ways this can be accomplished, one method is by using the device’s sensors. By utilizing the various motion sensors on a device, such as accelerometer or gyroscope, an application could detect that the device is being interacted with. That way, the application could continue to run while the device is not in use but cease operating while the user is using the device, hiding anything that would indicate malicious activity was ongoing. Accessing the sensors in this way does not require any permissions from the user, so it would be completely transparent.

## N/A: Virtualization/Sandbox Evasion
Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors after checking for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware’s behavior to disengage from the victim or conceal the core functions of the payload. They may also search for VME artifacts before dropping further payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1633) during automated discovery to shape follow-on behaviors. 

Adversaries may use several methods to accomplish [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1633) such as checking for system artifacts associated with analysis or virtualization. Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. 

## N/A: Keychain
Adversaries may collect the keychain storage data from an iOS device to acquire credentials. Keychains are the built-in way for iOS to keep track of users' passwords and credentials for many services and features such as Wi-Fi passwords, websites, secure notes, certificates, private keys, and VPN credentials.

On the device, the keychain database is stored outside of application sandboxes to prevent unauthorized access to the raw data. Standard iOS APIs allow applications access to their own keychain contained within the database. By utilizing a privilege escalation exploit or existing root access, an adversary can access the entire encrypted database.(Citation: Apple Keychain Services)(Citation: Elcomsoft Decrypt Keychain)

## N/A: Application Versioning
An adversary may push an update to a previously benign application to add malicious code. This can be accomplished by pushing an initially benign, functional application to a trusted application store, such as the Google Play Store or the Apple App Store. This allows the adversary to establish a trusted userbase that may grant permissions to the application prior to the introduction of malicious code. Then, an application update could be pushed to introduce malicious code.(Citation: android_app_breaking_bad)

This technique could also be accomplished by compromising a developer’s account. This would allow an adversary to take advantage of an existing userbase without having to establish the userbase themselves. 

## N/A: Access Sensitive Data in Device Logs
On versions of Android prior to 4.1, an adversary may use a malicious application that holds the READ_LOGS permission to obtain private keys, passwords, other credentials, or other sensitive data stored in the device's system log. On Android 4.1 and later, an adversary would need to attempt to perform an operating system privilege escalation attack to be able to access the log.

## N/A: Command and Scripting Interpreter
Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, Android is a UNIX-like OS and includes a basic [Unix Shell](https://attack.mitre.org/techniques/T1623/001) that can be accessed via the Android Debug Bridge (ADB) or Java’s `Runtime` package.

Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in [Initial Access](https://attack.mitre.org/tactics/TA0027) payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells. 

## N/A: Disable or Modify Tools
Adversaries may disable security tools to avoid potential detection of their tools and activities. This can take the form of disabling security software, modifying SELinux configuration, or other methods to interfere with security tools scanning or reporting information. This is typically done by abusing device administrator permissions or using system exploits to gain root access to the device to modify protected system files.

## N/A: Ingress Tool Transfer
Adversaries may transfer tools or other files from an external system onto a compromised device to facilitate follow-on actions. Files may be copied from an external adversary-controlled system through the command and control channel  or through alternate protocols with another tool such as FTP.

## N/A: Dynamic Resolution
Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations. This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware's communications. This algorithm can be used to dynamically adjust parameters such as the domain name, IP address, or port number the malware uses for command and control.

## N/A: Exploit via Radio Interfaces
The mobile device may be targeted for exploitation through its interface to cellular networks or other radio interfaces.

### Baseband Vulnerability Exploitation

A message sent over a radio interface (typically cellular, but potentially Bluetooth, GPS, NFC, Wi-Fi(Citation: ProjectZero-BroadcomWiFi) or other) to the mobile device could exploit a vulnerability in code running on the device(Citation: Register-BaseStation)(Citation: Weinmann-Baseband).

### Malicious SMS Message

An SMS message could contain content designed to exploit vulnerabilities in the SMS parser on the receiving device(Citation: Forbes-iPhoneSMS). An SMS message could also contain a link to a web site containing malicious content designed to exploit the device web browser. Vulnerable SIM cards may be remotely exploited and reprogrammed via SMS messages(Citation: SRLabs-SIMCard).

## N/A: Network Service Scanning
Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans from the mobile device. This technique may take advantage of the mobile device's access to an internal enterprise network either through local connectivity or through a Virtual Private Network (VPN).

## N/A: User Evasion
Adversaries may attempt to avoid detection by hiding malicious behavior from the user. By doing this, an adversary’s modifications would most likely remain installed on the device for longer, allowing the adversary to continue to operate on that device. 

While there are many ways this can be accomplished, one method is by using the device’s sensors. By utilizing the various motion sensors on a device, such as accelerometer or gyroscope, an application could detect that the device is being interacted with. That way, the application could continue to run while the device is not in use but cease operating while the user is using the device, hiding anything that would indicate malicious activity was ongoing. Accessing the sensors in this way does not require any permissions from the user, so it would be completely transparent.

## N/A: Exfiltration Over C2 Channel
Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.

## N/A: Accounts
Adversaries may utilize standard operating system APIs to gather account data. On Android, this can be accomplished by using the AccountManager API. For example, adversaries may use the `getAccounts()` method to list all accounts.(Citation: Android_AccountManager_Feb2025) On iOS, this can be accomplished by using the Keychain services.  

If the device has been jailbroken or rooted, adversaries may be able to access [Accounts](https://attack.mitre.org/techniques/T1636/005) without the users’ knowledge or approval. 

## N/A: Exploitation for Privilege Escalation
Adversaries may exploit software vulnerabilities in order to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in an application, service, within the operating system software, or kernel itself to execute adversary-controlled code. Security constructions, such as permission levels, will often hinder access to information and use of certain techniques. Adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions. 

When initially gaining access to a device, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and applications running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user- level permission to root permissions depending on the component that is vulnerable. 

## N/A: Call Control
Adversaries may make, forward, or block phone calls without user authorization. This could be used for adversary goals such as audio surveillance, blocking or forwarding calls from the device owner, or C2 communication.

Several permissions may be used to programmatically control phone calls, including:

* `ANSWER_PHONE_CALLS` - Allows the application to answer incoming phone calls(Citation: Android Permissions)
* `CALL_PHONE` - Allows the application to initiate a phone call without going through the Dialer interface(Citation: Android Permissions)
* `PROCESS_OUTGOING_CALLS` - Allows the application to see the number being dialed during an outgoing call with the option to redirect the call to a different number or abort the call altogether(Citation: Android Permissions)
* `MANAGE_OWN_CALLS` - Allows a calling application which manages its own calls through the self-managed `ConnectionService` APIs(Citation: Android Permissions)
* `BIND_TELECOM_CONNECTION_SERVICE` - Required permission when using a `ConnectionService`(Citation: Android Permissions)
* `WRITE_CALL_LOG` - Allows an application to write to the device call log, potentially to hide malicious phone calls(Citation: Android Permissions)

When granted some of these permissions, an application can make a phone call without opening the dialer first. However, if an application desires to simply redirect the user to the dialer with a phone number filled in, it can launch an Intent using `Intent.ACTION_DIAL`, which requires no specific permissions. This then requires the user to explicitly initiate the call or use some form of [Input Injection](https://attack.mitre.org/techniques/T1516) to programmatically initiate it.

## N/A: Exfiltration Over Unencrypted Non-C2 Protocol
Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.

Adversaries may opt to obfuscate this data, without the use of encryption, within network protocols that are natively unencrypted (such as HTTP, FTP, or DNS). Adversaries may employ custom or publicly available encoding/compression algorithms (such as base64) or embed data within protocol headers and fields.

## N/A: Broadcast Receivers
Adversaries may establish persistence using system mechanisms that trigger execution based on specific events. Mobile operating systems have means to subscribe to events such as receiving an SMS message, device boot completion, or other device activities. 

An intent is a message passed between Android applications or system components. Applications can register to receive broadcast intents at runtime, which are system-wide intents delivered to each app when certain events happen on the device, such as network changes or the user unlocking the screen. Malicious applications can then trigger certain actions within the app based on which broadcast intent was received. 

In addition to Android system intents, malicious applications can register for intents broadcasted by other applications. This allows the malware to respond based on actions in other applications. This behavior typically indicates a more intimate knowledge, or potentially the targeting of specific devices, users, or applications. 

In Android 8 (API level 26), broadcast intent behavior was changed, limiting the implicit intents that applications can register for in the manifest. In most cases, applications that register through the manifest will no longer receive the broadcasts. Now, applications must register context-specific broadcast receivers while the user is actively using the app.(Citation: Android Changes to System Broadcasts) 

## N/A: Commonly Used Port
Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. 

They may use commonly open ports such as

* TCP:80 (HTTP)
* TCP:443 (HTTPS)
* TCP:25 (SMTP)
* TCP/UDP:53 (DNS)

They may use the protocol associated with the port or a completely different protocol.

## N/A: Eavesdrop on Insecure Network Communication
If network traffic between the mobile device and remote servers is unencrypted or is encrypted in an insecure manner, then an adversary positioned on the network can eavesdrop on communication.(Citation: mHealth)

## N/A: Access Notifications
Adversaries may collect data within notifications sent by the operating system or other applications. Notifications may contain sensitive data such as one-time authentication codes sent over SMS, email, or other mediums. In the case of Credential Access, adversaries may attempt to intercept one-time code sent to the device. Adversaries can also dismiss notifications to prevent the user from noticing that the notification has arrived and can trigger action buttons contained within notifications.(Citation: ESET 2FA Bypass) 

## N/A: Network Traffic Capture or Redirection
An adversary may capture network traffic to and from the device to obtain credentials or other sensitive data, or redirect network traffic to flow through an adversary-controlled gateway to do the same.

A malicious app could register itself as a VPN client on Android or iOS to gain access to network packets. However, on both platforms, the user must grant consent to the app to act as a VPN client, and on iOS the app requires a special entitlement that must be granted by Apple.

Alternatively, if a malicious app is able to escalate operating system privileges, it may be able to use those privileges to gain access to network traffic.

An adversary could redirect network traffic to an adversary-controlled gateway by establishing a VPN connection or by manipulating the device's proxy settings. For example, Skycure (Citation: Skycure-Profiles) describes the ability to redirect network traffic by installing a malicious iOS Configuration Profile.

If applications encrypt their network traffic, sensitive data may not be accessible to an adversary, depending on the point of capture.

## N/A: Input Prompt
The operating system and installed applications often have legitimate needs to prompt the user for sensitive information such as account credentials, bank account information, or Personally Identifiable Information (PII). Adversaries may mimic this functionality to prompt users for sensitive information.

Compared to traditional PCs, the constrained display size of mobile devices may impair the ability to provide users with contextual information, making users more susceptible to this technique’s use.(Citation: Felt-PhishingOnMobileDevices)

Specific approaches to this technique include:

### Impersonate the identity of a legitimate application

A malicious application could impersonate the identity of a legitimate application (e.g. use the same application name and/or icon) and get installed on the device. The malicious app could then prompt the user for sensitive information.(Citation: eset-finance)

### Display a prompt on top of a running legitimate application

A malicious application could display a prompt on top of a running legitimate application to trick users into entering sensitive information into the malicious application rather than the legitimate application. Typically, the malicious application would need to know when the targeted application (and individual activity within the targeted application) is running in the foreground, so that the malicious application knows when to display its prompt. Android 5.0 and 5.1.1, respectively, increased the difficulty of determining the current foreground application through modifications to the `ActivityManager` API.(Citation: Android-getRunningTasks)(Citation: StackOverflow-getRunningAppProcesses). A malicious application can still abuse Android’s accessibility features to determine which application is currently in the foreground.(Citation: ThreatFabric Cerberus) Approaches to display a prompt include:

* A malicious application could start a new activity on top of a running legitimate application.(Citation: Felt-PhishingOnMobileDevices)(Citation: Hassell-ExploitingAndroid) Android 10 places new restrictions on the ability for an application to start a new activity on top of another application, which may make it more difficult for adversaries to utilize this technique.(Citation: Android Background)
* A malicious application could create an application overlay window on top of a running legitimate application. Applications must hold the `SYSTEM_ALERT_WINDOW` permission to create overlay windows. This permission is handled differently than typical Android permissions, and at least under certain conditions is automatically granted to applications installed from the Google Play Store.(Citation: Cloak and Dagger)(Citation: NowSecure Android Overlay)(Citation: Skycure-Accessibility) The `SYSTEM_ALERT_WINDOW` permission and its associated ability to create application overlay windows are expected to be deprecated in a future release of Android in favor of a new API.(Citation: XDA Bubbles)

### Fake device notifications

A malicious application could send fake device notifications to the user. Clicking on the device notification could trigger the malicious application to display an input prompt.(Citation: Group IB Gustuff Mar 2019)

## N/A: Exfiltration Over Alternative Protocol
Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. 

Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Different protocol channels could also include Web services such as cloud storage. Adversaries may opt to also encrypt and/or obfuscate these alternate channels. 

## N/A: Internet Connection Discovery
Adversaries may check for Internet connectivity on compromised systems. This may be performed during automated discovery and can be accomplished in numerous ways such as using `adb shell netstat` for Android.(Citation: adb_commands)

Adversaries may use the results and responses from these requests to determine if the mobile devices are capable of communicating with adversary-owned C2 servers before attempting to connect to them. The results may also be used to identify routes, redirectors, and proxy servers.

## T1460: Biometric Spoofing
No description available.

## N/A: Boot or Logon Initialization Scripts
Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts are part of the underlying operating system and are not accessible to the user unless the device has been rooted or jailbroken. 

## N/A: Execution Guardrails
Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign. Values an adversary can provide about a target system or environment to use as guardrails may include environment information such as location.(Citation: SWB Exodus March 2019)

Guardrails can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. This use of guardrails is distinct from typical [System Checks](https://attack.mitre.org/techniques/T1633/001). While use of [System Checks](https://attack.mitre.org/techniques/T1633/001) may involve checking for known sandbox values and continuing with execution only if there is no match, the use of guardrails will involve checking for an expected target-specific value and only continuing with execution if there is such a match.

## N/A: GUI Input Capture
Adversaries may mimic common operating system GUI components to prompt users for sensitive information with a seemingly legitimate prompt. The operating system and installed applications often have legitimate needs to prompt the user for sensitive information such as account credentials, bank account information, or Personally Identifiable Information (PII). Compared to traditional PCs, the constrained display size of mobile devices may impair the ability to provide users with contextual information, making users more susceptible to this technique’s use.(Citation: Felt-PhishingOnMobileDevices)

There are several approaches adversaries may use to mimic this functionality. Adversaries may impersonate the identity of a legitimate application (e.g. use the same application name and/or icon) and, when installed on the device, may prompt the user for sensitive information.(Citation: eset-finance) Adversaries may also send fake device notifications to the user that may trigger the display of an input prompt when clicked.(Citation: Group IB Gustuff Mar 2019) 

Additionally, adversaries may display a prompt on top of a running, legitimate application to trick users into entering sensitive information into a malicious application rather than the legitimate application. Typically, adversaries need to know when the targeted application and the individual activity within the targeted application is running in the foreground to display the prompt at the proper time. Adversaries can abuse Android’s accessibility features to determine which application is currently in the foreground.(Citation: ThreatFabric Cerberus) Two known approaches to displaying a prompt include:

* Adversaries start a new activity on top of a running legitimate application.(Citation: Felt-PhishingOnMobileDevices)(Citation: Hassell-ExploitingAndroid) Android 10 places new restrictions on the ability for an application to start a new activity on top of another application, which may make it more difficult for adversaries to utilize this technique.(Citation: Android Background)
* Adversaries create an application overlay window on top of a running legitimate application. Applications must hold the `SYSTEM_ALERT_WINDOW` permission to create overlay windows. This permission is handled differently than typical Android permissions and, at least under certain conditions, is automatically granted to applications installed from the Google Play Store.(Citation: Cloak and Dagger)(Citation: NowSecure Android Overlay)(Citation: Skycure-Accessibility) The `SYSTEM_ALERT_WINDOW` permission and its associated ability to create application overlay windows are expected to be deprecated in a future release of Android in favor of a new API.(Citation: XDA Bubbles)

## N/A: Access Contact List
An adversary could call standard operating system APIs from a malicious application to gather contact list (i.e., address book) data, or with escalated privileges could directly access files containing contact list data.

## N/A: Compromise Client Software Binary
Adversaries may modify system software binaries to establish persistent access to devices. System software binaries are used by the underlying operating system and users over adb or terminal emulators. 

Adversaries may make modifications to client software binaries to carry out malicious tasks when those binaries are executed. For example, malware may come with a pre-compiled malicious binary intended to overwrite the genuine one on the device. Since these binaries may be routinely executed by the system or user, the adversary can leverage this for persistent access to the device. 

## N/A: Software Packing
Adversaries may perform software packing to conceal their code. Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory. 

Utilities used to perform software packing are called packers. An example packer is FTT. A more comprehensive list of known packers is available, but adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses.

## T1445: Abuse of iOS Enterprise App Signing Key
No description available.

## N/A: Exploit SS7 to Track Device Location
An adversary could exploit signaling system vulnerabilities to track the location of mobile devices. (Citation: Engel-SS7) (Citation: Engel-SS7-2008) (Citation: 3GPP-Security) (Citation: Positive-SS7) (Citation: CSRIC5-WG10-FinalReport)

## N/A: Native API
Adversaries may use Android’s Native Development Kit (NDK) to write native functions that can achieve execution of binaries or functions. Like system calls on a traditional desktop operating system, native code achieves execution on a lower level than normal Android SDK calls.

The NDK allows developers to write native code in C or C++ that is compiled directly to machine code, avoiding all intermediate languages and steps in compilation that higher level languages, like Java, typically have. The Java Native Interface (JNI) is the component that allows Java functions in the Android app to call functions in a native library.(Citation: Google NDK Getting Started)

Adversaries may also choose to use native functions to execute malicious code since native actions are typically much more difficult to analyze than standard, non-native behaviors.(Citation: MITRE App Vetting Effectiveness)

## N/A: Deliver Malicious App via Other Means
Malicious applications are a common attack vector used by adversaries to gain a presence on mobile devices. This technique describes installing a malicious application on targeted mobile devices without involving an authorized app store (e.g., Google Play Store or Apple App Store). Adversaries may wish to avoid placing malicious applications in an authorized app store due to increased potential risk of detection or other reasons. However, mobile devices often are configured to allow application installation only from an authorized app store which would prevent this technique from working.

Delivery methods for the malicious application include:

* [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001) - Including the mobile app package as an attachment to an email message.
* [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) - Including a link to the mobile app package within an email, text message (e.g. SMS, iMessage, Hangouts, WhatsApp, etc.), web site, QR code, or other means.
* Third-Party App Store - Installed from a third-party app store (as opposed to an authorized app store that the device implicitly trusts as part of its default behavior), which may not apply the same level of scrutiny to apps as applied by an authorized app store.(Citation: IBTimes-ThirdParty)(Citation: TrendMicro-RootingMalware)(Citation: TrendMicro-FlappyBird)

Some Android malware comes with functionality to install additional applications, either automatically or when the adversary instructs it to.(Citation: android-trojan-steals-paypal-2fa)

## N/A: Remotely Wipe Data Without Authorization
An adversary who is able to obtain unauthorized access to or misuse authorized access to cloud services (e.g. Google's Android Device Manager or Apple iCloud's Find my iPhone) or to an EMM console could use that access to wipe enrolled devices (Citation: Honan-Hacking).

## N/A: Exploitation for Client Execution
Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to insecure coding practices that can lead to unanticipated behavior. Adversaries may take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility. 

Adversaries may use device-based zero-click exploits for code execution. These exploits are powerful because there is no user interaction required for code execution. 

### SMS/iMessage Delivery  

SMS and iMessage in iOS are common targets through [Drive-By Compromise](https://attack.mitre.org/techniques/T1456), [Phishing](https://attack.mitre.org/techniques/T1660), etc. Adversaries may use embed malicious links, files, etc. in SMS messages or iMessages. Mobile devices may be compromised through one-click exploits, where the victim must interact with a text message, or zero-click exploits, where no user interaction is required. 

### AirDrop 

Unique to iOS, AirDrop is a network protocol that allows iOS users to transfer files between iOS devices. Before patches from Apple were released, on iOS 13.4 and earlier, adversaries may force the Apple Wireless Direct Link (AWDL) interface to activate, then exploit a buffer overflow to gain access to the device and run as root without interaction from the user.  

## N/A: Proxy Through Victim
Adversaries may use a compromised device as a proxy server to the Internet. By utilizing a proxy, adversaries hide the true IP address of their C2 server and associated infrastructure from the destination of the network traffic. This masquerades an adversary’s traffic as legitimate traffic originating from the compromised device, which can evade IP-based restrictions and alerts on certain services, such as bank accounts and social media websites.(Citation: Threat Fabric Exobot)

The most common type of proxy is a SOCKS proxy. It can typically be implemented using standard OS-level APIs and 3rd party libraries with no indication to the user. On Android, adversaries can use the `Proxy` API to programmatically establish a SOCKS proxy connection, or lower-level APIs to interact directly with raw sockets.

## N/A: Domain Generation Algorithms
Adversaries may use [Domain Generation Algorithms](https://attack.mitre.org/techniques/T1520) (DGAs) to procedurally generate domain names for command and control communication, and other uses such as malicious application distribution.(Citation: securelist rotexy 2018)

DGAs increase the difficulty for defenders to block, track, or take over the command and control channel, as there potentially could be thousands of domains that malware can check for instructions.

## N/A: Access Calendar Entries
An adversary could call standard operating system APIs from a malicious application to gather calendar entry data, or with escalated privileges could directly access files containing calendar data.

## N/A: Rogue Wi-Fi Access Points
An adversary could set up unauthorized Wi-Fi access points or compromise existing access points and, if the device connects to them, carry out network-based attacks such as eavesdropping on or modifying network communication(Citation: NIST-SP800153)(Citation: Kaspersky-DarkHotel).

## N/A: Foreground Persistence
Adversaries may abuse Android's `startForeground()` API method to maintain continuous sensor access. Beginning in Android 9, idle applications running in the background no longer have access to device sensors, such as the camera, microphone, and gyroscope.(Citation: Android-SensorsOverview) Applications can retain sensor access by running in the foreground, using Android’s `startForeground()` API method. This informs the system that the user is actively interacting with the application, and it should not be killed. The only requirement to start a foreground service is showing a persistent notification to the user.(Citation: Android-ForegroundServices)

Malicious applications may abuse the `startForeground()` API method to continue running in the foreground, while presenting a notification to the user pretending to be a genuine application. This would allow unhindered access to the device’s sensors, assuming permission has been previously granted.(Citation: BlackHat Sutter Android Foreground 2019)

Malicious applications may also abuse the `startForeground()` API to inform the Android system that the user is actively interacting with the application, thus preventing it from being killed by the low memory killer.(Citation: TrendMicro-Yellow Camera)

## N/A: Replication Through Removable Media
Adversaries may move onto devices by exploiting or copying malware to devices connected via USB. In the case of Lateral Movement, adversaries may utilize the physical connection of a device to a compromised or malicious charging station or PC to bypass application store requirements and install malicious applications directly.(Citation: Lau-Mactans) In the case of Initial Access, adversaries may attempt to exploit the device via the connection to gain access to data stored on the device.(Citation: Krebs-JuiceJacking) Examples of this include: 
 
* Exploiting insecure bootloaders in a Nexus 6 or 6P device over USB and gaining the ability to perform actions including intercepting phone calls, intercepting network traffic, and obtaining the device physical location.(Citation: IBM-NexusUSB) 
* Exploiting weakly-enforced security boundaries in Android devices such as the Google Pixel 2 over USB.(Citation: GoogleProjectZero-OATmeal) 
* Products from Cellebrite and Grayshift purportedly that can exploit some iOS devices using physical access to the data port to unlock the passcode.(Citation: Computerworld-iPhoneCracking) 

## N/A: Audio Capture
Adversaries may capture audio to collect information by leveraging standard operating system APIs of a mobile device. Examples of audio information adversaries may target include user conversations, surroundings, phone calls, or other sensitive information. 

 

Android and iOS, by default, require that applications request device microphone access from the user.  

 

On Android devices, applications must hold the `RECORD_AUDIO` permission to access the microphone or the `CAPTURE_AUDIO_OUTPUT` permission to access audio output. Because Android does not allow third-party applications to hold the `CAPTURE_AUDIO_OUTPUT` permission by default, only privileged applications, such as those distributed by Google or the device vendor, can access audio output.(Citation: Android Permissions) However, adversaries may be able to gain this access after successfully elevating their privileges. With the `CAPTURE_AUDIO_OUTPUT` permission, adversaries may pass the `MediaRecorder.AudioSource.VOICE_CALL` constant to `MediaRecorder.setAudioOutput`, allowing capture of both voice call uplink and downlink.(Citation: Manifest.permission) 

 

On iOS devices, applications must include the `NSMicrophoneUsageDescription` key in their `Info.plist` file to access the microphone.(Citation: Requesting Auth-Media Capture)

## N/A: Hijack Execution Flow
Adversaries may execute their own malicious payloads by hijacking the way operating systems run applications. Hijacking execution flow can be for the purposes of persistence since this hijacked execution may reoccur over time. 

There are many ways an adversary may hijack the flow of execution. A primary way is by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs or resources, such as file directories, could also be poisoned to include malicious payloads.

## N/A: Unix Shell
Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are the underlying command prompts on Android and iOS devices. Unix shells can control every aspect of a system, with certain commands requiring elevated privileges that are only accessible if the device has been rooted or jailbroken. 

Unix shells also support scripts that enable sequential execution of commands as well as other typical programming operations such as conditionals and loops. Common uses of shell scripts include long or repetitive tasks, or the need to run the same set of commands on multiple systems. 

Adversaries may abuse Unix shells to execute various commands or payloads. Interactive shells may be accessed through command and control channels or during lateral movement such as with SSH. Adversaries may also leverage shell scripts to deliver and execute multiple commands on victims or as part of payloads used for persistence. 

If the device has been rooted or jailbroken, adversaries may locate and invoke a superuser binary to elevate their privileges and interact with the system as the root user. This dangerous level of permissions allows the adversary to run special commands and modify protected system files.  

## N/A: Application Layer Protocol
Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the mobile device, and often the results of those commands, will be embedded within the protocol traffic between the mobile device and server. 

Adversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, or DNS.

## T1431: App Delivered via Web Download
No description available.

## N/A: Download New Code at Runtime
Adversaries may download and execute dynamic code not included in the original application package after installation. This technique is primarily used to evade static analysis checks and pre-publication scans in official app stores. In some cases, more advanced dynamic or behavioral analysis techniques could detect this behavior. However, in conjunction with [Execution Guardrails](https://attack.mitre.org/techniques/T1627) techniques, detecting malicious code downloaded after installation could be difficult.

On Android, dynamic code could include native code, Dalvik code, or JavaScript code that utilizes Android WebView’s `JavascriptInterface` capability. 

On iOS, dynamic code could be downloaded and executed through 3rd party libraries such as JSPatch. (Citation: FireEye-JSPatch) 

## N/A: Exploitation for Initial Access
Adversaries may exploit software vulnerabilities to gain initial access to a mobile device. 

This can be accomplished in a variety of ways. Vulnerabilities may be present in the applications, the services, the underlying operating system, or the kernel itself. Several well-known mobile device exploits exist, including FORCEDENTRY, StageFright, and BlueBorne. Furthermore, some exploits may be possible to exploit without any user interaction (i.e. zero-click exploits, see [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1658)), making them particularly dangerous. Mobile operating system vendors are typically very quick to patch such critical bugs, ensuring only a small window where they can be exploited. 

## N/A: Remotely Track Device Without Authorization
An adversary who is able to obtain unauthorized access to or misuse authorized access to cloud services (e.g. Google's Android Device Manager or Apple iCloud's Find my iPhone) or to an enterprise mobility management (EMM) / mobile device management (MDM) server console could use that access to track mobile devices.(Citation: Krebs-Location)

## N/A: System Checks
Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behavior after checking for the presence of artifacts indicative of a virtual environment or sandbox. If the adversary detects a virtual environment, they may alter their malware’s behavior to disengage from the victim or conceal the core functions of the implant. They may also search for virtualization artifacts before dropping secondary or additional payloads. 

Checks could include generic system properties such as host/domain name and samples of network traffic. Adversaries may also check the network adapters addresses, CPU core count, and available memory/drive size. 

Hardware checks, such as the presence of motion sensors, could also be used to gather evidence that can be indicative a virtual environment. Adversaries may also query for specific readings from these devices. 

## N/A: Stored Application Data
Adversaries may try to access and collect application data resident on the device. Adversaries often target popular applications, such as Facebook, WeChat, and Gmail.(Citation: SWB Exodus March 2019) 

 

Due to mobile OS sandboxing, this technique is only possible in three scenarios: 

 

* An application stores files in unprotected external storage 
* An application stores files in its internal storage directory with insecure permissions (e.g. 777) 
* The adversary gains root permissions on the device 

## N/A: Screen Capture
Adversaries may use screen capture to collect additional information about a target device, such as applications running in the foreground, user data, credentials, or other sensitive information. Applications running in the background can capture screenshots or videos of another application running in the foreground by using the Android `MediaProjectionManager` (generally requires the device user to grant consent).(Citation: Fortinet screencap July 2019)(Citation: Android ScreenCap1 2019) Background applications can also use Android accessibility services to capture screen contents being displayed by a foreground application.(Citation: Lookout-Monokle) An adversary with root access or Android Debug Bridge (adb) access could call the Android `screencap` or `screenrecord` commands.(Citation: Android ScreenCap2 2019)(Citation: Trend Micro ScreenCap July 2015) 

## N/A: Transmitted Data Manipulation
Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity. By manipulating transmitted data, adversaries may attempt to affect a business process, organizational understanding, or decision making.

Manipulation may be possible over a network connection or between system processes where there is an opportunity to deploy a tool that will intercept and change information. The type of modification and the impact it will have depends on the target transmission mechanism as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system, typically gained through a prolonged information gathering campaign, in order to have the desired impact.

One method to achieve [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1641/001) is by modifying the contents of the device clipboard. Malicious applications may monitor clipboard activity through the `ClipboardManager.OnPrimaryClipChangedListener` interface on Android to determine when clipboard contents have changed. Listening to clipboard activity, reading clipboard contents, and modifying clipboard contents requires no explicit application permissions and can be performed by applications running in the background. However, this behavior has changed with the release of Android 10.

Adversaries may use [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1641/001) to replace text prior to being pasted. For example, replacing a copied Bitcoin wallet address with a wallet address that is under adversarial control.

[Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1641/001) was seen within the Android/Clipper.C trojan. This sample was detected by ESET in an application distributed through the Google Play Store targeting cryptocurrency wallet numbers.(Citation: ESET Clipboard Modification February 2019)

## N/A: Manipulate App Store Rankings or Ratings
An adversary could use access to a compromised device's credentials to attempt to manipulate app store rankings or ratings by triggering application downloads or posting fake reviews of applications. This technique likely requires privileged access (a rooted or jailbroken device).

## N/A: URI Hijacking
Adversaries may register Uniform Resource Identifiers (URIs) to intercept sensitive data.

Applications regularly register URIs with the operating system to act as a response handler for various actions, such as logging into an app using an external account via single sign-on. This allows redirections to that specific URI to be intercepted by the application. If a malicious application were to register for a URI that was already in use by a genuine application, the malicious application may be able to intercept data intended for the genuine application or perform a phishing attack against the genuine application. Intercepted data may include OAuth authorization codes or tokens that could be used by the malicious application to gain access to resources.(Citation: Trend Micro iOS URL Hijacking)(Citation: IETF-PKCE)

## N/A: Compromise Software Dependencies and Development Tools
Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise. Applications often depend on external software to function properly. Popular open source projects that are used as dependencies in many applications may be targeted as a means to add malicious code to users of the dependency.(Citation: Grace-Advertisement)

## N/A: Evade Analysis Environment
Malicious applications may attempt to detect their operating environment prior to fully executing their payloads. These checks are often used to ensure the application is not running within an analysis environment such as a sandbox used for application vetting, security research, or reverse engineering. 
Adversaries may use many different checks such as physical sensors, location, and system properties to fingerprint emulators and sandbox environments.(Citation: Talos Gustuff Apr 2019)(Citation: ThreatFabric Cerberus)(Citation: Xiao-ZergHelper)(Citation: Cyberscoop Evade Analysis January 2019) Adversaries may access `android.os.SystemProperties` via Java reflection to obtain specific system information.(Citation: Github Anti-emulator) Standard values such as phone number, IMEI, IMSI, device IDs, and device drivers may be checked against default signatures of common sandboxes.(Citation: Sophos Anti-emulation)


## N/A: URI Hijacking
Adversaries may register Uniform Resource Identifiers (URIs) to intercept sensitive data. 

Applications regularly register URIs with the operating system to act as a response handler for various actions, such as logging into an app using an external account via single sign-on. This allows redirections to that specific URI to be intercepted by the application. If an adversary were to register for a URI that was already in use by a genuine application, the adversary may be able to intercept data intended for the genuine application or perform a phishing attack against the genuine application. Intercepted data may include OAuth authorization codes or tokens that could be used by the adversary to gain access to protected resources.(Citation: Trend Micro iOS URL Hijacking)(Citation: IETF-PKCE) 

## N/A: Subvert Trust Controls
Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted applications. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust. Examples of such features include: an app being allowed to run because it is signed by a valid code signing certificate; an OS prompt alerting the user that an app came from an untrusted source; or getting an indication that you are about to connect to an untrusted site. The method adversaries use will depend on the specific mechanism they seek to subvert. 

## N/A: Access Call Log
On Android, an adversary could call standard operating system APIs from a malicious application to gather call log data, or with escalated privileges could directly access files containing call log data.

On iOS, applications do not have access to the call log, so privilege escalation would be required in order to access the data.

## N/A: Geofencing
Adversaries may use a device’s geographical location to limit certain malicious behaviors. For example, malware operators may limit the distribution of a second stage payload to certain geographic regions.(Citation: Lookout eSurv)

[Geofencing](https://attack.mitre.org/techniques/T1581) is accomplished by persuading the user to grant the application permission to access location services. The application can then collect, process, and exfiltrate the device’s location to perform location-based actions, such as ceasing malicious behavior or showing region-specific advertisements.

One method to accomplish [Geofencing](https://attack.mitre.org/techniques/T1581) on Android is to use the built-in Geofencing API to automatically trigger certain behaviors when the device enters or exits a specified radius around a geographical location. Similar to other [Geofencing](https://attack.mitre.org/techniques/T1581) methods, this requires that the user has granted the `ACCESS_FINE_LOCATION` and `ACCESS_BACKGROUND_LOCATION` permissions. The latter is only required if the application targets Android 10 (API level 29) or higher. However, Android 11 introduced additional permission controls that may restrict background location collection based on user permission choices at runtime. These additional controls include “Allow only while using the app”, which will effectively prohibit background location collection.(Citation: Android Geofencing API)

Similarly, on iOS, developers can use built-in APIs to setup and execute geofencing. Depending on the use case, the app will either need to call `requestWhenInUseAuthorization()` or `requestAlwaysAuthorization()`, depending on when access to the location services is required. Similar to Android, users also have the option to limit when the application can access the device’s location, including one-time use and only when the application is running in the foreground.(Citation: Apple Location Services)

[Geofencing](https://attack.mitre.org/techniques/T1581) can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. For example, location data could be used to limit malware spread and/or capabilities, which could also potentially evade application analysis environments (ex: malware analysis outside of the target geographic area). Other malicious usages could include showing language-specific [Input Prompt](https://attack.mitre.org/techniques/T1411)s and/or advertisements.

## N/A: Device Administrator Permissions
Adversaries may request device administrator permissions to perform malicious actions.

By abusing the device administration API, adversaries can perform several nefarious actions, such as resetting the device’s password for [Device Lockout](https://attack.mitre.org/techniques/T1446), factory resetting the device to [Delete Device Data](https://attack.mitre.org/techniques/T1447) and any traces of the malware, disabling all of the device’s cameras, or make it more difficult to uninstall the app.(Citation: Android DeviceAdminInfo)

Device administrators must be approved by the user at runtime, with a system popup showing which of the actions have been requested by the app. In conjunction with other techniques, such as [Input Injection](https://attack.mitre.org/techniques/T1516), an app can programmatically grant itself administrator permissions without any user input.

## T1443: Remotely Install Application
No description available.

## N/A: Keychain
Adversaries may collect keychain data from an iOS device to acquire credentials. Keychains are the built-in way for iOS to keep track of users' passwords and credentials for many services and features such as Wi-Fi passwords, websites, secure notes, certificates, private keys, and VPN credentials. 

On the device, the keychain database is stored outside of application sandboxes to prevent unauthorized access to the raw data. Standard iOS APIs allow applications access to their own keychain contained within the database. By utilizing a privilege escalation exploit or existing root access, adversaries can access the entire encrypted database.(Citation: Apple Keychain Services)(Citation: Elcomsoft Decrypt Keychain) 

## N/A: Modify Cached Executable Code
ART (the Android Runtime) compiles optimized code on the device itself to improve performance. An adversary may be able to use escalated privileges to modify the cached code in order to hide malicious behavior. Since the code is compiled on the device, it may not receive the same level of integrity checks that are provided to code running in the system partition.(Citation: Sabanal-ART)

## N/A: Device Type Discovery
On Android, device type information is accessible to apps through the android.os.Build class (Citation: Android-Build). Device information could be used to target privilege escalation exploits.

## N/A: Uninstall Malicious Application
Adversaries may include functionality in malware that uninstalls the malicious application from the device. This can be achieved by:

* Abusing device owner permissions to perform silent uninstallation using device owner API calls.
* Abusing root permissions to delete files from the filesystem.
* Abusing the accessibility service. This requires an intent be sent to the system to request uninstallation, and then abusing the accessibility service to click the proper places on the screen to confirm uninstallation.

## N/A: Virtualization Solution
Adversaries may carry out malicious operations using virtualization solutions to escape from Android sandboxes and to avoid detection. Android uses sandboxes to separate resources and code execution between applications and the operating system.(Citation: Android Application Sandbox) There are a few virtualization solutions available on Android, such as the Android Virtualization Framework (AVF).(Citation: Android AVF Overview)  

 

Through virtualization solutions, adversaries may execute malicious operations without user knowledge. For example, adversaries may mimic a legitimate banking application’s functionalities in a virtual environment, thanks to the virtualization solution, while malicious code captures credentials.  

## N/A: Delete Device Data
Adversaries may wipe a device or delete individual files in order to manipulate external outcomes or hide activity. An application must have administrator access to fully wipe the device, while individual files may not require special permissions to delete depending on their storage location. (Citation: Android DevicePolicyManager 2019)

Stored data could include a variety of file formats, such as Office files, databases, stored emails, and custom file formats. The impact file deletion will have depends on the type of data as well as the goals and objectives of the adversary, but can include deleting update files to evade detection or deleting attacker-specified files for impact.

## N/A: Carrier Billing Fraud
A malicious app may trigger fraudulent charges on a victim’s carrier billing statement in several different ways, including SMS toll fraud and SMS shortcodes that make purchases.

Performing SMS fraud relies heavily upon the fact that, when making SMS purchases, the carriers perform device verification but not user verification. This allows adversaries to make purchases on behalf of the user, with little or no user interaction.(Citation: Google Bread)

Malicious applications may also perform toll billing, which occurs when carriers provide payment endpoints over a web page. The application connects to the web page over cellular data so the carrier can directly verify the number, or the application must retrieve a code sent via SMS and enter it into the web page.(Citation: Google Bread)

On iOS, apps cannot send SMS messages.

On Android, apps must hold the `SEND_SMS` permission to send SMS messages. Additionally, Android version 4.2 and above has mitigations against this threat by requiring user consent before allowing SMS messages to be sent to premium numbers (Citation: AndroidSecurity2014).

## N/A: URL Scheme Hijacking
An iOS application may be able to maliciously claim a URL scheme, allowing it to intercept calls that are meant for a different application(Citation: FireEye-Masque2)(Citation: Dhanjani-URLScheme). This technique, for example, could be used to capture OAuth authorization codes(Citation: IETF-PKCE) or to phish user credentials(Citation: MobileIron-XARA).

## N/A: Bidirectional Communication
Adversaries may use an existing, legitimate external Web service channel as a means for sending commands to and receiving output from a compromised system. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems can then send the output from those commands back over that Web service channel. The return traffic may occur in a variety of ways, depending on the Web service being utilized. For example, the return traffic may take the form of the compromised system posting a comment on a forum, issuing a pull request to development project, updating a document hosted on a Web service, or by sending a Tweet. 

 

Popular websites and social media, acting as a mechanism for C2, may give a significant amount of cover. This is due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection. 

## N/A: Non-Standard Port
Adversaries may generate network traffic using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088 or port 587 as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.

## N/A: Compromise Software Supply Chain
Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise. Supply chain compromise of software can take place in a number of ways, including manipulation of the application source code, manipulation of the update/distribution mechanism for that software, or replacing compiled releases with a modified version.

## N/A: Dead Drop Resolver
Adversaries may use an existing, legitimate external Web service to host information that points to additional command and control (C2) infrastructure. Adversaries may post content, known as a dead drop resolver, on Web services with embedded (and often obfuscated/encoded) domains or IP addresses. Once infected, victims will reach out to and be redirected by these resolvers. 

 

Popular websites and social media, acting as a mechanism for C2, may give a significant amount of cover. This is due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection. 

 

Use of a dead drop resolver may also protect back-end C2 infrastructure from discovery through malware binary analysis, or enable operational resiliency (since this infrastructure may be dynamically changed). 

## N/A: Location Tracking
Adversaries may track a device’s physical location through use of standard operating system APIs via malicious or exploited applications on the compromised device. 

 

On Android, applications holding the `ACCESS_COAURSE_LOCATION` or `ACCESS_FINE_LOCATION` permissions provide access to the device’s physical location. On Android 10 and up, declaration of the `ACCESS_BACKGROUND_LOCATION` permission in an application’s manifest will allow applications to request location access even when the application is running in the background.(Citation: Android Request Location Permissions) Some adversaries have utilized integration of Baidu map services to retrieve geographical location once the location access permissions had been obtained.(Citation: PaloAlto-SpyDealer)(Citation: Palo Alto HenBox) 

 

On iOS, applications must include the `NSLocationWhenInUseUsageDescription`, `NSLocationAlwaysAndWhenInUseUsageDescription`, and/or `NSLocationAlwaysUsageDescription` keys in their `Info.plist` file depending on the extent of requested access to location information.(Citation: Apple Requesting Authorization for Location Services) On iOS 8.0 and up, applications call `requestWhenInUseAuthorization()` to request access to location information when the application is in use or `requestAlwaysAuthorization()` to request access to location information regardless of whether the application is in use. With elevated privileges, an adversary may be able to access location data without explicit user consent with the `com.apple.locationd.preauthorized` entitlement key.(Citation: Google Project Zero Insomnia)

## N/A: Device Administrator Permissions
Adversaries may abuse Android’s device administration API to obtain a higher degree of control over the device. By abusing the API, adversaries can perform several nefarious actions, such as resetting the device’s password for [Endpoint Denial of Service](https://attack.mitre.org/techniques/T1642), factory resetting the device for [File Deletion](https://attack.mitre.org/techniques/T1630/002) and to delete any traces of the malware, disabling all the device’s cameras, or to make it more difficult to uninstall the app.

Device administrators must be approved by the user at runtime, with a system popup showing which actions have been requested by the app. In conjunction with other techniques, such as [Input Injection](https://attack.mitre.org/techniques/T1516), an app can programmatically grant itself administrator permissions without any user input.

## N/A: Device Lockout
An adversary may seek to lock the legitimate user out of the device, for example to inhibit user interaction or to obtain a ransom payment.

On Android versions prior to 7, apps can abuse Device Administrator access to reset the device lock passcode to prevent the user from unlocking the device. After Android 7, only device or profile owners (e.g. MDMs) can reset the device’s passcode.(Citation: Android resetPassword)

On iOS devices, this technique does not work because mobile device management servers can only remove the screen lock passcode, they cannot set a new passcode. However, on jailbroken devices, malware has been discovered that can lock the user out of the device.(Citation: Xiao-KeyRaider)

## N/A: Remote Device Management Services
An adversary may use access to cloud services (e.g. Google's Android Device Manager or Apple iCloud's Find my iPhone) or to an enterprise mobility management (EMM)/mobile device management (MDM) server console to track the location of mobile devices managed by the service.(Citation: Krebs-Location) 

## N/A: Data Destruction
Adversaries may destroy data and files on specific devices or in large numbers to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives.  

To achieve data destruction, adversaries may use the `pm uninstall` command to uninstall packages or the `rm` command to remove specific files. For example, adversaries may first use `pm uninstall` to uninstall non-system apps, and then use `rm (-f) <file(s)>` to delete specific files, further hiding malicious activity.(Citation: rootnik_rooting_tool)(Citation: abuse_native_linux_tools)

## N/A: Attack PC via USB Connection
With escalated privileges, an adversary could program the mobile device to impersonate USB devices such as input devices (keyboard and mouse), storage devices, and/or networking devices in order to attack a physically connected PC(Citation: Wang-ExploitingUSB)(Citation: ArsTechnica-PoisonTap) This technique has been demonstrated on Android. We are unaware of any demonstrations on iOS.

## N/A: Linked Devices
Adversaries may abuse the “linked devices” feature on messaging applications, such as Signal and WhatsApp, to register the user’s account to an adversary-controlled device. By abusing the “linked devices” feature, adversaries may achieve and maintain persistence through the user’s account, may collect information, such as the user’s messages and contacts list, and may send future messages from the linked device.

Signal is a messaging application that uses the open-source Signal Protocol to encrypt messages and calls; similarly, WhatsApp is a messaging application that has end-to-end encryption and other security measures to protect messages and calls. Both applications have a “linked devices” feature that allows users to access their Signal and/or WhatsApp accounts from different devices, such as a Windows or Mac desktop, an iPad or an Android tablet.(Citation: WhatsApp_LinkDevice_NoDate)(Citation: Signal_LinkedDevices_NoDate)

Adversaries may use [Phishing](https://attack.mitre.org/techniques/T1660) techniques to trick the user into scanning a quick-response (QR) code, which is used to link the user’s Signal and/or WhatsApp account to an adversary-controlled device. For example, adversaries may masquerade QR codes as group invites, security alerts or as legitimate instructions for pairing linked devices. 
Upon scanning the QR code in Signal, users may click on the “Transfer Message History” option to sync the linked devices, which may allow adversaries to collect more information about the user. Upon scanning the QR code in WhatsApp, the user’s device will automatically send an end-to-end encrypted copy of recent message history to the adversary-controlled device. 

## T1441: Stolen Developer Credentials or Signing Keys
No description available.

## N/A: Rogue Cellular Base Station
An adversary could set up a rogue cellular base station and then use it to eavesdrop on or manipulate cellular device communication. A compromised cellular femtocell could be used to carry out this technique(Citation: Computerworld-Femtocell).

## N/A: SIM Card Swap
Adversaries may gain access to mobile devices through transfers or swaps from victims’ phone numbers to adversary-controlled SIM cards and mobile devices.(Citation: ATT SIM Swap Scams)(Citation: Verizon SIM Swapping) 

The typical process is as follows:  

1. Adversaries will first gather information about victims through [Phishing](https://attack.mitre.org/techniques/T1660), social engineering, data breaches, or other avenues. 
2. Adversaries will then impersonate victims as they contact mobile carriers to request for the SIM swaps. For example, adversaries would provide victims’ name and address to mobile carriers; once authenticated, adversaries would request for victims’ phone numbers to be transferred to adversary-controlled SIM cards.  
3. Once completed, victims will lose mobile data, such as text messages and phone calls, on their mobile devices. In turn, adversaries will receive mobile data that was intended for the victims.  

Adversaries may use the intercepted SMS messages to log into online accounts that use SMS-based authentication. Specifically, adversaries may use SMS-based authentication to log into banking and/or cryptocurrency accounts, then transfer funds to adversary-controlled wallets. 

## N/A: Input Capture
Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal device usage, users often provide credentials to various locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. [Keylogging](https://attack.mitre.org/techniques/T1417/001)) or rely on deceiving the user into providing input into what they believe to be a genuine application prompt (e.g. [GUI Input Capture](https://attack.mitre.org/techniques/T1417/002)).

## N/A: Generate Traffic from Victim
Adversaries may generate outbound traffic from devices. This is typically performed to manipulate external outcomes, such as to achieve carrier billing fraud or to manipulate app store rankings or ratings. Outbound traffic is typically generated as SMS messages or general web traffic, but may take other forms as well.

If done via SMS messages, Android apps must hold the `SEND_SMS` permission. Additionally, sending an SMS message requires user consent if the recipient is a premium number. Applications cannot send SMS messages on iOS

## N/A: Disguise Root/Jailbreak Indicators
An adversary could use knowledge of the techniques used by security software to evade detection.(Citation: Brodie)(Citation: Tan) For example, some mobile security products perform compromised device detection by searching for particular artifacts such as an installed "su" binary, but that check could be evaded by naming the binary something else. Similarly, polymorphic code techniques could be used to evade signature-based detection.(Citation: Rastogi)

## N/A: Masquerade as Legitimate Application
An adversary could distribute developed malware by masquerading the malware as a legitimate application. This can be done in two different ways: by embedding the malware in a legitimate application, or by pretending to be a legitimate application.

Embedding the malware in a legitimate application is done by downloading the application, disassembling it, adding the malicious code, and then re-assembling it.(Citation: Zhou) The app would appear to be the original app, but would contain additional malicious functionality. The adversary could then publish the malicious application to app stores or use another delivery method.

Pretending to be a legitimate application relies heavily on lack of scrutinization by the user. Typically, a malicious app pretending to be a legitimate one will have many similar details as the legitimate one, such as name, icon, and description.(Citation: Palo Alto HenBox)

Malicious applications may also masquerade as legitimate applications when requesting access to the accessibility service in order to appear as legitimate to the user, increasing the likelihood that the access will be granted.

## T1457: Malicious Media Content
No description available.

## N/A: Calendar Entries
Adversaries may utilize standard operating system APIs to gather calendar entry data. On Android, this can be accomplished using the Calendar Content Provider. On iOS, this can be accomplished using the `EventKit` framework. 

 

If the device has been jailbroken or rooted, an adversary may be able to access [Calendar Entries](https://attack.mitre.org/techniques/T1636/001) without the user’s knowledge or approval. 

## N/A: File Deletion
Adversaries may wipe a device or delete individual files in order to manipulate external outcomes or hide activity. An application must have administrator access to fully wipe the device, while individual files may not require special permissions to delete depending on their storage location.(Citation: Android DevicePolicyManager 2019) 

Stored data could include a variety of file formats, such as Office files, databases, stored emails, and custom file formats. The impact file deletion will have depends on the type of data as well as the goals and objectives of the adversary, but can include deleting update files to evade detection or deleting attacker-specified files for impact.

## N/A: Device Lockout
An adversary may seek to inhibit user interaction by locking the legitimate user out of the device. This is typically accomplished by requesting device administrator permissions and then locking the screen using `DevicePolicyManager.lockNow()`. Other novel techniques for locking the user out of the device have been observed, such as showing a persistent overlay, using carefully crafted “call” notification screens, and locking HTML pages in the foreground. These techniques can be very difficult to get around, and typically require booting the device into safe mode to uninstall the malware.(Citation: Microsoft MalLockerB)(Citation: Talos GPlayed)(Citation: securelist rotexy 2018)

Prior to Android 7, device administrators were able to reset the device lock passcode to prevent the user from unlocking the device. The release of Android 7 introduced updates that only allow device or profile owners (e.g. MDMs) to reset the device’s passcode.(Citation: Android resetPassword)

## N/A: Keylogging
Adversaries may log user keystrokes to intercept credentials or other information from the user as the user types them.

Some methods of keylogging include:

* Masquerading as a legitimate third-party keyboard to record user keystrokes.(Citation: Zeltser-Keyboard) On both Android and iOS, users must explicitly authorize the use of third-party keyboard apps. Users should be advised to use extreme caution before granting this authorization when it is requested.
* Abusing accessibility features. On Android, adversaries may abuse accessibility features to record keystrokes by registering an `AccessibilityService` class, overriding the `onAccessibilityEvent` method, and listening for the `AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED` event type. The event object passed into the function will contain the data that the user typed. 
*Additional methods of keylogging may be possible if root access is available. 


## N/A: SMS Control
Adversaries may delete, alter, or send SMS messages without user authorization. This could be used to hide C2 SMS messages, spread malware, or various external effects.

This can be accomplished by requesting the `RECEIVE_SMS` or `SEND_SMS` permissions depending on what the malware is attempting to do. If the app is set as the default SMS handler on the device, the `SMS_DELIVER` broadcast intent can be registered, which allows the app to write to the SMS content provider. The content provider directly modifies the messaging database on the device, which could allow malicious applications with this ability to insert, modify, or delete arbitrary messages on the device.(Citation: SMS KitKat)(Citation: Android SmsProvider)

## N/A: Disguise Root/Jailbreak Indicators
An adversary could use knowledge of the techniques used by security software to evade detection(Citation: Brodie)(Citation: Tan). For example, some mobile security products perform compromised device detection by searching for particular artifacts such as an installed "su" binary, but that check could be evaded by naming the binary something else. Similarly, polymorphic code techniques could be used to evade signature-based detection(Citation: Rastogi).

## N/A: Exfiltration Over Other Network Medium
Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a standard Internet connection, the exfiltration may occur, for example, via Bluetooth, or another radio frequency (RF) channel. 

Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network. 

## T1440: Detect App Analysis Environment
No description available.

## N/A: Process Injection
Adversaries may inject code into processes in order to evade process-based defenses or even elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. 

Both Android and iOS have no legitimate way to achieve process injection. The only way this is possible is by abusing existing root access or exploiting a vulnerability.

## T1462: Malicious Software Development Tools
No description available.

## N/A: Symmetric Cryptography
Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic, rather than relying on any inherent protections provided by a communication protocol. Symmetric encryption algorithms use the same key for plaintext encryption and ciphertext decryption. Common symmetric encryption algorithms include AES, Blowfish, and RC4.

## N/A: Broadcast Receivers
An intent is a message passed between Android application or system components. Applications can register to receive broadcast intents at runtime, which are system-wide intents delivered to each app when certain events happen on the device, such as network changes or the user unlocking the screen. Malicious applications can then trigger certain actions within the app based on which broadcast intent was received.

Further, malicious applications can register for intents broadcasted by other applications in addition to the Android system itself. This allows the malware to respond based on actions in other applications. This behavior typically indicates a more intimate knowledge, or potentially the targeting of specific devices, users, or applications.

In Android 8 (API level 26), broadcast intent behavior was changed, limiting the implicit intents that applications can register for in the manifest. In most cases, applications that register through the manifest will no longer receive the broadcasts. Now, applications must register context-specific broadcast receivers while the user is actively using the app.(Citation: Android Changes to System Broadcasts)

## N/A: Wi-Fi Discovery
Adversaries may search for information about Wi-Fi networks, such as network names and passwords, on compromised systems. Adversaries may use Wi-Fi information as part of [Discovery](https://attack.mitre.org/tactics/TA0032) or [Credential Access](https://attack.mitre.org/tactics/TA0031) activity to support both ongoing and future campaigns. 

## N/A: Compromise Hardware Supply Chain
Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise. By modifying hardware or firmware in the supply chain, adversaries can insert a backdoor into consumer networks that may be difficult to detect and give the adversary a high degree of control over the system. 

## N/A: Clipboard Data
Adversaries may abuse clipboard manager APIs to obtain sensitive information copied to the device clipboard. For example, passwords being copied and pasted from a password manager application could be captured by a malicious application installed on the device.(Citation: Fahl-Clipboard) 

 

On Android, applications can use the `ClipboardManager.OnPrimaryClipChangedListener()` API to register as a listener and monitor the clipboard for changes. However, starting in Android 10, this can only be used if the application is in the foreground, or is set as the device’s default input method editor (IME).(Citation: Github Capture Clipboard 2019)(Citation: Android 10 Privacy Changes) 

 

On iOS, this can be accomplished by accessing the `UIPasteboard.general.string` field. However, starting in iOS 14, upon accessing the clipboard, the user will be shown a system notification if the accessed text originated in a different application. For example, if the user copies the text of an iMessage from the Messages application, the notification will read “application_name has pasted from Messages” when the text was pasted in a different application.(Citation: UIPPasteboard)

## N/A: Modify System Partition
If an adversary can escalate privileges, he or she may be able to use those privileges to place malicious code in the device system partition, where it may persist after device resets and may not be easily removed by the device user.

Many Android devices provide the ability to unlock the bootloader for development purposes. An unlocked bootloader may provide the ability for an adversary to modify the system partition. Even if the bootloader is locked, it may be possible for an adversary to escalate privileges and then modify the system partition.

## N/A: Data Manipulation
Adversaries may insert, delete, or alter data in order to manipulate external outcomes or hide activity. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.

The type of modification and the impact it will have depends on the target application, process, and the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system, typically gained through a prolonged information gathering campaign, in order to have the desired impact.

## N/A: SMS Messages
Adversaries may utilize standard operating system APIs to gather SMS messages. On Android, this can be accomplished using the SMS Content Provider. iOS provides no standard API to access SMS messages. 

If the device has been jailbroken or rooted, an adversary may be able to access [SMS Messages](https://attack.mitre.org/techniques/T1636/004) without the user’s knowledge or approval. 

## N/A: Web Service
Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system. Popular websites and social media, acting as a mechanism for C2, may give a significant amount of cover. This is due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection. 

 

Use of Web services may also protect back-end C2 infrastructure from discovery through malware binary analysis, or enable operational resiliency (since this infrastructure may be dynamically changed). 

 

## N/A: System Runtime API Hijacking
Adversaries may execute their own malicious payloads by hijacking the way an operating system runs applications. Hijacking execution flow can be for the purposes of persistence since this hijacked execution may reoccur at later points in time. 


On Android, adversaries may overwrite the standard OS API library with a malicious alternative to hook into core functions to achieve persistence. By doing this, the adversary’s code will be executed every time the overwritten API function is called by an app on the infected device.

## T1455: Exploit Baseband Vulnerability
No description available.

## N/A: Credentials from Password Store
Adversaries may search common password storage locations to obtain user credentials. Passwords can be stored in several places on a device, depending on the operating system or application holding the credentials. There are also specific applications that store passwords to make it easier for users to manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.

## N/A: Hooking
Adversaries may utilize hooking to hide the presence of artifacts associated with their behaviors to evade detection. Hooking can be used to modify return values or data structures of system APIs and function calls. This process typically involves using 3rd party root frameworks, such as Xposed or Magisk, with either a system exploit or pre-existing root access. By including custom modules for root frameworks, adversaries can hook system APIs and alter the return value and/or system data structures to alter functionality/visibility of various aspects of the system.

## N/A: Install Insecure or Malicious Configuration
An adversary could attempt to install insecure or malicious configuration settings on the mobile device, through means such as phishing emails or text messages either directly containing the configuration settings as an attachment, or containing a web link to the configuration settings. The device user may be tricked into installing the configuration settings through social engineering techniques (Citation: Symantec-iOSProfile).

For example, an unwanted Certification Authority (CA) certificate could be placed in the device's trusted certificate store, increasing the device's susceptibility to adversary-in-the-middle network attacks seeking to eavesdrop on or manipulate the device's network communication ([Eavesdrop on Insecure Network Communication](https://attack.mitre.org/techniques/T1439) and [Manipulate Device Communication](https://attack.mitre.org/techniques/T1463)).

On iOS, malicious Configuration Profiles could contain unwanted Certification Authority (CA) certificates or other insecure settings such as unwanted proxy server or VPN settings to route the device's network traffic through an adversary's system. The device could also potentially be enrolled into a malicious Mobile Device Management (MDM) system (Citation: Talos-MDM).

## N/A: File and Directory Discovery
Adversaries may enumerate files and directories or search in specific device locations for desired information within a filesystem. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1420) during automated discovery to shape follow-on behaviors, including deciding if the adversary should fully infect the target and/or attempt specific actions. 

On Android, Linux file permissions and SELinux policies typically stringently restrict what can be accessed by apps without taking advantage of a privilege escalation exploit. The contents of the external storage directory are generally visible, which could present concerns if sensitive data is inappropriately stored there. iOS's security architecture generally restricts the ability to perform any type of [File and Directory Discovery](https://attack.mitre.org/techniques/T1420) without use of escalated privileges. 

## N/A: Obfuscated Files or Information
Adversaries may attempt to make a payload or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the device or in transit. This is common behavior that can be used across different platforms and the network to evade defenses. 
 
Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Portions of files can also be encoded to hide the plaintext strings that would otherwise help defenders with discovery. Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled.(Citation: Microsoft MalLockerB) 

## N/A: Input Injection
A malicious application can inject input to the user interface to mimic user interaction through the abuse of Android's accessibility APIs.

[Input Injection](https://attack.mitre.org/techniques/T1516) can be achieved using any of the following methods:

* Mimicking user clicks on the screen, for example to steal money from a user's PayPal account.(Citation: android-trojan-steals-paypal-2fa)
* Injecting global actions, such as `GLOBAL_ACTION_BACK` (programatically mimicking a physical back button press), to trigger actions on behalf of the user.(Citation: Talos Gustuff Apr 2019)
* Inserting input into text fields on behalf of the user. This method is used legitimately to auto-fill text fields by applications such as password managers.(Citation: bitwarden autofill logins)

## N/A: Network Denial of Service
Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth that services rely on, or by jamming the signal going to or coming from devices. 

A Network DoS will occur when an adversary is able to jam radio signals (e.g. Wi-Fi, cellular, GPS) around a device to prevent it from communicating. For example, to jam cellular signal, an adversary may use a handheld signal jammer, which jam devices within the jammer’s operational range.(Citation: NIST-SP800187) 

Usage of cellular jamming has been documented in several arrests reported in the news.(Citation: CNET-Celljammer)(Citation: NYTimes-Celljam)(Citation: Digitaltrends-Celljam)(Citation: Arstechnica-Celljam)

## N/A: Compromise Application Executable
Adversaries may modify applications installed on a device to establish persistent access to a victim. These malicious modifications can be used to make legitimate applications carry out adversary tasks when these applications are in use.

There are multiple ways an adversary can inject malicious code into applications. One method is by taking advantages of device vulnerabilities, the most well-known being Janus, an Android vulnerability that allows adversaries to add extra bytes to APK (application) and DEX (executable) files without affecting the file's signature. By being able to add arbitrary bytes to valid applications, attackers can seamlessly inject code into genuine executables without the user's knowledge.(Citation: Guardsquare Janus)

Adversaries may also rebuild applications to include malicious modifications. This can be achieved by decompiling the genuine application, merging it with the malicious code, and recompiling it.(Citation: CheckPoint Agent Smith)

Adversaries may also take action to conceal modifications to application executables and bypass user consent. These actions include altering modifications to appear as an update or exploiting vulnerabilities that allow activities of the malicious application to run inside a system application.(Citation: CheckPoint Agent Smith)

## N/A: Event Triggered Execution
Adversaries may establish persistence using system mechanisms that trigger execution based on specific events. Mobile operating systems have means to subscribe to events such as receiving an SMS message, device boot completion, or other device activities. 

Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via automatically and repeatedly executing malicious code. After gaining access to a victim’s system, adversaries may create or modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked. 

## N/A: System Network Configuration Discovery
Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of devices they access or through information discovery of remote systems. 

Adversaries may use the information from [System Network Configuration Discovery](https://attack.mitre.org/techniques/T1422) during automated discovery to shape follow-on behaviors, including determining certain access within the target network and what actions to do next. 

On Android, details of onboard network interfaces are accessible to apps through the `java.net.NetworkInterface` class.(Citation: NetworkInterface) Previously, the Android `TelephonyManager` class could be used to gather telephony-related device identifiers, information such as the IMSI, IMEI, and phone number. However, starting with Android 10, only preloaded, carrier, the default SMS, or device and profile owner applications can access the telephony-related device identifiers.(Citation: TelephonyManager) 

 

On iOS, gathering network configuration information is not possible without root access. 

 

Adversaries may use the information from [System Network Configuration Discovery](https://attack.mitre.org/techniques/T1422) during automated discovery to shape follow-on behaviors, including determining certain access within the target network and what actions to do next. 

