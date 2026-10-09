# Apple iOS Security & Vulnerability Advisory

Reference iOS vulnerabilities mapped from NVD CVE records.

## CVE-2008-1586
ImageIO in Apple iPhone OS 1.0 through 2.1 and iPhone OS for iPod touch 1.1 through 2.1 allow remote attackers to cause a denial of service (memory consumption and device reset) via a crafted TIFF image.

## CVE-2008-4227
Apple iPhone OS 1.0 through 2.1 and iPhone OS for iPod touch 1.1 through 2.1 changes the encryption level of PPTP VPN connections to a lower level than was previously used, which makes it easier for remote attackers to obtain sensitive information or hijack a connection by decrypting network traffic.

## CVE-2008-4228
The Passcode Lock feature in Apple iPhone OS 1.0 through 2.1 and iPhone OS for iPod touch 1.1 through 2.1 allows physically proximate attackers to leverage the emergency-call ability of locked devices to make a phone call to an arbitrary number.

## CVE-2008-4229
Race condition in the Passcode Lock feature in Apple iPhone OS 2.0 through 2.1 and iPhone OS for iPod touch 2.0 through 2.1 allows physically proximate attackers to remove the lock and launch arbitrary applications by restoring the device from a backup.

## CVE-2008-4230
The Passcode Lock feature in Apple iPhone OS 1.0 through 2.1 and iPhone OS for iPod touch 1.1 through 2.1 displays SMS messages when the emergency-call screen is visible, which allows physically proximate attackers to obtain sensitive information by reading these messages.  NOTE: this might be a duplicate of CVE-2008-4593.

## CVE-2008-4231
Safari in Apple iPhone OS 1.0 through 2.1 and iPhone OS for iPod touch 1.1 through 2.1 does not properly handle HTML TABLE elements, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted HTML document.

## CVE-2008-4232
Safari in Apple iPhone OS 2.0 through 2.1 and iPhone OS for iPod touch 2.1 through 2.1 does not restrict an IFRAME's content display to the boundaries of the IFRAME, which allows remote attackers to spoof a user interface via a crafted HTML document.

## CVE-2008-4233
Safari in Apple iPhone OS 1.0 through 2.1 and iPhone OS for iPod touch 1.1 through 2.1 does not isolate the call-approval dialog from the process of launching new applications, which allows remote attackers to make arbitrary phone calls via a crafted HTML document.

## CVE-2009-1698
WebKit in Apple Safari before 4.0, iPhone OS 1.0 through 2.2.1, and iPhone OS for iPod touch 1.1 through 2.2.1 does not initialize a pointer during handling of a Cascading Style Sheets (CSS) attr function call with a large numerical argument, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted HTML document.

## CVE-2009-1700
The XSLT implementation in WebKit in Apple Safari before 4.0, iPhone OS 1.0 through 2.2.1, and iPhone OS for iPod touch 1.1 through 2.2.1 does not properly handle redirects, which allows remote attackers to read XML content from arbitrary web pages via a crafted document.

## CVE-2009-1701
Use-after-free vulnerability in the JavaScript DOM implementation in WebKit in Apple Safari before 4.0, iPhone OS 1.0 through 2.2.1, and iPhone OS for iPod touch 1.1 through 2.2.1 allows remote attackers to execute arbitrary code or cause a denial of service (application crash) by destroying a document.body element that has an unspecified XML container with elements that support the dir attribute.

## CVE-2009-1702
Cross-site scripting (XSS) vulnerability in WebKit in Apple Safari before 4.0, iPhone OS 1.0 through 2.2.1, and iPhone OS for iPod touch 1.1 through 2.2.1 allows remote attackers to inject arbitrary web script or HTML via vectors related to improper handling of Location and History objects.

## CVE-2009-0958
Apple iPhone OS 1.0 through 2.2.1 and iPhone OS for iPod touch 1.1 through 2.2.1 stores an exception for a hostname when the user accepts an untrusted Exchange server certificate, which causes it to be accepted without prompting in future usage and allows remote Exchange servers to obtain sensitive information such as credentials.

## CVE-2009-0959
The MPEG-4 video codec in Apple iPhone OS 1.0 through 2.2.1 and iPhone OS for iPod touch 1.1 through 2.2.1 allows remote attackers to cause a denial of service (device reset) via a crafted MPEG-4 video file that triggers an "input validation issue."

## CVE-2009-0960
The Mail component in Apple iPhone OS 1.0 through 2.2.1 and iPhone OS for iPod touch 1.1 through 2.2.1 does not provide an option to disable remote image loading in HTML email, which allows remote attackers to determine the device address and when an e-mail is read via an HTML email containing an image URL.

## CVE-2009-0961
The Mail component in Apple iPhone OS 1.0 through 2.2.1 and iPhone OS for iPod touch 1.1 through 2.2.1 dismisses the call approval dialog when another alert appears, which might allow remote attackers to force the iPhone to place a call without user approval by causing an application to trigger an alert.

## CVE-2009-1679
The Profiles component in Apple iPhone OS 1.0 through 2.2.1 and iPhone OS for iPod touch 1.1 through 2.2.1, when installing a configuration profile, can replace the password policy from Exchange ActiveSync with a weaker password policy, which allows physically proximate attackers to bypass the intended policy.

## CVE-2009-1680
Safari in Apple iPhone OS 1.0 through 2.2.1 and iPhone OS for iPod touch 1.1 through 2.2.1 does not properly clear the search history when it is cleared from the Settings application, which allows physically proximate attackers to obtain the search history.

## CVE-2009-1683
The Telephony component in Apple iPhone OS 1.0 through 2.2.1 and iPhone OS for iPod touch 1.1 through 2.2.1 allows remote attackers to cause a denial of service (device reset) via a crafted ICMP echo request, which triggers an assertion error related to a "logic issue."

## CVE-2009-1692
WebKit before r41741, as used in Apple iPhone OS 1.0 through 2.2.1, iPhone OS for iPod touch 1.1 through 2.2.1, Safari, and other software, allows remote attackers to cause a denial of service (memory consumption or device reset) via a web page containing an HTMLSelectElement object with a large length attribute, related to the length property of a Select object.

## CVE-2009-1724
Cross-site scripting (XSS) vulnerability in WebKit in Apple Safari before 4.0.2, as used on iPhone OS before 3.1, iPhone OS before 3.1.1 for iPod touch, and other platforms, allows remote attackers to inject arbitrary web script or HTML via vectors related to parent and top objects.

## CVE-2009-1725
WebKit in Apple Safari before 4.0.2, as used on iPhone OS before 3.1, iPhone OS before 3.1.1 for iPod touch, and other platforms; KHTML in kdelibs in KDE; QtWebKit (aka Qt toolkit); and possibly other products do not properly handle numeric character references, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted HTML document.

## CVE-2009-2199
Incomplete blacklist vulnerability in WebKit in Apple Safari before 4.0.3, as used on iPhone OS before 3.1, iPhone OS before 3.1.1 for iPod touch, and other platforms, allows remote attackers to spoof domain names in URLs, and possibly conduct phishing attacks, via unspecified homoglyphs.

## CVE-2009-2206
Multiple heap-based buffer overflows in the AudioCodecs library in the CoreAudio component in Apple iPhone OS before 3.1, and iPhone OS before 3.1.1 for iPod touch, allow remote attackers to execute arbitrary code or cause a denial of service (application crash) via a crafted (1) AAC or (2) MP3 file, as demonstrated by a ringtone with malformed entries in the sample size table.

## CVE-2010-1029
Stack consumption vulnerability in the WebCore::CSSSelector function in WebKit, as used in Apple Safari 4.0.4, Apple Safari on iPhone OS and iPhone OS for iPod touch, and Google Chrome 4.0.249, allows remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a STYLE element composed of a large number of *> sequences.

## CVE-2010-1387
Use-after-free vulnerability in JavaScriptCore in WebKit in Apple iTunes before 9.2 on Windows, and Apple iOS before 4 on the iPhone and iPod touch, allows remote attackers to execute arbitrary code or cause a denial of service (application crash) via vectors related to page transitions, a different vulnerability than CVE-2010-1763 and CVE-2010-1769.

## CVE-2010-1407
WebKit in Apple iOS before 4 on the iPhone and iPod touch does not properly implement the history.replaceState method in certain situations involving IFRAME elements, which allows remote attackers to obtain sensitive information via a crafted HTML document.

## CVE-2010-1751
Application Sandbox in Apple iOS before 4 on the iPhone and iPod touch does not prevent photo-library access, which might allow remote attackers to obtain location information via unspecified vectors.

## CVE-2010-1756
The Settings application in Apple iOS before 4 on the iPhone and iPod touch does not properly report the wireless network that is in use, which might make it easier for remote attackers to trick users into communicating over an unintended network.

## CVE-2010-1775
Race condition in Passcode Lock in Apple iOS before 4 on the iPhone and iPod touch allows physically proximate attackers to bypass intended passcode requirements, and pair a locked device with a computer and access arbitrary data, via vectors involving the initial boot.

## CVE-2010-2913
The Citibank Citi Mobile app before 2.0.3 for iOS stores account data in a file, which allows local users to obtain sensitive information via vectors involving (1) the mobile device or (2) a synchronized computer.

## CVE-2010-2973
Integer overflow in IOSurface in Apple iOS before 4.0.2 on the iPhone and iPod touch, and before 3.2.2 on the iPad, allows local users to gain privileges via vectors involving IOSurface properties, as demonstrated by JailbreakMe.

## CVE-2010-1781
Double free vulnerability in WebKit in Apple iOS before 4.1 on the iPhone and iPod touch allows remote attackers to execute arbitrary code or cause a denial of service (application crash) via vectors related to the rendering of an inline element.

## CVE-2010-1810
FaceTime in Apple iOS before 4.1 on the iPhone and iPod touch does not properly handle invalid X.509 certificates, which allows man-in-the-middle attackers to redirect calls via a crafted certificate.

## CVE-2010-3832
Heap-based buffer overflow in the GSM mobility management implementation in Telephony in Apple iOS before 4.2 on the iPhone and iPad allows remote attackers to execute arbitrary code on the baseband processor via a crafted Temporary Mobile Subscriber Identity (TMSI) field.

## CVE-2011-1344
Use-after-free vulnerability in WebKit, as used in Apple Safari before 5.0.5; iOS before 4.3.2 for iPhone, iPod, and iPad; iOS before 4.2.7 for iPhone 4 (CDMA); and possibly other products allows remote attackers to execute arbitrary code by adding children to a WBR tag and then removing the tag, related to text nodes, as demonstrated by Chaouki Bekrar during a Pwn2Own competition at CanSecWest 2011.

## CVE-2012-2648
Cross-site scripting (XSS) vulnerability in the GoodReader app 3.16 and earlier for iOS on the iPad, and 3.15.1 and earlier for iOS on the iPhone and iPod touch, allows remote attackers to inject arbitrary web script or HTML via vectors involving use of this app in conjunction with a web browser.

## CVE-2014-0647
The Starbucks 2.6.1 application for iOS stores sensitive information in plaintext in the Crashlytics log file (/Library/Caches/com.crashlytics.data/com.starbucks.mystarbucks/session.clslog), which allows attackers to discover usernames, passwords, and e-mail addresses via an application that reads session.clslog.

## CVE-2015-7651
Use-after-free vulnerability in Adobe Flash Player before 18.0.0.261 and 19.x before 19.0.0.245 on Windows and OS X and before 11.2.202.548 on Linux, Adobe AIR before 19.0.0.241, Adobe AIR SDK before 19.0.0.241, and Adobe AIR SDK & Compiler before 19.0.0.241 allows attackers to execute arbitrary code via crafted DefineFunction atoms, a different vulnerability than CVE-2015-7652, CVE-2015-7653, CVE-2015-7654, CVE-2015-7655, CVE-2015-7656, CVE-2015-7657, CVE-2015-7658, CVE-2015-7660, CVE-2015-7661, CVE-2015-7663, CVE-2015-8042, CVE-2015-8043, CVE-2015-8044, and CVE-2015-8046.

## CVE-2015-7652
Use-after-free vulnerability in Adobe Flash Player before 18.0.0.261 and 19.x before 19.0.0.245 on Windows and OS X and before 11.2.202.548 on Linux, Adobe AIR before 19.0.0.241, Adobe AIR SDK before 19.0.0.241, and Adobe AIR SDK & Compiler before 19.0.0.241 allows attackers to execute arbitrary code via a crafted gridFitType property value, a different vulnerability than CVE-2015-7651, CVE-2015-7653, CVE-2015-7654, CVE-2015-7655, CVE-2015-7656, CVE-2015-7657, CVE-2015-7658, CVE-2015-7660, CVE-2015-7661, CVE-2015-7663, CVE-2015-8042, CVE-2015-8043, CVE-2015-8044, and CVE-2015-8046.

## CVE-2015-7653
Use-after-free vulnerability in Adobe Flash Player before 18.0.0.261 and 19.x before 19.0.0.245 on Windows and OS X and before 11.2.202.548 on Linux, Adobe AIR before 19.0.0.241, Adobe AIR SDK before 19.0.0.241, and Adobe AIR SDK & Compiler before 19.0.0.241 allows attackers to execute arbitrary code via crafted globalToLocal arguments, a different vulnerability than CVE-2015-7651, CVE-2015-7652, CVE-2015-7654, CVE-2015-7655, CVE-2015-7656, CVE-2015-7657, CVE-2015-7658, CVE-2015-7660, CVE-2015-7661, CVE-2015-7663, CVE-2015-8042, CVE-2015-8043, CVE-2015-8044, and CVE-2015-8046.

## CVE-2015-7654
Use-after-free vulnerability in Adobe Flash Player before 18.0.0.261 and 19.x before 19.0.0.245 on Windows and OS X and before 11.2.202.548 on Linux, Adobe AIR before 19.0.0.241, Adobe AIR SDK before 19.0.0.241, and Adobe AIR SDK & Compiler before 19.0.0.241 allows attackers to execute arbitrary code via crafted attachSound arguments, a different vulnerability than CVE-2015-7651, CVE-2015-7652, CVE-2015-7653, CVE-2015-7655, CVE-2015-7656, CVE-2015-7657, CVE-2015-7658, CVE-2015-7660, CVE-2015-7661, CVE-2015-7663, CVE-2015-8042, CVE-2015-8043, CVE-2015-8044, and CVE-2015-8046.

## CVE-2015-7655
Use-after-free vulnerability in Adobe Flash Player before 18.0.0.261 and 19.x before 19.0.0.245 on Windows and OS X and before 11.2.202.548 on Linux, Adobe AIR before 19.0.0.241, Adobe AIR SDK before 19.0.0.241, and Adobe AIR SDK & Compiler before 19.0.0.241 allows attackers to execute arbitrary code via crafted actionExtends arguments, a different vulnerability than CVE-2015-7651, CVE-2015-7652, CVE-2015-7653, CVE-2015-7654, CVE-2015-7656, CVE-2015-7657, CVE-2015-7658, CVE-2015-7660, CVE-2015-7661, CVE-2015-7663, CVE-2015-8042, CVE-2015-8043, CVE-2015-8044, and CVE-2015-8046.

## CVE-2015-7656
Use-after-free vulnerability in Adobe Flash Player before 18.0.0.261 and 19.x before 19.0.0.245 on Windows and OS X and before 11.2.202.548 on Linux, Adobe AIR before 19.0.0.241, Adobe AIR SDK before 19.0.0.241, and Adobe AIR SDK & Compiler before 19.0.0.241 allows attackers to execute arbitrary code via crafted actionImplementsOp arguments, a different vulnerability than CVE-2015-7651, CVE-2015-7652, CVE-2015-7653, CVE-2015-7654, CVE-2015-7655, CVE-2015-7657, CVE-2015-7658, CVE-2015-7660, CVE-2015-7661, CVE-2015-7663, CVE-2015-8042, CVE-2015-8043, CVE-2015-8044, and CVE-2015-8046.

## CVE-2015-7657
Use-after-free vulnerability in Adobe Flash Player before 18.0.0.261 and 19.x before 19.0.0.245 on Windows and OS X and before 11.2.202.548 on Linux, Adobe AIR before 19.0.0.241, Adobe AIR SDK before 19.0.0.241, and Adobe AIR SDK & Compiler before 19.0.0.241 allows attackers to execute arbitrary code via crafted actionCallMethod arguments, a different vulnerability than CVE-2015-7651, CVE-2015-7652, CVE-2015-7653, CVE-2015-7654, CVE-2015-7655, CVE-2015-7656, CVE-2015-7658, CVE-2015-7660, CVE-2015-7661, CVE-2015-7663, CVE-2015-8042, CVE-2015-8043, CVE-2015-8044, and CVE-2015-8046.

## CVE-2015-7658
Use-after-free vulnerability in Adobe Flash Player before 18.0.0.261 and 19.x before 19.0.0.245 on Windows and OS X and before 11.2.202.548 on Linux, Adobe AIR before 19.0.0.241, Adobe AIR SDK before 19.0.0.241, and Adobe AIR SDK & Compiler before 19.0.0.241 allows attackers to execute arbitrary code via crafted actionInstanceOf arguments, a different vulnerability than CVE-2015-7651, CVE-2015-7652, CVE-2015-7653, CVE-2015-7654, CVE-2015-7655, CVE-2015-7656, CVE-2015-7657, CVE-2015-7660, CVE-2015-7661, CVE-2015-7663, CVE-2015-8042, CVE-2015-8043, CVE-2015-8044, and CVE-2015-8046.

## CVE-2015-7659
Adobe Flash Player before 18.0.0.261 and 19.x before 19.0.0.245 on Windows and OS X and before 11.2.202.548 on Linux, Adobe AIR before 19.0.0.241, Adobe AIR SDK before 19.0.0.241, and Adobe AIR SDK & Compiler before 19.0.0.241 allow attackers to execute arbitrary code by leveraging an unspecified "type confusion" in the NetConnection object implementation.

## CVE-2015-7660
Use-after-free vulnerability in Adobe Flash Player before 18.0.0.261 and 19.x before 19.0.0.245 on Windows and OS X and before 11.2.202.548 on Linux, Adobe AIR before 19.0.0.241, Adobe AIR SDK before 19.0.0.241, and Adobe AIR SDK & Compiler before 19.0.0.241 allows attackers to execute arbitrary code via crafted setMask arguments, a different vulnerability than CVE-2015-7651, CVE-2015-7652, CVE-2015-7653, CVE-2015-7654, CVE-2015-7655, CVE-2015-7656, CVE-2015-7657, CVE-2015-7658, CVE-2015-7661, CVE-2015-7663, CVE-2015-8042, CVE-2015-8043, CVE-2015-8044, and CVE-2015-8046.

## CVE-2015-7661
Use-after-free vulnerability in Adobe Flash Player before 18.0.0.261 and 19.x before 19.0.0.245 on Windows and OS X and before 11.2.202.548 on Linux, Adobe AIR before 19.0.0.241, Adobe AIR SDK before 19.0.0.241, and Adobe AIR SDK & Compiler before 19.0.0.241 allows attackers to execute arbitrary code via a crafted getBounds call, a different vulnerability than CVE-2015-7651, CVE-2015-7652, CVE-2015-7653, CVE-2015-7654, CVE-2015-7655, CVE-2015-7656, CVE-2015-7657, CVE-2015-7658, CVE-2015-7660, CVE-2015-7663, CVE-2015-8042, CVE-2015-8043, CVE-2015-8044, and CVE-2015-8046.

## CVE-2015-7662
Adobe Flash Player before 18.0.0.261 and 19.x before 19.0.0.245 on Windows and OS X and before 11.2.202.548 on Linux, Adobe AIR before 19.0.0.241, Adobe AIR SDK before 19.0.0.241, and Adobe AIR SDK & Compiler before 19.0.0.241 allow remote attackers to bypass intended access restrictions and write to files via unspecified vectors.

