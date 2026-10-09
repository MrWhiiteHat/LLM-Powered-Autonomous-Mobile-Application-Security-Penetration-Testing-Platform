# OSV Android SDK Library Vulnerabilities

## ASB-A-111893654: Affected Packages: :linux_kernel:
In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-112551163: Affected Packages: :linux_kernel:
In ip_check_mc_rcu of igmp.c, there is a possible use after free due to improper locking. This could lead to local escalation of privilege when opening and closing inet sockets with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-119041698: Affected Packages: platform/frameworks/base
In several functions of NotificationManagerService.java and related files, there is a possible way to record audio from the background without notification to the user due to a permission bypass. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-123700107: Affected Packages: platform/frameworks/base, platform/frameworks/base
In checkKeyIntent of AccountManagerService.java, there is a possible permission bypass. This could lead to local information disclosure with User execution privileges needed. User interaction is needed for exploitation.

## ASB-A-129287265: Affected Packages: platform/frameworks/base, platform/frameworks/base, platform/frameworks/base
In Account of Account.java, there is a possible boot loop due to improper input validation. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-129476618: Affected Packages: platform/cts, platform/frameworks/base, platform/cts, platform/frameworks/base, platform/cts, platform/frameworks/base, platform/cts, platform/frameworks/base
In onCommand of CompanionDeviceManagerService.java, there is a possible permissions bypass due to a missing permission check. This could lead to local escalation of privilege allowing background data usage or launching from the background, with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-130373736: Affected Packages: :unknown:
In driver/firmware of broadcom wifi chipset, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-130374366: Affected Packages: :unknown:
In driver/firmware of broadcom wifi chipset, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-134155286: Affected Packages: platform/packages/providers/MediaProvider, platform/packages/providers/MediaProvider
In parseNextBox of IsoInterface.java, there is a possible leak of unredacted location information due to improper input validation. This could lead to remote information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.

## ASB-A-135368228: Affected Packages: :linux_kernel:
In i915_gem_execbuffer2_ioctl of i915_gem_execbuffer.c, there is a possible arbitrary kernel memory write due to a missing validation of a userspace pointer. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-137284057: Affected Packages: platform/frameworks/native
In SurfaceFlinger::createLayer of SurfaceFlinger.cpp, there is a possible arbitrary code execution due to improper casting. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-140108616: Affected Packages: platform/frameworks/base, platform/packages/apps/Settings, platform/packages/services/Car, platform/frameworks/base, platform/packages/apps/Settings, platform/packages/services/Car, platform/frameworks/base, platform/packages/apps/Settings, platform/packages/services/Car
In postNotification of ServiceRecord.java, there is a possible bypass of foreground process restrictions due to an uncaught exception. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-140256621: Affected Packages: platform/frameworks/base, platform/frameworks/base, platform/frameworks/base, platform/frameworks/base, platform/frameworks/base, platform/frameworks/base
In generatePackageInfo of PackageManagerService.java, there is a possible permissions bypass due to an incorrect permission check. This could lead to local escalation of privilege that allows instant apps access to permissions not allowed for instant apps, with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-140417248: Affected Packages: :unknown:, :unknown:, :unknown:, :unknown:
In onCreate of ConfirmConnectActivity.java, there is a possible leak of Bluetooth information due to a permissions bypass. This could lead to local escalation of privilege of a pairing Bluetooth MAC address with no additional execution privileges needed. User interaction is needed for exploitation.

## ASB-A-141745510: Affected Packages: platform/frameworks/base, platform/frameworks/base, platform/frameworks/base, platform/frameworks/base
In addWindow of WindowManagerService.java, there is a possible window overlay attack due to an insecure default value. This could lead to local escalation of privilege via tapjacking with no additional execution privileges needed. User interaction is needed for exploitation.

## ASB-A-142125338: Affected Packages: platform/frameworks/base, platform/frameworks/base, platform/frameworks/base
In generateInfo of PackageInstallerSession.java, there is a possible leak of cross-profile URI data during app installation due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-142546668: Affected Packages: platform/system/bt
In a2dp_vendor_ldac_decoder_decode_packet of a2dp_vendor_ldac_decoder.cc, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-142641801: Affected Packages: platform/frameworks/av
In ~AACExtractor() of AACExtractor.cpp, there is a possible out of bounds write due to uninitialized data. This could lead to remote information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.

## ASB-A-143230980: Affected Packages: platform/frameworks/base, platform/packages/providers/ContactsProvider
In queryInternal of CallLogProvider.java, there is a possible permission bypass due to improper input validation. This could lead to local information disclosure of voicemail metadata with User execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-143464314: Affected Packages: :unknown:
In hevcd_fmt_conv_420sp_to_420sp_av8 of ihevcd_fmt_conv_420sp_to_420sp.s, there is a possible out of bounds write due to a heap buffer overflow. This could lead to remote information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.

## ASB-A-143559931: Affected Packages: platform/frameworks/base, platform/frameworks/base
In ResolverActivity, there is a possible user interaction bypass due to a tapjacking/overlay attack. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation.

## ASB-A-145728612: Affected Packages: :linux_kernel:
In multiple methods, there is a possible out of bounds read due to a missing bounds check during initial processing of a beacon packet. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-145728687: Affected Packages: platform/frameworks/base, platform/frameworks/base, platform/frameworks/base, platform/frameworks/base
In loadAnimation of WindowContainer.java, there is a possible way to keep displaying a malicious app while a target app is brought to the foreground. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.

## ASB-A-146204120: Affected Packages: platform/frameworks/base, platform/frameworks/base, platform/frameworks/base, platform/frameworks/base
In verifyIntentFiltersIfNeeded of PackageManagerService.java, there is a possible settings bypass allowing an app to become the default handler for arbitrary domains. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-146398979: Affected Packages: platform/system/bt, platform/system/bt, platform/system/bt, platform/system/bt
In allocExcessBits of bitalloc.c, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-146570216: Affected Packages: platform/packages/services/Telephony
In getUiccCardsInfo of PhoneInterfaceManager.java, there is a possible permissions bypass due to improper input validation. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-147102899: Affected Packages: :linux_kernel:Qualcomm
No details available.

## ASB-A-147103019: Affected Packages: :linux_kernel:Qualcomm
No details available.

## ASB-A-147104886: Affected Packages: :linux_kernel:Qualcomm
No details available.

## ASB-A-147247775: Affected Packages: :unknown:, :unknown:, :unknown:, :unknown:
In the permission declaration for com.google.android.providers.gsf.permission.WRITE_GSERVICES in AndroidManifest.xml, there is a possible permissions bypass. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-147358092: Affected Packages: platform/frameworks/base, platform/frameworks/base, platform/frameworks/base, platform/frameworks/base, platform/frameworks/base, platform/frameworks/base
In Message and toBundle of Notification.java, there is a possible UI slowdown or crash due to improper input validation. This could lead to remote denial of service if a malicious contact file is received, with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-147664838: Affected Packages: platform/external/chromium-libpac, platform/external/v8, platform/external/chromium-libpac, platform/external/v8, platform/external/chromium-libpac, platform/external/v8, platform/external/chromium-libpac, platform/external/v8
In FastKeyAccumulator::GetKeysSlow of keys.cc, there is a possible out of bounds write due to type confusion. This could lead to remote code execution when processing a proxy configuration with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-147802478: Affected Packages: :linux_kernel:
In do_epoll_ctl and ep_loop_check_proc of eventpoll.c, there is a possible use after free due to a logic error. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-148588557: Affected Packages: :linux_kernel:
In __flow_hash_from_keys of flow_dissector.c, there is a possible packet injection due to improperly used crypto. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-148816706: Affected Packages: :linux_kernel:Qualcomm
No details available.

## ASB-A-149871374: Affected Packages: :unknown:
There is a possible out of bounds write due to an incorrect bounds check.

## ASB-A-150156492: Affected Packages: platform/system/bt, platform/system/bt, platform/system/bt, platform/system/bt
In the Bluetooth service, there is a possible spoofing attack due to a logic error. This could lead to remote information disclosure of sensitive information with no additional execution privileges needed. User interaction is needed for exploitation.

## ASB-A-150159669: Affected Packages: platform/external/sonivox, platform/external/sonivox, platform/external/sonivox, platform/external/sonivox
In Parse_wave of eas_mdls.c, there is a possible out of bounds write due to an integer overflow. This could lead to remote information disclosure in a highly constrained process with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-150159906: Affected Packages: platform/external/sonivox, platform/external/sonivox, platform/external/sonivox, platform/external/sonivox
In Parse_art of eas_mdls.c, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote information disclosure in the media extractor with no additional execution privileges needed. User interaction is needed for exploitation.

## ASB-A-150160041: Affected Packages: platform/external/sonivox, platform/external/sonivox, platform/external/sonivox, platform/external/sonivox
In Parse_insh of eas_mdls.c, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote information disclosure in the media extractor with no additional execution privileges needed. User interaction is needed for exploitation.

## ASB-A-150160279: Affected Packages: platform/external/sonivox, platform/external/sonivox, platform/external/sonivox, platform/external/sonivox
In Parse_ins of eas_mdls.c, there is a possible out of bounds write due to a missing bounds check. This could lead to remote information disclosure in the media extractor process with no additional execution privileges needed. User interaction is needed for exploitation.

## ASB-A-150226608: Affected Packages: platform/frameworks/native, platform/frameworks/native
In getLayerDebugInfo of SurfaceFlinger.cpp, there is a possible code execution due to a double free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-150226994: Affected Packages: platform/frameworks/native
In createWithSurfaceParent of Client.cpp, there is a possible out of bounds write due to type confusion. This could lead to local escalation of privilege in the graphics server with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-150371903: Affected Packages: platform/frameworks/native, platform/system/netd
In resolv_cache_lookup of res_cache.cpp, there is a possible side channel information disclosure. This could lead to local information disclosure of accessed web resources with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-150693166: Affected Packages: :linux_kernel:
In audit_free_lsm_field of auditfilter.c, there is a possible bad kfree due to a logic error in audit_data_to_entry. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-150693748: Affected Packages: :linux_kernel:
In __locks_wake_up_blocks of locks.c, there is a possible out of bounds write due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-150694665: Affected Packages: :linux_kernel:
In gre_handle_offloads of ip_gre.c, there is a possible page fault due to an invalid memory access. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-150706594: Affected Packages: platform/external/v8
In NewFixedDoubleArray of factory.cc, there is a possible out of bounds write due to an integer overflow. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation.

## ASB-A-150857253: Affected Packages: platform/frameworks/base, platform/frameworks/base, platform/frameworks/base, platform/frameworks/base
In setInstallerPackageName of PackageManagerService.java, there is a missing permission check. This could lead to local escalation of privilege and granting spurious permissions with no additional execution privileges needed. User interaction is not needed for exploitation.

## ASB-A-150946634: Affected Packages: platform/packages/apps/Settings, platform/packages/apps/Settings, platform/packages/apps/Settings, platform/packages/apps/Settings
In updatePreferenceIntents of AccountTypePreferenceLoader, there is a possible confused deputy attack due to a race condition. This could lead to local escalation of privilege and launching privileged activities with no additional execution privileges needed. User interaction is not needed for exploitation.

