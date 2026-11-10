# Research notes: portability across ChromeOS, macOS and Linux

Raw findings from the research pass on 2026-11-10.
DESIGN.md section 10 and the paper section "Portability" use these notes.

## macOS as the key host

* Verified: libfido2 finds FIDO keys with IOHIDManager (usage page 0xF1D0) and opens them with kIOHIDOptionsTypeSeizeDevice; input through IOHIDDeviceRegisterInputReportCallback, output through IOHIDDeviceSetReport.
  https://github.com/Yubico/libfido2/blob/7ef25ec477bd2f03986e74f6acd8ffc37238fc1a/src/hid_osx.c#L201 , #L259, #L451, #L469, #L588
* Verified: Chromium opens HID devices with kIOHIDOptionsTypeNone.
  https://github.com/chromium/chromium/blob/a1ebdbe91c3de5b2bf06c0c326cd9d07f752a223/services/device/hid/hid_service_mac.cc#L175
* Verified: while one client has seized a device, others get kIOReturnExclusiveAccess.
  https://github.com/apple-oss-distributions/IOHIDFamily/blob/777ccd9698845aadf711e32d843c8c9b777431d9/IOHIDFamily/IOHIDLibUserClient.cpp#L1626
* Assumption: a relay that opens with kIOHIDOptionsTypeNone lets the Mac's own Chrome keep using the key; all clients see all input reports, and CTAPHID channel IDs keep them apart.
* Verified: Input Monitoring (TCC) is required only for devices with kIOHIDRequiresTCCAuthorization, which the kernel sets on keyboards, mice and touchpads.
  https://github.com/apple-oss-distributions/IOHIDFamily/blob/777ccd9698845aadf711e32d843c8c9b777431d9/IOHIDFamily/IOHIDDevice.cpp#L527-L531 , IOHIDLib/IOHIDDeviceClass.m#L510-L532
* Verified: a non-root process needs kIOClientPrivilegeLocalUser, which passes only when its uid has a console (GUI) session.
  https://github.com/apple-oss-distributions/IOHIDFamily/blob/777ccd9698845aadf711e32d843c8c9b777431d9/IOHIDFamily/IOHIDLibUserClient.cpp#L332 , #L710-L714 ; xnu iokit/Kernel/IOUserClient.cpp#L1504-L1531
* Assumption: over SSH, a non-root relay works only while the same user is logged in at the Mac's screen.

## Go libraries for macOS HID

* rafaelmartins/usbhid (module path `rafaelmartins.com/p/usbhid`): BSD-3, pure Go on darwin through ebitengine/purego v0.9.1, last commit 2026-10-05; opens with kIOHIDOptionsTypeNone by default.
  Verified here: `bazel build @com_rafaelmartins_p_usbhid//:usbhid --@rules_go//go/config:pure` succeeds for darwin_arm64 and darwin_amd64 from Linux, with no Apple SDK.
  https://github.com/rafaelmartins/usbhid/blob/3657fb472d94eda451e0e7d3d291b91d9ad0a8a7/device_darwin.go#L15 , #L204, #L593-L611
* ebitengine/purego: Apache-2.0, last commit 2026-11-07, darwin fakecgo runtime.
  https://github.com/ebitengine/purego/tree/3716594ee18e266013ce32e40c130a717587b543/internal/fakecgo
* flynn/hid (cgo, 2019), sstallion/go-hid (hidapi, cgo, 2025-05), karalabe/hid (cgo only, 2026-03), karalabe/usb (cgo, 2023-12), bearsh/hid (cgo, 2024-09).

## macOS as the use host

* Verified: IOHIDUserDeviceCreate needs entitlement com.apple.developer.hid.virtual.device (or an Apple-private one); without it, the call fails, also for root.
  https://github.com/apple-oss-distributions/IOHIDFamily/blob/777ccd9698845aadf711e32d843c8c9b777431d9/IOHIDFamily/IOHIDResourceUserClient.cpp#L32-L33 , #L117-L148
* Verified: entitlement available from macOS 10.15; CoreHID HIDVirtualDevice needs macOS 15.
  https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.hid.virtual.device , https://developer.apple.com/documentation/corehid/hidvirtualdevice
* Verified: the entitlement is requested from Apple and reviewed; one request was pending after 2.5 months.
  https://developer.apple.com/forums/thread/845599 , https://developer.apple.com/forums/thread/843327
* Assumption: it needs a provisioning profile and a Developer ID signature; an ad-hoc signed Go binary cannot hold it.
* Verified: DriverKit virtual HID needs Apple-granted entitlements and a user-approved system extension (Karabiner entitlements file).
  https://github.com/pqrs-org/Karabiner-DriverKit-VirtualHIDDevice/blob/212a0f660702e33a3874895c4db991061e68e0e2/src/DriverKit/entitlements.plist
* Verified: bulwarkid/virtual-fido on macOS uses its own DriverKit extension; needs SIP off for development or Apple-approved signing.
  https://github.com/bulwarkid/virtual-fido/blob/512d8a3fef0e073171a7ef3261f300e8a5e48694/mac/USBDriver/README.md
* Verified: github/SoftU2F used a kernel extension; deprecated, last commit 2020-12-14.
* Assumption: Chrome on macOS would list a virtual 0xF1D0 device (its HID service has no transport filter, hid_service_mac.cc L92); untested.

## ChromeOS as the use host

* Verified: the termina kernel config (chromeos-6.6, commit c3031f3e) has no UHID or HIDRAW option.
  https://chromium.googlesource.com/chromiumos/third_party/kernel/+/c3031f3e2ec63700bda45fbec3b10d4794b27816/chromeos/config/termina/base.config#328
* Assumption: a device made inside Crostini would not reach ChromeOS Chrome, which sees only host devices.

## Linux

* Verified: systemd tags hidraw FIDO devices ID_SECURITY_TOKEN=1 and gives them the uaccess tag.
  https://github.com/systemd/systemd/blob/76e9aee9e5296f65387ffe8f16b319354f236fd5/rules.d/60-fido-id.rules#L5-L8 , rules.d/70-uaccess.rules.in#L67
* Assumption: over SSH, uaccess helps only while the same user is logged in at the seat; otherwise a group rule is needed.

## Windows (contrast)

* Verified: since Windows 10 1903, raw FIDO HID access needs Administrator; other programs use webauthn.dll.
  https://github.com/Yubico/python-fido2/blob/main/README.adoc#L65
