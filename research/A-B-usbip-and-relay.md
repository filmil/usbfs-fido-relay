# Research notes: approaches A and B

Raw findings from the research pass on 2026-11-10.
DESIGN.md uses these notes.

## Crostini (both approaches)

* Verified: tremplin passes only uevents of subsystem block, tty and usb into the container, as unix-char devices with mode 0666.
  The container gets /dev/bus/usb/BBB/DDD and no /dev/hidraw node.
  chromiumos/platform/tremplin src/chromiumos/tremplin/start_lxd.go L192-228 and L366, commit 744f7e4.
* Verified: Chrome asks permission_broker for all interfaces (cros_usb_detector.cc L651-660, L1036-1040); HID-only devices get no share notification but stay shareable (L416-435).
  https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/ash/usb/cros_usb_detector.cc
* Verified: permission_broker gives ALLOW_WITH_DETACH to devices tagged external; the legacy flow gives ALLOW_WITH_LOCKDOWN or DENY for a key with usbhid bound; policy UsbDetachableAllowlist overrides.
  https://chromium.googlesource.com/chromiumos/platform2/+/main/permission_broker/allow_conforming_usb_device_rule.cc
* Verified: a 2025 report: LOCKDOWN, then DENY on a Chromebook Plus; ALLOW_WITH_DETACH on an older Chromebook; disabling Smart Card Connector fixed it.
  https://groups.google.com/a/chromium.org/g/chromium-os-dev/c/2bVDprdrLOY
* Verified: USBDEVFS_DISCONNECT has no capability check in the kernel (drivers/usb/core/devio.c, proc_ioctl).
  https://github.com/torvalds/linux/blob/master/drivers/usb/core/devio.c
* Verified: `vmc key-attach` (crosvm virtual U2F) shares the key with ChromeOS but supports U2F only; FIDO2 hangs.
  https://groups.google.com/a/chromium.org/g/crosvm-dev/c/D5iCnoTk-4k , https://crosvm.dev/book/devices/virtual_u2f.html

## A. Userspace USB/IP

* jiegec/usbip: Rust, MIT, last push 2026-11-09.
  Verified: exports real devices through rusb or nusb; control, interrupt and bulk; no isochronous (src/host.rs L46-97, L198-326).
  Verified: one blocking transfer at a time with a 1 s timeout; a timeout returns success with 0 bytes (host.rs L44, L97); UNLINK is answered without a cancel (src/lib.rs L532-611).
  Verified: issue #51, a YubiKey attached but WebAuthn did not see it, closed stale; issue #63, interrupt IN polled every few microseconds, closed stale.
  https://github.com/jiegec/usbip/issues/51 , https://github.com/jiegec/usbip/issues/63
* yunsmall/usbipdcpp: C++, LGPL-3.0, created 2025-07, last push 2026-11-09.
  Verified: libusb_submit_transfer (async), cancels on UNLINK, detaches kernel drivers (src/LibusbHandler/LibusbDeviceHandler.cpp L230, L104, L964, L997).
  Assumption: maturity and YubiKey behavior unknown.
* jwise/pyusbip: Apache-2.0, 2018; sends bulk requests to interrupt endpoints. Unsuitable.
* Verified: YubiKey interfaces: OTP is a HID keyboard; FIDO is HID; CCID serves PIV, OATH, OpenPGP.
  https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-usb-interface.html
* Verified: Debian builds CONFIG_USBIP_VHCI_HCD=m and ships the usbip package; Ubuntu ships vhci-hcd in linux-modules-extra and usbip in linux-tools.
  https://packages.debian.org/trixie/usbip
* Verified: USB/IP has no access control and no encryption (Debian package description).

## B. CTAPHID relay

* txomon/fido-forward: Go, MIT, commit 2b7b2ac on 2026-10-06, about 40 commits, one author.
  Verified: raw 64-byte reports over `ssh -T` stdio; FFWD 0x01 marker exchange; no framing (docs/REQUIREMENTS.md, "Wire protocol").
  Verified: key side opens /dev/hidrawN as the ssh user; use side is setuid `fidofwd`, opens /dev/uhid, drops privilege first.
  Verified: channel filter only (internal/ctaphid/filter.go); no CTAP command filter.
  Verified here: builds with Bazel (rules_go, pure, linux amd64 and arm64).
* QubesOS/qubes-app-u2f: Python, GPL-2.0+, commit 069a20b on 2026-10-08.
  Verified: uhid on the browser side; relays parsed CTAP, not raw reports; passes only getInfo, clientPIN, makeCredential, getAssertion (protocol.py L485-495); sends no keepalives.
  Verified: open issues #10981, #11208, #9001, #10808, #6480.
* Verified: Chrome discovers any HID device with usage page 0xF1D0, on any bus (device/fido/hid/fido_hid_discovery.cc L46-47, L77-86).
* Verified: Chrome's FIDO device timeout is 20 s and each keepalive re-arms it (device/fido/public/fido_constants.cc L191, device/fido/hid/fido_hid_device.cc L387-392).
* Verified: systemd fido_id sets ID_SECURITY_TOKEN=1, then uaccess gives the node to the seat user (src/udev/fido_id/fido_id.c, rules.d/60-fido-id.rules, 70-uaccess.rules.in L67).
* Assumption: a Chrome Remote Desktop session is not the active seat, so it needs a group rule such as fido-forward's 91-fido-forward-hidraw.rules.
* Verified: CTAP 2.1 command codes; reset needs user interaction within 10 s of power-up.
  https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorReset
* Verified: CTAPHID_KEEPALIVE should come at least every 100 ms (CTAP 2.1 section 11.2.9.1.7).
