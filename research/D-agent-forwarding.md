# Research notes: approach D (agent forwarding)

Raw findings from the research pass on 2026-11-10.
DESIGN.md uses these notes.

## ssh-agent with sk keys

* Verified: sk keys since OpenSSH 8.2; they can be added to ssh-agent; the token must be attached where the key is used.
  https://www.openssh.org/txt/release-8.2
* Verified: the agent signs locally; private keys never cross the network.
  https://man.openbsd.org/ssh-agent.1
* Verified: OpenSSH uses libfido2 inside ssh-sk-helper.
  https://www.openssh.org/txt/release-8.2
* Assumption: in penguin, libfido2 needs a readable /dev/hidraw node for the FIDO interface.
* Verified (8.4): ssh-agent refuses WebAuthn-like signatures for keys whose application does not start with "ssh:".
  https://www.openssh.org/txt/release-8.4
* Verified (8.9): agent destination constraints (`ssh-add -h`); PIN-required FIDO keys in the agent, PIN asked locally with SSH_ASKPASS.
  https://www.openssh.org/txt/release-8.9 , https://man.openbsd.org/ssh-add , https://www.openssh.org/agent-restrict.html
* Verified: `-O resident`, `ssh-keygen -K`, `ssh-add -K`; `-O verify-required` (8.4).
  https://man.openbsd.org/ssh-keygen , https://www.openssh.org/txt/release-8.4
* Verified: ed25519-sk needs YubiKey firmware 5.2.3 or later.
  https://developers.yubico.com/SSH/Securing_SSH_with_FIDO2.html

## PIV through PKCS#11

* Verified: `ssh-add -s <module>` with ykcs11.
  https://developers.yubico.com/PIV/Guides/SSH_with_PIV_and_PKCS11.html
* Assumption: ykcs11 and OpenSC need pcscd and libccid in penguin.
* Verified: since 9.3p2 a forwarded agent does not load PKCS#11 or FIDO providers for remote clients (CVE-2023-38408).
  https://www.openssh.org/txt/release-9.3p2
* Verified: p11-kit server forwards a PKCS#11 token over a Unix socket and `ssh -R`; BSD-3-Clause; release 0.26.5 on 2026-08-06.
  https://p11-glue.github.io/p11-glue/p11-kit/manual/remoting.html , https://github.com/p11-glue/p11-kit

## gpg-agent extra socket

* Verified: GnuPG 2.1.1+; extra socket default since 2.1.17; `RemoteForward`; `StreamLocalBindUnlink yes`; `gpgconf --create-socketdir`; `--no-autostart` on the remote side; remote needs the public keys.
  https://wiki.gnupg.org/AgentForwarding
* Verified (source): restricted mode refuses most SCD commands and key export.
  https://github.com/gpg/gnupg/blob/master/agent/command.c
* Assumption: remote `gpg --card-status` fails; signing and decryption work.

## Crostini

* Verified: Google's FAQ says USB support is per device; it says nothing about security keys.
  https://developers.google.com/chromeos/app-development/develop/linux-on-chromeos-faq
* Verified: Chrome opens the device for the VM with kAllInterfacesMask through permission_broker.
  https://github.com/chromium/chromium/blob/main/chrome/browser/ash/usb/cros_usb_detector.cc
* Verified: permission_broker returns ALLOW_WITH_DETACH for external devices; legacy flow uses ALLOW_WITH_LOCKDOWN for kernel-claimed HID.
  https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/permission_broker/allow_conforming_usb_device_rule.cc
* Verified: users report gpg and PIV working after sharing; sharing must be re-enabled on each plug-in.
  https://worklifenotes.com/2021/12/02/yubikey-for-ssh-on-linux-and-chromebook/ , https://andrew.jorgensenfamily.us/2025/02/ssh-yubikey-gpg-chromeos/
* Verified: the Smart Card Connector app takes the key and blocks Linux and Android.
  https://groups.google.com/a/chromium.org/g/chromium-os-dev/c/7lvuQOVJbBo/m/JI0YnV7QAQAJ
* Verified (2025): `vmc usb-attach` locks the key away from the ChromeOS browser; `vmc key-attach` (virtual U2F passthrough) supports U2F only, and FIDO2 traffic hangs (maintainer confirms).
  https://groups.google.com/a/chromium.org/g/crosvm-dev/c/D5iCnoTk-4k
* Not found: a report of ed25519-sk working in Crostini through "Manage USB devices".

## Security and timeouts

* Verified: anyone who can reach a forwarded agent socket can use it while the session is open.
  https://www.openssh.org/agent-restrict.html
* Verified: `ssh-add -c` confirm, `-t` lifetime; the agent shows "Confirm user presence" for sk keys.
  https://man.openbsd.org/ssh-add , https://github.com/openssh/openssh-portable/blob/master/ssh-agent.c
* Verified (source): sk-usbhid waits SELECT_MS 15000 when it selects among tokens by touch.
  https://github.com/openssh/openssh-portable/blob/master/sk-usbhid.c
