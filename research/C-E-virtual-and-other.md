# Research notes: approaches C and E

Raw findings from the research pass on 2026-11-10.
DESIGN.md uses these notes.

## C. Virtual FIDO device

* bulwarkid/virtual-fido: MIT, Go, last commit 512d8a3 on 2024-06-23, beta, 38 open issues.
  Verified: it makes the device with a local USB/IP server and `usbip attach` (client_usbip.go L13-20, cmd/demo/exec_linux.go L9, README L31).
  Verified: signing is internal: `PrivateKey.Sign(authData||clientDataHash)` at ctap/ctap.go L250 and L364; it builds authData itself (L162).
  https://github.com/bulwarkid/virtual-fido/blob/512d8a3fef0e073171a7ef3261f300e8a5e48694/ctap/ctap.go#L364
  Conclusion: it cannot pass a signature through to a real key; delegation means forwarding whole CTAP commands, which is approach B.
* psanford/tpm-fido: MIT, Go, uhid, last commit 2023-06-22, U2F only (fidohid/fidohid.go L437, tpmfido.go L109).
* danstiner/rust-u2f: Apache-2.0 or MIT, Rust, uhid, last commit 2023-09-15, U2F only.
* ellerh/softfido: Rust, no license, last commit 2022-11-12, USB/IP, PKCS#11 back end.

## Existing approach B implementations

* txomon/fido-forward: MIT, Go, single commit 2b7b2ac, created 2026-10-06.
  Verified: uhid device on the use host, relayed over `ssh -T` to /dev/hidrawN on the key host; `-R` reverses the direction; FIDO only; installed setuid to a `fidofwd` user.
  https://github.com/txomon/fido-forward
* neroduality/pcsc-fido: Apache-2.0, C, last commit 2026-10-29; uhid FIDO device that relays to NFC keys over PC/SC.
  https://github.com/neroduality/pcsc-fido

## E1. Hybrid (phone)

* Verified: hybrid needs a BLE advertisement near the client (CTAP 2.2, Hybrid).
  https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-hybrid
* freQuensy23-coder/passkey-bridge: Apache-2.0, Python, 2026-11-03, macOS local side only, uses webAuthenticationProxy on the remote.

## E2. CRD forwarding

* Verified: policy RemoteAccessHostAllowGnubbyAuth is internal_only.
  https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/RemoteAccess/RemoteAccessHostAllowGnubbyAuth.yaml
* Verified: remoting/host/webauthn accepts only hard-coded CRD extension IDs (remote_webauthn_constants.cc L11, L35-55).
* Verified: WebAuthenticationRemoteProxiedRequestsAllowed is internal_only.
* Verified: WebAuthenticationRemoteDesktopAllowedOrigins (136+) is public but for affiliated (managed) users only.

## E3. Browser-level WebAuthn proxy

* Verified: chrome.webAuthenticationProxy (Chrome 115+, MV3); attach() takes over WebAuthn; requests arrive as requestDetailsJson with no origin field.
  https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy
* parallelworks/auth-relay: no license, Python and JS, last commit 2026-05-18.
  Verified: remote extension builds clientDataJSON and sends CTAP2 CBOR over `ssh -R` to python-fido2 on the laptop.
  Verified: origin is taken from the active tab as a best-effort guess (vdi/extension/background.js L298-305).
  https://github.com/parallelworks/auth-relay/blob/851f1e9a89e9dee3aa440e8171c02f9e1d0debd8/docs/architecture.md
* pedropaulovc/passkey: MIT, Go, 2026-08-12; same API, WSL to Windows.

## E4. PC/SC forwarding

* frankmorgner/vsmartcard: GPL-3.0, C and Python, last commit 2026-10-15.
  Verified: vpcd listens on TCP 35963 (vpcd.h L59); `vicc --type=relay` relays a local card; `--reverse` picks the connecting side (vicc.in L38-72).
* Assumption: works for YubiKey PIV and OpenPGP; untested.

## E5. Use the Chromebook's own Chrome

* Assumption: `ssh -D` SOCKS proxy keeps the real hostname, so the RP ID matches; `-L` to localhost does not.
* Verified: RP ID rules, https://www.w3.org/TR/webauthn-3/#relying-party-identifier

## E6. OpenSSH

* Verified: the agent signs locally (ssh-agent.c L970-990 at 1d28115).
* Verified: 8.4 stops a forwarded agent from signing web challenges with non-"ssh:" keys.
* mgbowen/windows-fido-bridge: Apache-2.0, SK middleware for WSL.
