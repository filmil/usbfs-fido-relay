[![test](https://github.com/filmil/usbfs-fido-relay/actions/workflows/test.yml/badge.svg)](https://github.com/filmil/usbfs-fido-relay/actions/workflows/test.yml)
[![release](https://github.com/filmil/usbfs-fido-relay/actions/workflows/release.yml/badge.svg)](https://github.com/filmil/usbfs-fido-relay/actions/workflows/release.yml)

# usbfs-fido-relay

Use a FIDO security key that is plugged into a Chromebook from a remote Linux host, over SSH.
`ffwd-usbfs` reads the key through its raw USB node, the only way in from the Chromebook's Linux container (Crostini), and relays it to [fido-forward](https://github.com/txomon/fido-forward)'s sink, which makes a virtual key on the remote host.
Tested with a YubiKey 5.

The repository started as a design study, and it still holds the study.
YubiKey is a trademark of Yubico AB; this project is not affiliated with Yubico.

* [DESIGN.md](DESIGN.md): the approaches, the comparison, the recommendation, and the open questions.
* [TESTPLAN.md](TESTPLAN.md): the tests to run on the real Chromebook and the remote host.
* [research/](research/): the raw research notes, with sources.
* [paper/](paper/): the same study as an IEEE two-column paper; build it with `bazel build //paper:usbfs-fido-relay`.

## Status and safety

This is a research prototype, not a finished product.

* **Tested once, end to end:** on 2026-11-09, a Chromebook (amd64) with a YubiKey 5 (firmware 5.8.0), relaying to an Ubuntu 24.04 host.
  Chrome on that host registered a WebAuthn credential and signed in with it.
  TESTPLAN.md has the results.
  No other hardware or distribution has been tested.
* **The remote host needs a setuid program.**
  The remote side is [fido-forward](https://github.com/txomon/fido-forward)'s sink, a third-party program installed setuid to a dedicated user so that it can open `/dev/uhid`.
  Read its README before you install it.
* **The relay runs as root, briefly.**
  In the ChromeOS Linux container, only root can open the key's USB node, so `ffwd-usbfs` starts under `sudo`.
  It switches to your user before it starts `ssh`.
* **Commands that change or erase the key are blocked.**
  The relay refuses CTAP2 reset, credential management, bio enrollment, config and large-blob commands, and YubiKey vendor commands, unless you pass `--allow-management`.
  PIN commands pass, because sign-ins use them.
* **A compromised remote host can ask the key to sign in to any site** while the relay runs, and you touch the key.
  The key cannot tell which site really asked.
  Run the relay only while you need it.
  DESIGN.md, section 7, and the paper, Section IX, explain this.
* **Only the FIDO interface is forwarded.**
  OTP, PIV and OpenPGP on the key stay on the Chromebook.

To report a security problem, see [SECURITY.md](SECURITY.md).

## Build and test

```sh
bazel test //...
```

`bazel build //...` builds:

* `fido-probe`, a read-only check of the key, for Linux (amd64, arm64) and macOS (amd64, arm64), as `//cmd/fido-probe:fido-probe_<platform>`;
* `ffwd-usbfs`, the relay that forwards the key over SSH to fido-forward's sink, for Linux (amd64, arm64), as `//cmd/ffwd-usbfs:ffwd-usbfs_<platform>`;
* the paper, as `//paper:usbfs-fido-relay`.

Bazel provides the Go SDK, the C toolchain and a TeX distribution (TinyTeX); nothing comes from the host.

## Releases

[`release.yml`](.github/workflows/release.yml) runs once a month and from the Actions tab.
It releases only when `main` has changed since the last release.
Each release holds `fido-probe` for the four platforms, `ffwd-usbfs` for the two Linux platforms, the paper as a PDF, and `SHA256SUMS`.

## License

Apache 2.0; see [LICENSE](LICENSE).
