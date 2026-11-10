[![test](https://github.com/filmil/yubikey-forward/actions/workflows/test.yml/badge.svg)](https://github.com/filmil/yubikey-forward/actions/workflows/test.yml)
[![release](https://github.com/filmil/yubikey-forward/actions/workflows/release.yml/badge.svg)](https://github.com/filmil/yubikey-forward/actions/workflows/release.yml)

# yubikey-forward

A design study: use a YubiKey on a Chromebook (in the Crostini Linux container) from a remote Linux host.

* [DESIGN.md](DESIGN.md): the approaches, the comparison, the recommendation, and the open questions.
* [TESTPLAN.md](TESTPLAN.md): the tests to run on the real Chromebook and the remote host.
* [research/](research/): the raw research notes, with sources.
* [paper/](paper/): the same study as an IEEE two-column paper; build it with `bazel build //paper:yubikey-forward`.

## Build and test

```sh
bazel test //...
```

`bazel build //...` builds `fido-probe` for Linux (amd64, arm64) and macOS (amd64, arm64) as `//cmd/fido-probe:fido-probe_<platform>`, and the paper as `//paper:yubikey-forward`.
Bazel provides the Go SDK, the C toolchain and a TeX distribution (TinyTeX); nothing comes from the host.

## Releases

[`release.yml`](.github/workflows/release.yml) runs once a month and from the Actions tab.
It releases only when `main` has changed since the last release.
Each release holds `fido-probe` for the four platforms, the paper as a PDF, and `SHA256SUMS`.

## License

Apache 2.0; see [LICENSE](LICENSE).
