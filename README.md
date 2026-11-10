# yubikey-forward

A design study: use a YubiKey on a Chromebook (in the Crostini Linux container) from a remote Linux host.

* [DESIGN.md](DESIGN.md): the approaches, the comparison, the recommendation, and the open questions.
* [TESTPLAN.md](TESTPLAN.md): the tests to run on the real Chromebook and the remote host.
* [research/](research/): the raw research notes, with sources.
* [paper/](paper/): the same study as an IEEE two-column paper; build it with `bazel build //paper:yubikey-forward`.

## Build and test

```sh
bazel test //...
bazel build //cmd/fido-probe --@rules_go//go/config:pure --platforms=@rules_go//go/toolchain:linux_amd64
```

Bazel provides the Go SDK and the C toolchain; nothing comes from the host.

## License

Apache 2.0; see [LICENSE](LICENSE).
