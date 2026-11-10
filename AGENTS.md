# Instructions

This repository is a design study: how to use a YubiKey that is plugged into a Chromebook (Crostini) from a remote Linux host.
Read README.md first.

The rules of `ai-coding-sop` (https://github.com/filmil/ai-coding-sop) apply.
The ones that matter most here:

* **Bazel only.** Build with `bazel build //...` and test with `bazel test //...` (Bazel 9.2.0, see `.bazelversion`).
  Every tool comes from `MODULE.bazel`: the Go SDK from `rules_go`, a C toolchain from `hermetic_cc_toolchain`.
  Run Go commands as `bazel run @rules_go//go -- ARGS`, never with a host `go`.
  Regenerate BUILD files with `bazel run //:gazelle`; format them with `bazel run //:buildifier`.
* **The paper** is `paper/`, an IEEEtran two-column document built by `rules_latex_host` (`bazel build //paper:yubikey-forward`).
  It follows the `latex-pdf-tutorial` skill: one file per section, TikZ diagrams, Latin Modern fonts (no Times), no Type 3 fonts.
  After a change to a figure or a table, render the pages and look at them (the skill's occlusion pass).
* **Prose.** Simplified technical English (ASD-STE100): short sentences, active voice.
  No em dashes or en dashes anywhere; check with `grep -rnP '\x{2013}|\x{2014}' <files>`.
  Mark each claim about other software as verified, with a source, or as an assumption.
* **SPDX.** Every source and BUILD file starts with `SPDX-License-Identifier: Apache-2.0`.
* **Git.** Conventional commit titles, the assistant attribution note, and the prompt in the commit message.
  Branch for each change and open a pull request; do not push to `main`.
* **Hardware.** Nothing here has been tested on a real Chromebook yet.
  TESTPLAN.md lists the tests. Do not mark an open question as answered without a test result.
