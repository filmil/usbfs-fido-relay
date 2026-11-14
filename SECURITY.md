# Security

## Reporting a problem

Please report a security problem privately: open the repository's **Security** tab and choose **Report a vulnerability**.
Do not open a public issue for it.

Say which program the problem is in (`ffwd-usbfs`, `fido-probe`, or a package), and how to reproduce it.

## Scope

In scope: the code in this repository, in particular the command policy in `ctaphid/` and `relay/`, and the USB access in `usbfs/`.

Out of scope: [fido-forward](https://github.com/txomon/fido-forward), which provides the remote side.
Report problems in it to that project.

## Known limits

These are by design, and README.md ("Status and safety") explains them:

* While the relay runs, the remote host can ask the key to sign in to any site, and a touch approves it.
* PIN commands pass the relay, because sign-ins need them.
