# Test plan

This plan answers the open questions in [DESIGN.md](DESIGN.md), section 8.
Do the tests in order.
Stop when a test fails, and record the output.

Names in the commands:

* `REMOTE` is the SSH name of the remote host (from `~/.ssh/config`).
* "Build host" is a Linux machine with Bazel and a clone of this workspace.
* "penguin" is the Linux container on the Chromebook (the Terminal app).

## T0. Find the Chromebook architecture and build the probe

On the Chromebook, in penguin:

```sh
uname -m
```

`x86_64` means amd64.
`aarch64` means arm64.

On the build host, in the workspace directory:

```sh
bazel build //cmd/fido-probe:fido-probe_linux_amd64   # amd64 Chromebook
bazel build //cmd/fido-probe:fido-probe_linux_arm64   # arm64 Chromebook
bazel cquery //cmd/fido-probe:fido-probe_linux_amd64 --output=files   # prints the binary's path
```

A release of this repository also has both binaries.
It is static, so it needs no libraries in penguin.
Copy it to penguin, for example with `scp` from penguin, or through the Files app into "Linux files".

## T1. Share the key with Linux (Q1, Q2, Q9)

On the Chromebook:

1. Open `chrome://extensions` and the app list. If "Smart Card Connector" is installed, turn it off.
2. Plug in the YubiKey.
3. Open Settings, Developers (or About ChromeOS, Developers), Linux development environment, Manage USB devices.
4. Turn on the switch for the YubiKey.

In penguin:

```sh
sudo apt-get install -y usbutils
lsusb | grep -i 1050
ls -l /dev/bus/usb/*/*
ls -l /dev/hidraw* 2>&1
```

Expected result:

* `lsusb` shows `1050:` (Yubico).
* The key's node under `/dev/bus/usb` exists. On the tested Chromebook it was `crw-rw-r-- root root`, so the probe needs `sudo`.
* `/dev/hidraw*` does not exist (DESIGN.md, F1).

Record:

* Did the switch appear? Did it stay on?
* Was Smart Card Connector installed?
* The `lsusb` line.

If the switch does not appear or turns off again, ChromeOS refused the key (DENY or LOCKDOWN).
Approaches A and B then cannot work on this Chromebook.
Use approach E5 for web logins.

## T2. Probe the FIDO interface through usbfs (Q3)

In penguin, in the directory with the probe:

```sh
chmod +x fido-probe
sudo ./fido-probe
```

The node is writable only by root, so run the probe with `sudo`.
Without `sudo` it reports that it has no permission to open the node.
To name the device, give its path: `sudo ./fido-probe /dev/bus/usb/001/002`.

The probe sends CTAPHID_INIT and authenticatorGetInfo.
These commands read only.
They do not need a touch.

Expected result, for a YubiKey 5:

```
device: /dev/bus/usb/001/00N
id: 1050:0407, 3 interfaces
  interface 0: class 03, 1 endpoints
  interface 1: class 03, 2 endpoints
  interface 2: class 0b, 3 endpoints
interface 1: kernel driver detached
interface 1: FIDO usage page 0xF1D0, endpoints in 84 out 04
CTAPHID_INIT: channel ..., device version 5.x.y, capabilities 05 (CBOR true), ...
authenticatorGetInfo: ... bytes of CBOR, ...
  version: U2F_V2
  version: FIDO_2_0
  version: FIDO_2_1
PASS: the FIDO interface works from this machine
```

Interface numbers and endpoint addresses can be different.

| Result | Meaning | Next step |
|---|---|---|
| PASS | Approach B with `ffwd-usbfs` can work | Continue with T3 |
| `detach the kernel driver ...: operation not permitted` | The container cannot detach usbhid | Approach B and A fail. Use E5. Report the output. |
| `claim interface ...: device or resource busy` | Another process holds the interface | Close other key tools (`ykman`, `gpg`), then repeat |
| `no reply in 5 s` | Transfers do not reach the key | Repeat once. Then report the output. |

## T3. Install the sink on the remote host

On the build host:

```sh
bazel build @com_github_txomon_fido_forward//cmd/fido-forward --@rules_go//go/config:pure --platforms=@rules_go//go/toolchain:linux_amd64
```

The binary is `bazel-bin/external/gazelle++go_deps+com_github_txomon_fido_forward/cmd/fido-forward/fido-forward_/fido-forward`.
Copy it, and the `contrib/` files of fido-forward at commit 2b7b2ac, to the remote host.

On the remote host, as root (this is fido-forward's README, "Install on the use host"):

```sh
install -m 0644 contrib/fido-forward.sysusers.conf /usr/lib/sysusers.d/fido-forward.conf
install -m 0644 contrib/90-fido-forward-uhid.rules /etc/udev/rules.d/90-fido-forward-uhid.rules
install -m 0644 contrib/91-fido-forward-hidraw.rules /etc/udev/rules.d/91-fido-forward-hidraw.rules
systemd-sysusers
install -o fidofwd -g root -m 4755 fido-forward /usr/local/bin/fido-forward
echo uhid > /etc/modules-load.d/uhid.conf
modprobe uhid
udevadm control --reload
udevadm trigger /sys/devices/virtual/misc/uhid
usermod -aG fido-forward-users "$USER_WHO_RUNS_CHROME"
```

Then check, as root:

```sh
ls -l /dev/uhid                 # crw------- fidofwd ...
ls -l /usr/local/bin/fido-forward  # -rwsr-xr-x fidofwd root
grep -n ClientAliveInterval /etc/ssh/sshd_config  # set ClientAliveInterval 15, then reload sshd
```

Log out and in again (also in the CRD session), so that the new group applies.

## T4. Forward the key and log in with WebAuthn (Q7)

This test needs `ffwd-usbfs` (DESIGN.md, section 6), built as `//cmd/ffwd-usbfs:ffwd-usbfs_linux_amd64` or `_linux_arm64`.
First check that `ssh REMOTE true` works in penguin as your own user, with no password prompt that you cannot answer.

In penguin:

```sh
sudo --preserve-env=SSH_AUTH_SOCK ./ffwd-usbfs REMOTE
# expected: local: device ..., local: interface 1: FIDO usage page 0xF1D0 ...,
#           local: running as USER from now on,
#           remote: ready /dev/hidrawM, then: local: relaying
```

`sudo` is needed to open the key's node (T1).
The relay gives up root before it starts `ssh`, so `ssh` uses your keys and `~/.ssh/config`.
`--preserve-env=SSH_AUTH_SOCK` keeps your ssh-agent; without an agent, `ssh` reads your key files.
Ctrl-C ends the forward. The last line must be `local: key given back to the system`.

On the remote host, in a terminal of the CRD session:

```sh
id | grep fido-forward-users
ls -l /dev/hidraw*            # the new node: crw-rw---- root fido-forward-users
sudo apt-get install -y fido2-tools
fido2-token -L
fido2-token -I /dev/hidrawM   # prints versions, options, and the AAGUID of the real key
```

In Chrome in the CRD session:

1. Open https://webauthn.io.
2. Register with a new user name. Touch the key on the Chromebook when it blinks.
3. Authenticate. Touch the key again.

Record: success or the error text, and how long each step took.

Policy check, on the remote host (the relay must refuse this):

```sh
fido2-token -L -r /dev/hidrawM   # lists stored sites (credential management, read only): expect an error
```

`-L -r` only reads, but it uses the credential management command, so the policy must refuse it.

Do not run `fido2-token -R` (reset) as a test, even with the policy on.

## T5. Measure latency (Q5)

In penguin:

```sh
ping -c 10 "$(ssh -G REMOTE | awk '/^hostname /{print $2}')"
time ssh -T REMOTE true
```

During T4, note how long Chrome waits between your touch and the result.
More than 2 s means the relay is slow: report it with the ping times.

## T6. OpenPGP and PIV next to the FIDO relay (Q6)

In penguin:

```sh
sudo apt-get install -y pcscd scdaemon yubikey-manager opensc
ykman info
ykman piv info
gpg --card-status
```

Then start `ffwd-usbfs REMOTE` in a second terminal and repeat `ykman piv info` and `gpg --card-status`.
Both must still work.

OpenPGP forwarding (GnuPG wiki, AgentForwarding):

```sh
# penguin: find the local extra socket
gpgconf --list-dir agent-extra-socket
# remote host: find the remote agent socket, and stop the remote agent
gpgconf --list-dir agent-socket
gpgconf --kill gpg-agent
```

Add to `~/.ssh/config` in penguin, with the two paths from above:

```
Host REMOTE
  RemoteForward /run/user/REMOTE_UID/gnupg/S.gpg-agent /home/LOCAL_USER/.gnupg/S.gpg-agent.extra
```

On the remote host, as root, add `StreamLocalBindUnlink yes` to `/etc/ssh/sshd_config`, then reload sshd.
Then, on the remote host (it needs your public key):

```sh
gpg --import pubkey.asc
echo test | gpg --no-autostart --clearsign
```

Expected: pinentry and the touch happen on the Chromebook, and the signature appears on the remote host.

PIV forwarding with p11-kit (p11-kit manual, "Remoting"):

```sh
# penguin
sudo apt-get install -y p11-kit ykcs11
# on arm64 the path has aarch64-linux-gnu in place of x86_64-linux-gnu
p11-kit server --provider /usr/lib/x86_64-linux-gnu/libykcs11.so "pkcs11:"
# it prints P11_KIT_SERVER_ADDRESS=unix:path=...; forward that socket:
ssh -R /run/user/REMOTE_UID/p11-kit/pkcs11:/PATH/FROM/ABOVE REMOTE
# remote host
ssh-keygen -D /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so
```

Expected: the remote host lists the PIV public keys.

## T7. Give the key back to ChromeOS (Q8)

1. Stop `ffwd-usbfs` with Ctrl-C.
2. In Manage USB devices, turn off the switch for the YubiKey.
3. In Chrome on the Chromebook, open https://webauthn.io and authenticate.

Record: does it work without a replug?

## Results table

Fill in one row for each test.

| Test | Date | Chromebook model and ChromeOS version | Result | Notes |
|---|---|---|---|---|
| T0 | 2026-11-09 | Chromebook, ChromeOS version not recorded | `x86_64` (amd64) | Probe from pre-release `probe-test-1` |
| T1 | 2026-11-09 | same | Pass, with a Google Titan key (`18d1:5026`, "tk-x001") in place of the YubiKey | One shared device, mode `crw-rw-r-- root root` (0664), not 0666; no `/dev/hidraw*` |
| T2 | 2026-11-09 | same | **Pass** with `sudo`: kernel driver detached from interface 0, interface claimed, usage page 0xF1D0, endpoints in 81 out 01, CTAPHID_INIT answered in 3 ms, driver attached again | Titan key, U2F only (capabilities 03, no CBOR), so getInfo was not sent. Without `sudo` the probe could not open the node and reported no device. |
| T2 | 2026-11-09 | same | **Pass** with `sudo`, YubiKey 5 (`1050:0407`, firmware 5.8.0): interfaces 0 (HID), 1 (HID), 2 (CCID); interface 1 detached and claimed, usage page 0xF1D0, endpoints in 84 out 04; CTAPHID_INIT in 4 ms, capabilities 05 (CBOR); authenticatorGetInfo 569 bytes in 230 ms; versions U2F_V2, FIDO_2_0, FIDO_2_1 | Matches the expected output above. Q3 is answered for FIDO2. |
| T3 | 2026-11-09 | Remote host eph1: Ubuntu 24.04.5, kernel 6.8.0-147-generic, x86_64 | **Pass** | uhid is a module in `linux-modules-extra`, which was not installed; installed it first. fido-forward 2b7b2ac built with Bazel; the README steps ran as one script. `/dev/uhid` `crw------- fidofwd root`, binary `-rwsr-xr-x fidofwd root`, `ClientAliveInterval 15`. |
| T4 | 2026-11-09 | Chromebook (penguin) to eph1, YubiKey 5 firmware 5.8.0, `ffwd-usbfs` from pre-release `relay-test-1` | **Pass**: webauthn.io registration and authentication in Chrome in the CRD session on eph1, with a touch each time | `sudo --preserve-env=SSH_AUTH_SOCK ./ffwd-usbfs-linux_amd64 eph1`; the relay switched to the user, the sink made `/dev/hidraw1`. Chrome in the CRD session had started before the user joined `fido-forward-users`, so it lacked the group; for the test, `setfacl -m u:filmil:rw /dev/hidraw1`. For normal use, restart the CRD session once. Settings: user verification, discoverable credential and attestation all "Discouraged" or "None", so nothing was stored on the key and no PIN was asked. The relay's ssh took the user's `LocalForward 8080`; fixed by `ClearAllForwardings=yes` (PR #8). |
| T5 | | | | |
| T6 | | | | |
| T7 | 2026-11-09 | same | **Pass**, no replug: after the switch was turned off, Chrome on the Chromebook reached the YubiKey and read its capabilities | Done without `ffwd-usbfs` (after the probe, which attaches the driver again). webauthn.io sign-in with an empty user name: Chrome said the key "can't be used with this site", which needs the key's capabilities; no credential was created. Repeat after T4. |
