# Research notes: remote WebAuthn in Chrome Remote Desktop (approach E2)

Raw findings from the research pass on 2026-11-10.
The paper's appendix B uses these notes.
Chromium source: commit `2b88984cf66d` (main, 2026-11-10).
`cr:PATH:LINES` means `https://chromium.googlesource.com/chromium/src/+/main/PATH`, at those lines.

## Data flow

1. Chrome on the host has the "Chrome Remote Desktop Security Key Extension" (`djjmngfglakhkhmgcfdmjalogilepkhd`, v1.16), with the permissions `webAuthenticationProxy` and `nativeMessaging`.
   When a CRD session starts, the CRD host writes a file into `<chrome config>/WebAuthenticationProxyRemoteSessionStateChange/`; Chrome fires `onRemoteSessionStateChange`, and the extension calls `webAuthenticationProxy.attach()`.
2. The extension sends the request through native messaging (`com.google.chrome.remote_webauthn`) to the `remote-webauthn` binary.
3. That binary sends it through Mojo IPC (`ChromotingHostServices.BindWebAuthnProxy`, interface `WebAuthnProxy`) to the CRD host process.
4. The CRD host sends `remoting.protocol.RemoteWebAuthn` messages over the WebRTC data channel `remote-webauthn`, when the client has the `remoteWebAuthn` capability.
5. The CRD client calls WebAuthn in its own Chrome with `remoteClientDataJSON` (earlier `remoteDesktopClientOverride`), which carries the remote origin.
   Chrome allows that only for an allowlisted origin (see "Client side").

## Host side

* Verified: channel name `remote-webauthn`, cr:remoting/host/webauthn/remote_webauthn_constants.cc:11; allowed extension IDs, L33-50.
* Verified: messages IsUvpaa, Create, Get, Cancel, with JSON payloads, cr:remoting/proto/remote_webauthn.proto:14-108.
* Verified: native host dispatch, cr:remoting/host/webauthn/remote_webauthn_native_messaging_host.cc:81-120; Mojo, cr:remoting/host/mojom/webauthn_proxy.mojom:45,72-89.
* Verified: on Linux, the native host accepts only a parent process `/opt/google/chrome{,-beta,-canary,-unstable}/chrome` (Google Chrome, not Chromium), cr:remoting/host/webauthn/remote_webauthn_caller_security_utils.cc:52-59,73-82.
* Verified: wake-up file directory, cr:remoting/host/webauthn/remote_webauthn_extension_notifier.cc:117-149.
* Verified (checked by hand): the CRD host turns remote WebAuthn on for every host, `desktop_environment_options_.set_enable_remote_webauthn(true)`, cr:remoting/host/remoting_me2me_host.cc:2124.
  A session policy can turn it off; the comment says the admin can block the extension instead, cr:remoting/base/session_policies.h:105-110.
* Verified: `webAuthenticationProxy` is stable on Linux, Mac and Windows, not on ChromeOS, cr:chrome/common/extensions/api/_permission_features.json:882-887.
* Verified: the CRD host does not install the extension; nothing in `remoting/` force-installs it.
* Verified: the extension's store text: "Allows security keys to be used by remotedesktop.corp.google.com to authorize actions on the remote host"; its `externally_connectable` lists only `remotedesktop*.corp.google.com`.
  https://chromewebstore.google.com/detail/djjmngfglakhkhmgcfdmjalogilepkhd
* Verified: the public companion extension "Chrome Remote Desktop" (`inomeog...`) has no `webAuthenticationProxy` permission.

## Client side

* Verified (checked by hand): `OriginMayUseRemoteDesktopClientOverride`, cr:chrome/browser/webauthn/chrome_web_authentication_delegate_base.cc.
  Path a, L62-86: the profile is affiliated, and the origin is in `WebAuthenticationRemoteDesktopAllowedOrigins`.
  Path b, L34-59: the internal policy `WebAuthenticationRemoteProxiedRequestsAllowed`, and one of three hard-coded `remotedesktop*.corp.google.com` origins; the comment says it "explicitly does not cover external instances of CRD".
  `remotedesktop.google.com` is not hard-coded; it is only an example value in the policy YAML.
* Verified (checked by hand): policy YAML `WebAuthenticationRemoteDesktopAllowedOrigins`: "only applies to affiliated users", HTTPS origins only, no wildcards, `chrome.*`, `chrome_os` and `android` from 136, `per_profile`, `platform_only`.
  https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/Miscellaneous/WebAuthenticationRemoteDesktopAllowedOrigins.yaml
* Verified: `remoteClientDataJSON` takes precedence over `remoteDesktopClientOverride`, cr:content/browser/webauth/authenticator_common_impl.cc:1185-1220.
* Verified: affiliation means the user's affiliation IDs intersect those of the device or the browser, cr:chrome/browser/enterprise/util/affiliation.cc:16-44.
* Verified: W3C WebAuthn Editor's Draft defines `remoteClientDataJSON`, permission `publickey-credentials-remote-client-data-json`, denied by default; the user agent must trust the caller for the origin.
  https://github.com/w3c/webauthn/blob/main/index.bs
* Verified (third party): iwa-dev thread: works for affiliated users only; ChromeOS from Chrome 147, Windows, Mac, Linux and Android from Chrome 151; on ChromeOS the policy is set only in the Admin console, which has it since about 2026-07-14.
  https://groups.google.com/a/chromium.org/g/iwa-dev/c/oLOI_Qoj7x4
* Assumption: an Admin console setting named "WebAuth Remote Desktop Override" (reported in that thread, not in Google's documentation).
* Verified (search summary only): Chrome 136 enterprise release notes: "WebAuthn Support for Remote Desktop Clients on managed devices". https://support.google.com/chrome/a/answer/7679408
* Verified: "Intent to Prototype: WebAuthn remote desktop support", blink-dev, 2022-04-07.
  https://groups.google.com/a/chromium.org/g/blink-dev/c/3EFGXppjkWo/m/3o-pDPDeEQAJ

## Older security key channel

* Verified: channel `security-key` carries SSH agent bytes, cr:remoting/proto/security_key.proto:12-25.
* Verified: Linux sessions get `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/crd_ssh_auth_sock`, cr:remoting/host/linux/shared_lib.py:600-605.
* Verified: gated by `RemoteAccessHostAllowGnubbyAuth`, internal only; the client-side agent is not public.

## Open

* Does Google's public client at `remotedesktop.google.com` implement the `remote-webauthn` channel? Its code is not public. An administrator can test it (paper, appendix B).
* The value for `WebAuthenticationRemoteDesktopAllowedOrigins`; `https://remotedesktop.google.com` is an assumption.
