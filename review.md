# Accessible Wifi — Security & Accessibility Review

**Scope:** `src/accessiblewifi/app.py` (the entire application logic — 1308 lines), plus supporting config (`pyproject.toml`, `tests/`). This is a Toga/BeeWare desktop app that wraps `nmcli` to manage NetworkManager Wi-Fi connections on Linux, with an explicit goal of screen-reader accessibility.
**Not reviewed:** generated Briefcase scaffolding, packaging/build pipeline, icon assets.

---

## Summary

The codebase is small, readable, and already follows several security best practices for a privileged-adjacent desktop tool (no shell invocation, no passwords on the command line, restrictive temp-file permissions). The most impactful issues found are:

1. **Accessibility gap — FIXED:** several important connection/status outcomes used to be written only to a plain status label, with no dialog or other mechanism to reliably reach assistive technology. `set_status` now also speaks the same text through Orca's D-Bus service (see Accessibility finding 1), so every status update is announced without stealing focus.
2. **Security gap — FIXED:** the CA certificate field for Enterprise/802.1X networks is optional, so the app used to connect silently to a network authenticating with an unverified server certificate. A confirmation dialog (Security finding 1) now requires the user to explicitly acknowledge the rogue-AP risk before connecting without a CA certificate.
3. Several smaller robustness/hardening items below — the error-swallowing cleanup bug and missing initial focus in secondary windows (Accessibility findings 2 and 3) have been fixed.

No test coverage exists beyond a placeholder (`tests/test_app.py` is `assert 1 + 1 == 2`), so none of the logic below (SSID parsing, validation, security-type classification) is regression-protected.

---

## Security Review

### Strengths worth preserving

- **No shell is ever invoked.** All `nmcli` calls go through `asyncio.create_subprocess_exec` with an argument list (`app.py:278-285`), so there is no shell metacharacter/command-injection surface regardless of what a broadcast SSID contains.
- **Passwords never appear on the command line.** Every secret (WPA PSK, 802.1X password, private-key password, WEP key) is written to a temp file and passed via `nmcli ... passwd-file <path>` (`app.py:336-353`, `create_secret_file` at `app.py:308-334`), instead of being placed in `argv` where it would be visible to any local user via `ps`/`/proc`. This is a good, deliberate design choice.
- **Secret file permissions.** `tempfile.mkstemp` + `os.fchmod(descriptor, 0o600)` (`app.py:310-316`) ensures the secrets file is only readable by the invoking user, and the file is unlinked in a `finally` block (`app.py:348-353`) even on failure.
- **App explicitly avoids running as root** — the docstring at `app.py:21` warns against `sudo`, relying on PolicyKit for privilege escalation, which keeps the Toga UI process unprivileged.
- **Basic secret-file line-injection guard:** `create_secret_file` rejects any secret value containing `\n`/`\r` (`app.py:318-322`), preventing a value from injecting an extra `key:value` line into the passwd-file.

### Findings

**1. (Medium) Enterprise networks can connect without CA certificate validation — FIXED**
The CA certificate field is marked "recommended," not required (`required=False`), for PEAP, TTLS, and TLS. If left blank, `802-1x.ca-cert` is simply omitted from the `nmcli connection modify` call, and NetworkManager will accept whatever server certificate the AP presents. For WPA-Enterprise, this is the primary protection against a rogue/evil-twin access point capturing credentials — without it, an attacker broadcasting the same SSID can harvest the entered username/password. Fixed by adding a `ConfirmDialog` in `connect_enterprise` that fires whenever the CA certificate field is left blank, explicitly naming the rogue-AP credential-theft risk and requiring the user to confirm before the connection proceeds (declining aborts the attempt without contacting `nmcli`). The field is left optional rather than required, since some legitimate deployments (e.g. captive/test networks, or admins who intentionally omit CA pinning) still need a way to proceed.

**2. (Low) Error-handling paths can themselves raise, swallowing user-facing error messages — FIXED**
In `connect_personal`, `connect_enterprise`, and `connect_wep`, the `except` block called `await self.delete_profile(profile)` before reporting the error. `delete_profile` calls `run_nmcli(..., check=False)`, which still raises `NmcliError` if `nmcli` itself can't be run or the call times out. If that happened, the subsequent `set_status(...)` / `show_error(...)` calls never executed, and the exception propagated out of the `async def` handler unhandled — silence instead of an error. Fixed by routing all three cleanup calls through a new `cleanup_failed_profile` helper that swallows `NmcliError` from the cleanup itself, guaranteeing the primary error is always reported.

**3. (Low) Minimal SSID validation**
`validate_ssid` (`app.py:244-248`) only rejects empty strings and embedded newlines. There's no length check (real SSIDs are capped at 32 bytes) and no guard against a value that starts with `-` being misread as an option by `nmcli`'s own argument parser in some edge cases. Not exploitable for command injection (argv-based exec, not shell), but worth tightening defensively since SSID text originates from untrusted RF broadcasts.

**4. (Low) Secret temp file uses the system-wide temp directory**
`create_secret_file` uses the default `tempfile.mkstemp()` location (typically `/tmp`) rather than a per-user runtime directory such as `$XDG_RUNTIME_DIR` (usually a `tmpfs` that's private to the user session and cleared on logout). File permissions (0600) already prevent other users from reading it, so this is a minor defense-in-depth improvement rather than a live vulnerability.

**5. (Info) Profile naming from untrusted SSID text**
`profile_name` (`app.py:365-368`) builds the NetworkManager connection name directly from the scanned/typed SSID (only stripping `\r\n\t`). Two visually-similar or specially-crafted SSIDs could in principle normalize to the same profile name and cause one saved profile to be deleted/overwritten by `delete_profile`/`connection add` (`app.py:355-363`, `613`). Impact is limited to the app's own saved profiles, not other users' data, so this is informational.

**6. (Info) Captive-portal probe uses plain HTTP to a fixed URL**
`PORTAL_URL = "http://example.com/"` (`app.py:39`) is intentionally unencrypted, which is the standard technique for captive-portal detection (a portal must intercept unencrypted HTTP to inject its redirect). This is expected behavior, not a defect — noting it only so it isn't mistaken for an oversight in a future review.

---

## Accessibility Review

### Strengths worth preserving

- **Screen-reader-oriented network descriptions.** `WifiNetwork.display_name` (`app.py:76-81`) composes connection state, SSID, signal strength, and security type into one readable sentence ("Connected. MySSID. Signal 80 percent. WPA2") rather than relying on a multi-column list a screen reader would have to piece together. This is the strongest accessibility decision in the codebase.
- **Every control has an adjacent descriptive `Label`**, not just placeholder text (e.g. `app.py:678-683`, `803-826`, `1051-1062`), which is the right pattern for label/field association.
- **Native dialogs for key confirmations.** `ErrorDialog`/`InfoDialog`/`ConfirmDialog` (e.g. `app.py:212-220`, `1209-1214`, `1223-1228`) are used for connection failures and the "full/portal/limited" connectivity outcomes — these are modal, take focus, and are reliably announced by platform assistive technology.
- **Plain-language warnings in context**, e.g. the WEP-is-insecure notice appears as the first line read in that window, before the SSID field (`app.py:1046-1049`), and the enterprise window opens with a note that CA validation is recommended (`app.py:798-801`).
- **No color-only signaling** and no custom theming that would fight OS-level high-contrast/dark-mode settings.
- **Status updates speak through Orca without stealing focus.** `set_status`/`speak` (`app.py`) send status text to Orca's D-Bus service (`PresentMessage`) via a `busctl` subprocess, so a screen-reader user hears it immediately no matter which control currently has focus — no modal dialog required for routine, non-actionable updates.

### Findings

**1. (High) Several meaningful outcomes are reported only via a plain status label, with no reliable path to assistive technology — FIXED**
`set_status` used to just set `self.status_label.text`. Toga doesn't expose an ARIA-live-region equivalent, so a screen reader would only announce this text if the label happened to have focus — it wouldn't proactively interrupt the user the way a dialog does. Several important state transitions relied on this alone with no accompanying dialog (scan results, "Connecting to X.", "no Internet access was detected", "Internet access could not be checked", "Restarting Wi-Fi."). Fixed by having `set_status` also call a new `speak()` method, which sends the same text to Orca's D-Bus service (`org.gnome.Orca.Service` `PresentMessage`, see `ORCA_SPEAK_COMMAND`/`_speak_async` in `app.py`) so it's spoken immediately regardless of focus, without the modal interruption a dialog would cause. Since every status-only update already funneled through this one chokepoint, this single change covers all of the call sites listed above. Speech failures (Orca or D-Bus session unavailable) are swallowed — this is a best-effort enhancement layered on top of the existing label, not a replacement for it.

**2. (Medium) No feedback that a long-running operation is in progress beyond a single label change — PARTIALLY ADDRESSED**
`set_busy(True, message)` disables buttons and sets the status once, then goes silent until the operation completes — and some operations can take up to 120 seconds (`activate`). Because `set_busy`'s initial message goes through `set_status`, the *start* of a long operation is now spoken via Orca (see finding 1). No periodic "still working" reminder was added for the multi-second gap in the middle of very long operations — still worth considering if user testing shows people conclude the app has frozen.

**3. (Low) No explicit initial focus when secondary windows open — FIXED**
`show_hidden_window`, `show_enterprise_window`, and `show_wep_window` now call `.focus()` on their first input field (`hidden_ssid`/`enterprise_ssid`/`wep_ssid`) right after `.show()`, on both the freshly-built-window path and the reuse-existing-window path.

**4. (Low) Disabled-but-still-present fields in the Enterprise window**
The Enterprise window (`app.py:750-849`) shows all fields for every auth method and toggles `.enabled` based on the selected method (`enterprise_method_changed`, `app.py:851-883`) rather than removing irrelevant fields from the layout. Whether a screen reader skips `enabled=False` controls in Tab order is backend-dependent (GTK/Cocoa/WinForms may differ) — worth manually verifying on the target platform(s) that a user selecting "TLS with client certificate" isn't still tabbed through the now-irrelevant PEAP/TTLS fields (identity, password, inner-auth), which would be confusing given they're announced as present but disabled rather than absent.

**5. (Info) No coverage of accessibility behavior in tests**
Given the app's accessibility focus, it may be worth adding at least unit tests for the pure logic that feeds the screen-reader-facing strings (`WifiNetwork.display_name`, `parse_wifi_list`, `validate_ssid`) so that future changes can't silently regress the wording or ordering that screen-reader users depend on. Currently `tests/test_app.py` contains only a placeholder assertion.

---

## Other Notes (not security or accessibility, minor)

- `pyproject.toml` metadata is inconsistent with the app itself: `bundle = "org.aph"`, `author_email = "kperry@aph.org"`, `project_name = "Wifi"` (`pyproject.toml:3-10`), while `app.py:1302` uses `app_id="org.example.accessiblewifi"` and the README describes it as "Ken's wifi app." Worth reconciling before a real release/packaging pass.
- `README.md` and `CHANGELOG` are still template boilerplate with no real usage/setup instructions (e.g., that `nmcli`/NetworkManager and a PolicyKit agent are required) — the good "Requirements" list already written into the `app.py` docstring (`app.py:15-19`) would be worth surfacing there.
