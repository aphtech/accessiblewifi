# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A BeeWare/Toga desktop app (Linux, GTK backend) that wraps `nmcli` to provide a screen-reader-accessible
Wi-Fi connection manager. It supports open networks, hidden networks, WPA/WPA2/WPA3 Personal, WPA
Enterprise/802.1X (PEAP/TTLS/TLS), legacy WEP, captive-portal detection, and Wi-Fi restart. The app is a
thin GUI over NetworkManager — almost all logic lives in a single file.

Requires Linux with NetworkManager, `nmcli` on PATH, and (for authenticated `nmcli` operations) a
PolicyKit agent. The app must **not** be run with `sudo` — it relies on PolicyKit for privilege escalation,
keeping the Toga UI process unprivileged.

## Commands

Project uses [Briefcase](https://briefcase.beeware.org/) (BeeWare) for packaging/running, and pytest for
tests.

- Run the app in dev mode: `briefcase dev`
- Run the packaged app: `briefcase run`
- Run tests: `briefcase dev --test` (runs `tests/` via the Briefcase test harness), or directly with
  `pytest tests/`
- Build a distributable: `briefcase build` / `briefcase package`

There is no lint/format config in the repo (no ruff/flake8/black config) and no `pytest.ini`/`tox.ini` —
pytest runs with defaults.

## Architecture

Everything lives in `src/accessiblewifi/app.py` (one `toga.App` subclass, `AccessibleWifi`). Key shape:

- **`WifiNetwork`** (frozen dataclass): represents one scanned network, with classification properties
  (`is_open`, `is_enterprise`, `is_wep`, `is_wpa3_only`) that drive both connection logic and the
  accessible `display_name` string read by screen readers (e.g. `"Connected. MySSID. Signal 80 percent.
  WPA2"`).
- **`run_nmcli`**: the single chokepoint for shelling out. Always uses
  `asyncio.create_subprocess_exec` with an argv list (never `shell=True`), so there is no
  command-injection surface regardless of SSID content. Preserve this pattern for any new `nmcli` calls.
- **Secrets handling**: passwords/keys are never passed as CLI arguments (would be visible via `ps`).
  `create_secret_file` writes them to a `0600` temp file consumed via `nmcli ... passwd-file <path>`, then
  the file is unlinked in a `finally` block. Any new secret-carrying flow must follow this same
  write-temp-file/`passwd-file`/unlink pattern — never put a secret in a `run_nmcli(...)` argument.
- **Connection flow** (personal/hidden/enterprise/WEP each follow the same shape): delete any existing
  profile with the same name (`delete_profile`), create a base profile (`add_base_profile`), modify it
  with security-specific `nmcli connection modify` properties, then `activate()` it with the secrets file.
  On failure the just-created profile is deleted again so failed attempts don't leave stale profiles
  behind. `profile_name(ssid, category)` namespaces profiles as `"Accessible Wi-Fi {category} - {ssid}"`.
- **Accessibility is a first-class design constraint, not a UI nicety.** Status changes go through
  `set_status`, which both updates the on-screen label and calls `speak()` to announce the same text
  through Orca's D-Bus service (`org.gnome.Orca.Service` `PresentMessage`, via the `busctl` invocation in
  `ORCA_SPEAK_COMMAND`) — this reaches the screen reader immediately without stealing keyboard focus the
  way a dialog would, and without depending on the status label happening to have focus. For anything the
  user also needs to positively acknowledge (errors, connection outcomes), still pair `set_status` with
  `show_error` / `toga.ErrorDialog` / `toga.InfoDialog` / `toga.ConfirmDialog`. Any new status-only update
  should go through `set_status` (not a raw `status_label.text` assignment) to get speech for free.
  `WifiNetwork.display_name` and dialog copy should stay written as full sentences for screen-reader
  clarity rather than terse UI labels. Secondary windows (`show_hidden_window`, `show_enterprise_window`,
  `show_wep_window`) explicitly call `.focus()` on their first input field after `.show()`, including on
  the reuse-existing-window path — keep doing this for any new secondary window.
- **Busy/enabled state** is centralized in `set_busy(busy, message)`, which disables the action buttons
  and selection/input widgets during an in-flight `nmcli` operation and restores them afterward via
  `network_changed`. Any new long-running operation should route through `set_busy` rather than managing
  widget `enabled` state ad hoc.
- **Captive portal handling**: `get_connectivity()` calls `nmcli networking connectivity check` and
  `report_connectivity()` maps the result (`full`/`portal`/`limited`/`none`/`unknown`) to status text and,
  where relevant, a confirm dialog offering to open `PORTAL_URL` in a browser via
  `launch_portal_browser()`.

`__main__.py` and the `main()` function at the bottom of `app.py` are the two entry points Briefcase wires
up; keep both working since Briefcase invokes the module both ways depending on target platform.

## Known gaps (see `review.md`)

A security/accessibility review (`review.md` at repo root) is already on record with prioritized findings —
read it before making security- or accessibility-related changes here, since it documents intentional
design decisions (e.g. `PORTAL_URL` being plain HTTP is deliberate, not a bug) alongside real gaps (e.g.
CA certificate validation being optional for Enterprise networks, and some status-only paths not reliably
reaching assistive tech). Test coverage is currently just a placeholder (`tests/test_app.py`) — none of the
SSID parsing/validation/classification logic is regression-protected yet.
