"""Regression tests for the Wi-Fi connection flow.

These exercise the real `AccessibleWifi` connection methods (unbound, via a
lightweight recording harness) instead of instantiating the full Toga app,
since building the GTK app object requires a running GTK/GLib main loop that
isn't available in a headless test run. The harness only fakes I/O
boundaries: `run_nmcli` (records the argv NetworkManager would receive
instead of actually shelling out) and UI feedback (`set_status`,
`show_error`, `set_busy`).
"""

from __future__ import annotations

import asyncio

import pytest

from accessiblewifi.app import AccessibleWifi, NmcliError, WifiNetwork


class _FakeValue:
    def __init__(self, value: str = "") -> None:
        self.value = value


class _RecordingPersonal:
    """Harness exposing the real personal/hidden-network connection path."""

    add_base_profile = AccessibleWifi.add_base_profile
    connect_personal = AccessibleWifi.connect_personal
    delete_profile = AccessibleWifi.delete_profile
    cleanup_failed_profile = AccessibleWifi.cleanup_failed_profile
    activate = AccessibleWifi.activate
    connecting_ticker = AccessibleWifi.connecting_ticker
    _connect_tick_loop = AccessibleWifi._connect_tick_loop
    _play_tick = AccessibleWifi._play_tick
    validate_ssid = staticmethod(AccessibleWifi.validate_ssid)
    profile_name = staticmethod(AccessibleWifi.profile_name)
    create_secret_file = staticmethod(AccessibleWifi.create_secret_file)

    def __init__(self, *, fail_on: str | None = None) -> None:
        self.nmcli_calls: list[tuple[str, ...]] = []
        self.status_messages: list[str] = []
        self.errors: list[tuple[str, str]] = []
        self.busy_calls: list[tuple[bool, str | None]] = []
        self.connected: list[str] = []
        self._tick_command = None
        self.password_input = _FakeValue()
        self._fail_on = fail_on

    async def run_nmcli(self, *args: str, timeout: int = 90, check: bool = True) -> str:
        self.nmcli_calls.append(args)
        if self._fail_on and self._fail_on in args:
            raise NmcliError("Secrets were required, but not provided.")
        return ""

    def set_busy(self, busy: bool, message: str | None = None) -> None:
        self.busy_calls.append((busy, message))

    def set_status(self, message: str) -> None:
        self.status_messages.append(message)

    async def show_error(self, title: str, message: str, window=None) -> None:
        self.errors.append((title, message))

    def focus_connected_network(self, ssid: str) -> None:
        self.connected.append(ssid)

    async def handle_connection_result(self, ssid: str) -> None:
        pass


def _modify_calls(nmcli_calls: list[tuple[str, ...]]) -> list[tuple[str, ...]]:
    return [call for call in nmcli_calls if call[:2] == ("connection", "modify")]


# --- WifiNetwork classification -------------------------------------------------


@pytest.mark.parametrize(
    "security, expected",
    [
        ("", True),
        ("--", True),
        ("none", True),
        ("WPA2", False),
        ("WPA1 WPA2", False),
        ("WEP", False),
        ("SAE", False),
    ],
)
def test_is_open(security: str, expected: bool) -> None:
    network = WifiNetwork(ssid="n", signal=50, security=security)
    assert network.is_open is expected


def test_wpa2_psk_style_network_is_classified_as_personal_not_enterprise_or_wep() -> (
    None
):
    # nmcli reports plain "WPA2" for both a router's "regular WPA2" and
    # "WPA2-PSK" options - the app has no separate PSK-vs-non-PSK category,
    # it only distinguishes open / enterprise / WEP / WPA3-only / personal.
    network = WifiNetwork(ssid="Home", signal=70, security="WPA2")
    assert not network.is_open
    assert not network.is_enterprise
    assert not network.is_wep
    assert not network.is_wpa3_only


def test_wpa2_802_1x_is_enterprise() -> None:
    network = WifiNetwork(ssid="Office", signal=60, security="WPA2 802.1X")
    assert network.is_enterprise


def test_sae_only_is_wpa3() -> None:
    network = WifiNetwork(ssid="NewRouter", signal=80, security="SAE")
    assert network.is_wpa3_only


def test_mixed_wpa2_sae_is_not_wpa3_only() -> None:
    # Mixed-mode routers advertise both PSK and SAE; the app should treat
    # these as WPA2-Personal (wpa-psk) since that's compatible with either.
    network = WifiNetwork(ssid="Mixed", signal=80, security="WPA2 SAE")
    assert not network.is_wpa3_only


# --- add_base_profile: NetworkManager security properties -----------------------


def test_wpa_psk_profile_sets_key_mgmt_and_clears_agent_owned_flag() -> None:
    harness = _RecordingPersonal()
    asyncio.run(harness.add_base_profile("MySSID", "profile-1", False, "wpa-psk"))

    modify_calls = _modify_calls(harness.nmcli_calls)
    assert len(modify_calls) == 1
    args = modify_calls[0]
    assert "802-11-wireless-security.key-mgmt" in args
    assert args[args.index("802-11-wireless-security.key-mgmt") + 1] == "wpa-psk"
    # This is the actual fix: without this, NetworkManager can fall back to
    # querying a desktop secret agent (the keyring dialog) instead of using
    # the PSK supplied via `passwd-file` at activation time.
    assert "802-11-wireless-security.psk-flags" in args
    assert args[args.index("802-11-wireless-security.psk-flags") + 1] == "0"


def test_wpa3_sae_profile_also_clears_agent_owned_flag() -> None:
    harness = _RecordingPersonal()
    asyncio.run(harness.add_base_profile("MySSID", "profile-1", False, "sae"))

    modify_calls = _modify_calls(harness.nmcli_calls)
    args = modify_calls[0]
    assert args[args.index("802-11-wireless-security.key-mgmt") + 1] == "sae"
    assert args[args.index("802-11-wireless-security.psk-flags") + 1] == "0"


def test_open_network_profile_has_no_security_modify_call() -> None:
    harness = _RecordingPersonal()
    asyncio.run(harness.add_base_profile("MySSID", "profile-1", False, None))

    assert _modify_calls(harness.nmcli_calls) == []


def test_wep_base_profile_does_not_get_psk_flags() -> None:
    # WEP is handled through a different NM property (wep-key-flags, set
    # separately in connect_wep) - the PSK-specific flag must not leak in.
    harness = _RecordingPersonal()
    asyncio.run(harness.add_base_profile("MySSID", "profile-1", False, "none"))

    modify_calls = _modify_calls(harness.nmcli_calls)
    args = modify_calls[0]
    assert args[args.index("802-11-wireless-security.key-mgmt") + 1] == "none"
    assert "802-11-wireless-security.psk-flags" not in args


def test_enterprise_base_profile_does_not_get_psk_flags() -> None:
    harness = _RecordingPersonal()
    asyncio.run(harness.add_base_profile("MySSID", "profile-1", False, "wpa-eap"))

    modify_calls = _modify_calls(harness.nmcli_calls)
    args = modify_calls[0]
    assert args[args.index("802-11-wireless-security.key-mgmt") + 1] == "wpa-eap"
    assert "802-11-wireless-security.psk-flags" not in args


# --- connect_personal: end-to-end connection request -----------------------------


def test_wpa2_personal_connect_supplies_psk_via_passwd_file_not_argv() -> None:
    harness = _RecordingPersonal()
    captured_secrets: dict[str, str] = {}
    real_create_secret_file = AccessibleWifi.create_secret_file

    def spying_create_secret_file(secrets: dict[str, str]) -> str:
        captured_secrets.update(secrets)
        return real_create_secret_file(secrets)

    harness.create_secret_file = spying_create_secret_file

    password = "Sup3r Secret!"
    asyncio.run(
        harness.connect_personal("Home Network", password, "wpa-personal", hidden=False)
    )

    assert captured_secrets == {"802-11-wireless-security.psk": password}

    up_calls = [
        call for call in harness.nmcli_calls if call[:2] == ("connection", "up")
    ]
    assert len(up_calls) == 1
    assert "passwd-file" in up_calls[0]
    # The password itself must never appear as a literal argv element.
    assert password not in up_calls[0]
    assert not harness.errors
    assert harness.connected == ["Home Network"]


@pytest.mark.parametrize(
    "password",
    [
        "pass with spaces",
        'quote\'d "password"',
        "shell;chars$(whoami)`id`&&echo|<>*?[]{}",
        "back\\slash",
    ],
)
def test_wpa2_personal_connect_preserves_shell_sensitive_passwords_verbatim(
    password: str,
) -> None:
    harness = _RecordingPersonal()
    captured_secrets: dict[str, str] = {}
    real_create_secret_file = AccessibleWifi.create_secret_file

    def spying_create_secret_file(secrets: dict[str, str]) -> str:
        captured_secrets.update(secrets)
        return real_create_secret_file(secrets)

    harness.create_secret_file = spying_create_secret_file

    asyncio.run(
        harness.connect_personal("Home Network", password, "wpa-personal", hidden=False)
    )

    assert captured_secrets == {"802-11-wireless-security.psk": password}
    assert not harness.errors


def test_missing_password_never_reaches_nmcli() -> None:
    harness = _RecordingPersonal()
    asyncio.run(
        harness.connect_personal("Home Network", "", "wpa-personal", hidden=False)
    )

    # The failure happens before any profile is created or activated: only
    # the best-effort cleanup delete (a no-op here) may have run.
    assert not [
        call for call in harness.nmcli_calls if call[:2] == ("connection", "add")
    ]
    assert not [
        call for call in harness.nmcli_calls if call[:2] == ("connection", "up")
    ]
    assert harness.errors
    title, message = harness.errors[0]
    assert "password is required" in message.lower()


def test_open_network_connects_without_password() -> None:
    harness = _RecordingPersonal()
    asyncio.run(harness.connect_personal("Open Cafe", "", "open", hidden=False))

    up_calls = [
        call for call in harness.nmcli_calls if call[:2] == ("connection", "up")
    ]
    assert len(up_calls) == 1
    assert "passwd-file" not in up_calls[0]
    assert not harness.errors


def test_password_never_appears_in_status_or_error_text_on_failure() -> None:
    secret_password = "MyTotallySecretPassword123!"
    harness = _RecordingPersonal(fail_on="up")

    asyncio.run(
        harness.connect_personal(
            "Home Network", secret_password, "wpa-personal", hidden=False
        )
    )

    assert harness.errors
    combined = " ".join(harness.status_messages) + " ".join(
        f"{t} {m}" for t, m in harness.errors
    )
    assert secret_password not in combined

    # A profile-cleanup delete must have been attempted after the failure.
    delete_calls = [
        call for call in harness.nmcli_calls if call[:2] == ("connection", "delete")
    ]
    assert delete_calls


# --- connect_wep: legacy WEP profile still gets an explicit secret-flag ----------


class _RecordingWep:
    connect_wep = AccessibleWifi.connect_wep
    close_wep_window = AccessibleWifi.close_wep_window
    add_base_profile = AccessibleWifi.add_base_profile
    delete_profile = AccessibleWifi.delete_profile
    cleanup_failed_profile = AccessibleWifi.cleanup_failed_profile
    activate = AccessibleWifi.activate
    connecting_ticker = AccessibleWifi.connecting_ticker
    _connect_tick_loop = AccessibleWifi._connect_tick_loop
    _play_tick = AccessibleWifi._play_tick
    validate_ssid = staticmethod(AccessibleWifi.validate_ssid)
    profile_name = staticmethod(AccessibleWifi.profile_name)
    create_secret_file = staticmethod(AccessibleWifi.create_secret_file)

    def __init__(self) -> None:
        self.nmcli_calls: list[tuple[str, ...]] = []
        self.status_messages: list[str] = []
        self.errors: list[tuple[str, str]] = []
        self._tick_command = None
        self.wep_window = None
        self.wep_ssid = _FakeValue("LegacyGear")
        self.wep_visibility = _FakeValue("Visible network")
        self.wep_auth = _FakeValue("Open-system authentication")
        self.wep_key_type = _FakeValue("Hexadecimal or ASCII key")
        self.wep_key = _FakeValue("1A2B3C4D5E")
        self.wep_index = _FakeValue("Key 1")

    async def run_nmcli(self, *args: str, timeout: int = 90, check: bool = True) -> str:
        self.nmcli_calls.append(args)
        return ""

    def set_busy(self, busy: bool, message: str | None = None) -> None:
        pass

    def set_status(self, message: str) -> None:
        self.status_messages.append(message)

    async def show_error(self, title: str, message: str, window=None) -> None:
        self.errors.append((title, message))

    def focus_connected_network(self, ssid: str) -> None:
        pass

    async def handle_connection_result(self, ssid: str) -> None:
        pass


def test_wep_connect_sets_wep_key_flags_to_zero() -> None:
    harness = _RecordingWep()
    asyncio.run(harness.connect_wep(widget=None))

    modify_calls = _modify_calls(harness.nmcli_calls)
    flag_calls = [
        call
        for call in modify_calls
        if "802-11-wireless-security.wep-key-flags" in call
    ]
    assert len(flag_calls) == 1
    args = flag_calls[0]
    assert args[args.index("802-11-wireless-security.wep-key-flags") + 1] == "0"
    assert not harness.errors
