"""
Accessible Wi-Fi Manager for BeeWare/Toga on Linux.

Supports:
    * Visible and hidden networks
    * Open Wi-Fi
    * WPA/WPA2 Personal
    * WPA3 Personal
    * WPA Enterprise / 802.1X using PEAP, TTLS, or TLS
    * CA, client-certificate, and private-key paths
    * Legacy WEP
    * Captive-portal detection and browser launch
    * Wi-Fi restart

Requirements:
    * Linux with NetworkManager
    * nmcli
    * BeeWare Toga
    * A PolicyKit agent when authorization is required

Do not run this entire program with sudo.
"""
from __future__ import annotations

import asyncio
import math
import os
import re
import shutil
import struct
import tempfile
import webbrowser
from collections.abc import Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW


PORTAL_URL = "http://example.com/"

# A short, quiet tick tone repeated in the background while a connection
# attempt is in progress, so screen-reader users have a non-speech cue that
# the app is still working during the gap between the "Connecting" and
# connection-result announcements.
TICK_SAMPLE_RATE = 22050
TICK_INTERVAL_SECONDS = 1.2


def _generate_tick_pcm() -> bytes:
    duration_seconds = 0.08
    frequency_hz = 900
    frame_count = int(TICK_SAMPLE_RATE * duration_seconds)
    samples = bytearray()
    for index in range(frame_count):
        time = index / TICK_SAMPLE_RATE
        envelope = 1.0 - (index / frame_count)
        amplitude = int(8000 * envelope * math.sin(2 * math.pi * frequency_hz * time))
        samples += struct.pack("<h", amplitude)
    return bytes(samples)


TICK_PCM = _generate_tick_pcm()

# Speaks status text through Orca's D-Bus service (PresentMessage) instead of
# a screen widget, so screen-reader users hear status changes immediately
# without focus moving away from whatever control they're on.
ORCA_SPEAK_COMMAND = [
    "busctl", "--user", "call", "--expect-reply=false",
    "org.gnome.Orca.Service", "/org/gnome/Orca/Service",
    "org.gnome.Orca.Service", "PresentMessage", "s",
]


class NmcliError(RuntimeError):
    pass


class RevealablePasswordInput:
    """A single password entry paired with a "Show password" switch.

    Toga's PasswordInput cannot toggle masking on the fly, so this keeps one
    TextInput widget for the lifetime of the control and flips the
    underlying GTK entry's visibility property when the switch changes.
    Because it is always the same widget, the value, cursor position,
    selection, focus, accessible name, and tab order are untouched by
    toggling — and a screen reader only ever encounters one edit field.
    """

    def __init__(
        self,
        on_confirm: Callable[[toga.Widget], object] | None = None,
        style: Pack | None = None,
        speak_callback: Callable[[str], None] | None = None,
    ) -> None:
        self._speak_callback = speak_callback

        self.entry = toga.TextInput(
            on_confirm=on_confirm,
            style=style or Pack(flex=1),
        )
        self._set_masked(True)
        self.show_switch = toga.Switch(
            "Show password",
            on_change=self._show_changed,
            style=Pack(margin_top=3, margin_bottom=8),
        )

        self.box = toga.Box(
            children=[self.entry, self.show_switch],
            style=Pack(direction=COLUMN),
        )

    def _set_masked(self, masked: bool) -> None:
        self.entry._impl.native.set_visibility(not masked)

    def _show_changed(self, widget: toga.Switch) -> None:
        self._set_masked(not self.show_switch.value)
        if self.show_switch.value and self._speak_callback:
            self._speak_callback(
                f"Password: {self.entry.value}"
                if self.entry.value
                else "Password is empty."
            )

    @property
    def value(self) -> str:
        return self.entry.value

    @value.setter
    def value(self, new_value: str) -> None:
        self.entry.value = new_value

    @property
    def enabled(self) -> bool:
        return self.entry.enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self.entry.enabled = value
        self.show_switch.enabled = value

    def focus(self) -> None:
        self.entry.focus()


@dataclass(frozen=True)
class WifiNetwork:
    ssid: str
    signal: int
    security: str
    in_use: bool = False

    @property
    def security_upper(self) -> str:
        return self.security.upper()

    @property
    def is_open(self) -> bool:
        return self.security.strip().lower() in {"", "--", "none", "open"}

    @property
    def is_enterprise(self) -> bool:
        value = self.security_upper
        return "802.1X" in value or "8021X" in value or "EAP" in value

    @property
    def is_wep(self) -> bool:
        return "WEP" in self.security_upper

    @property
    def is_wpa3_only(self) -> bool:
        value = self.security_upper
        return "SAE" in value and "PSK" not in value and "WPA2" not in value

    @property
    def display_name(self) -> str:
        connected = "Connected. " if self.in_use else ""
        security = "Open network" if self.is_open else self.security
        return (
            f"{connected}{self.ssid}. Signal {self.signal} percent. {security}"
        )

class AccessibleWifi(toga.App):
    def startup(self) -> None:
        #print("USER =", os.environ.get("USER"))
        #print("XDG_SESSION_TYPE =", os.environ.get("XDG_SESSION_TYPE"))
        #print("DBUS_SESSION_BUS_ADDRESS =", os.environ.get("DBUS_SESSION_BUS_ADDRESS"))
        #print("XDG_RUNTIME_DIR =", os.environ.get("XDG_RUNTIME_DIR"))
        self.networks: list[WifiNetwork] = []
        self.network_by_description: dict[str, WifiNetwork] = {}
        self._tick_command = self._detect_tick_command()

        self.hidden_window: toga.Window | None = None
        self.enterprise_window: toga.Window | None = None
        self.wep_window: toga.Window | None = None

        self.instructions = toga.Label(
            "Choose a visible network and press Connect. Use the additional "
            "buttons for hidden, enterprise, certificate, or WEP networks.",
            style=Pack(margin_bottom=12),
        )

        self.network_selection = toga.Selection(
            items=["Press Refresh Networks to scan"],
            on_change=self.network_changed,
            style=Pack(flex=1),
        )
        self.network_selection.enabled = False

        self.password_label = toga.Label(
            "Wi-Fi password:",
            style=Pack(margin_top=12, margin_bottom=5),
        )
        self.password_input = RevealablePasswordInput(
            on_confirm=self.connect_selected_network,
            speak_callback=self.speak,
        )
        self.password_input.enabled = False

        self.connect_button = toga.Button(
            "Connect to Selected Network",
            on_press=self.connect_selected_network,
            enabled=False,
            style=Pack(flex=1, margin_right=5),
        )
        self.refresh_button = toga.Button(
            "Refresh Networks",
            on_press=self.refresh_networks,
            style=Pack(flex=1, margin_left=5),
        )

        self.hidden_button = toga.Button(
            "Hidden Personal or Open Network",
            on_press=self.show_hidden_window,
            style=Pack(flex=1, margin_right=5),
        )
        self.enterprise_button = toga.Button(
            "Enterprise or Certificate Network",
            on_press=self.show_enterprise_window,
            style=Pack(flex=1, margin_left=5),
        )

        self.wep_button = toga.Button(
            "Legacy WEP Network",
            on_press=self.show_wep_window,
            style=Pack(flex=1, margin_right=5),
        )
        self.restart_button = toga.Button(
            "Restart Wi-Fi",
            on_press=self.restart_wifi,
            style=Pack(flex=1, margin_left=5),
        )

        self.portal_button = toga.Button(
            "Open Wi-Fi Sign-In Page",
            on_press=self.open_portal_page,
            enabled=False,
            style=Pack(flex=1, margin_right=5),
        )
        self.check_button = toga.Button(
            "Check Internet Again",
            on_press=self.check_internet_again,
            style=Pack(flex=1, margin_left=5),
        )

        self.status_label = toga.Label(
            "Status: Ready.",
            style=Pack(margin_top=15),
        )

        content = toga.Box(
            children=[
                self.instructions,
                toga.Label(
                    "Available Wi-Fi networks:",
                    style=Pack(margin_bottom=5),
                ),
                self.network_selection,
                self.password_label,
                self.password_input.box,
                self.button_row(self.connect_button, self.refresh_button),
                self.button_row(self.hidden_button, self.enterprise_button),
                self.button_row(self.wep_button, self.restart_button),
                self.button_row(self.portal_button, self.check_button),
                self.status_label,
            ],
            style=Pack(direction=COLUMN, margin=20),
        )

        self.main_window = toga.MainWindow(
            title="Accessible Wi-Fi Setup",
            size=(760, 560),
        )
        self.main_window.content = content
        self.main_window.show()

        asyncio.create_task(self.initial_scan())

    @staticmethod
    def button_row(left: toga.Button, right: toga.Button) -> toga.Box:
        return toga.Box(
            children=[left, right],
            style=Pack(direction=ROW, margin_top=10),
        )

    async def initial_scan(self) -> None:
        await asyncio.sleep(0.25)
        await self.scan_for_networks()

    def set_status(self, message: str) -> None:
        self.status_label.text = f"Status: {message}"
        self.speak(message)

    def speak(self, message: str) -> None:
        """Announce `message` via Orca, without moving keyboard focus.

        Unlike updating a label (only announced if that label happens to
        have focus) or a dialog (steals focus and requires dismissal), this
        goes straight to Orca over D-Bus, so status changes are reliably
        heard by screen-reader users no matter what control they're on.
        """
        try:
            asyncio.create_task(self._speak_async(message))
        except RuntimeError:
            pass

    @staticmethod
    async def _speak_async(message: str) -> None:
        try:
            process = await asyncio.create_subprocess_exec(
                *ORCA_SPEAK_COMMAND,
                message,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(process.communicate(), timeout=2)
        except Exception:
            # Speech is a best-effort accessibility aid; never let a
            # missing Orca/D-Bus session break the underlying operation.
            pass

    @staticmethod
    def _detect_tick_command() -> list[str] | None:
        if shutil.which("paplay"):
            return [
                "paplay",
                "--raw",
                f"--rate={TICK_SAMPLE_RATE}",
                "--channels=1",
                "--format=s16le",
            ]
        if shutil.which("aplay"):
            return [
                "aplay",
                "-q",
                "-t",
                "raw",
                "-r",
                str(TICK_SAMPLE_RATE),
                "-f",
                "S16_LE",
                "-c",
                "1",
            ]
        return None

    async def _play_tick(self) -> None:
        if not self._tick_command:
            return
        try:
            process = await asyncio.create_subprocess_exec(
                *self._tick_command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(process.communicate(TICK_PCM), timeout=2)
        except Exception:
            # The tick is a best-effort activity cue; never let a missing
            # audio player break the underlying connection attempt.
            pass

    async def _connect_tick_loop(self) -> None:
        while True:
            await asyncio.sleep(TICK_INTERVAL_SECONDS)
            await self._play_tick()

    @asynccontextmanager
    async def connecting_ticker(self):
        """Play a repeating tick sound for the duration of the `async with`
        block, giving screen-reader users a non-speech cue that the app is
        still working during a Wi-Fi connection attempt."""
        task = asyncio.create_task(self._connect_tick_loop())
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    async def show_error(
        self,
        title: str,
        message: str,
        window: toga.Window | None = None,
    ) -> None:
        await (window or self.main_window).dialog(
            toga.ErrorDialog(title, message)
        )

    def set_busy(self, busy: bool, message: str | None = None) -> None:
        for button in (
            self.refresh_button,
            self.hidden_button,
            self.enterprise_button,
            self.wep_button,
            self.restart_button,
            self.check_button,
        ):
            button.enabled = not busy

        if busy:
            self.network_selection.enabled = False
            self.password_input.enabled = False
            self.connect_button.enabled = False
            if message:
                self.set_status(message)
        else:
            self.network_selection.enabled = bool(self.networks)
            self.network_changed(self.network_selection)

    @staticmethod
    def validate_ssid(ssid: str) -> None:
        if not ssid:
            raise NmcliError("The network name cannot be blank.")
        if "\n" in ssid or "\r" in ssid:
            raise NmcliError("The network name cannot contain a line break.")

    @staticmethod
    def validate_file(
        path_text: str,
        description: str,
        required: bool = False,
    ) -> str:
        path_text = path_text.strip()
        if not path_text:
            if required:
                raise NmcliError(f"{description} is required.")
            return ""

        path = Path(path_text).expanduser().resolve()
        if not path.is_file():
            raise NmcliError(f"{description} was not found: {path}")
        return str(path)

    async def run_nmcli(
        self,
        *arguments: str,
        timeout: int = 90,
        check: bool = True,
    ) -> str:
        if shutil.which("nmcli") is None:
            raise NmcliError(
                "The nmcli program was not found. Install NetworkManager."
            )

        process = await asyncio.create_subprocess_exec(
            "nmcli",
            "--colors",
            "no",
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError as error:
            process.kill()
            await process.communicate()
            raise NmcliError("The NetworkManager operation timed out.") from error

        output = stdout.decode("utf-8", errors="replace").strip()
        error_output = stderr.decode("utf-8", errors="replace").strip()

        if check and process.returncode != 0:
            raise NmcliError(
                error_output
                or output
                or "NetworkManager reported an unknown error."
            )
        return output

    @staticmethod
    def create_secret_file(secrets: dict[str, str]) -> str:
        descriptor, path = tempfile.mkstemp(
            prefix="accessible-wifi-",
            suffix=".secrets",
            text=True,
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                for property_name, value in secrets.items():
                    if "\n" in value or "\r" in value:
                        raise NmcliError(
                            f"The secret for {property_name} contains a line break."
                        )
                    handle.write(f"{property_name}:{value}\n")
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            raise
        return path

    async def activate(
        self,
        profile_name: str,
        secrets: dict[str, str] | None = None,
    ) -> None:
        secret_file: str | None = None
        try:
            args = ["connection", "up", "id", profile_name]
            if secrets:
                secret_file = self.create_secret_file(secrets)
                args.extend(["passwd-file", secret_file])
            await self.run_nmcli(*args, timeout=120)
        finally:
            if secret_file:
                try:
                    os.unlink(secret_file)
                except FileNotFoundError:
                    pass

    async def delete_profile(self, profile_name: str) -> None:
        await self.run_nmcli(
            "connection",
            "delete",
            "id",
            profile_name,
            timeout=30,
            check=False,
        )

    async def cleanup_failed_profile(self, profile_name: str) -> None:
        """Best-effort delete of a just-created profile after a failed
        connection attempt. Must never raise: it runs from an `except`
        block, and letting a cleanup failure propagate would swallow the
        real error message the user is about to be told via a dialog."""
        try:
            await self.delete_profile(profile_name)
        except NmcliError:
            pass

    @staticmethod
    def profile_name(ssid: str, category: str) -> str:
        cleaned = re.sub(r"[\r\n\t]", " ", ssid).strip()
        return f"Accessible Wi-Fi {category} - {cleaned}"

    async def add_base_profile(
        self,
        ssid: str,
        profile_name: str,
        hidden: bool,
        key_management: str | None,
    ) -> None:
        args = [
            "connection",
            "add",
            "type",
            "wifi",
            "ifname",
            "*",
            "con-name",
            profile_name,
            "ssid",
            ssid,
            "802-11-wireless.mode",
            "infrastructure",
            "connection.autoconnect",
            "yes",
            "ipv4.method",
            "auto",
            "ipv6.method",
            "auto",
        ]
        if hidden:
            args.extend(["802-11-wireless.hidden", "yes"])

        await self.run_nmcli(*args, timeout=30)

        if key_management:
            await self.run_nmcli(
                "connection",
                "modify",
                "id",
                profile_name,
                "802-11-wireless-security.key-mgmt",
                key_management,
                timeout=30,
            )

    async def refresh_networks(self, widget: toga.Widget) -> None:
        await self.scan_for_networks()

    async def scan_for_networks(self) -> None:
        self.set_busy(True, "Scanning for Wi-Fi networks.")
        try:
            await self.run_nmcli("radio", "wifi", "on", timeout=15)
            output = await self.run_nmcli(
                "--terse",
                "--escape",
                "yes",
                "--fields",
                "IN-USE,SSID,SIGNAL,SECURITY",
                "device",
                "wifi",
                "list",
                "--rescan",
                "yes",
                timeout=45,
            )

            self.networks = self.parse_wifi_list(output)
            self.network_by_description = {
                network.display_name: network for network in self.networks
            }

            if not self.networks:
                self.network_selection.items = [
                    "No visible Wi-Fi networks were found"
                ]
                self.network_selection.enabled = False
                self.connect_button.enabled = False
                self.password_input.enabled = False
                self.set_status(
                    "No visible networks were found. Hidden networks can "
                    "still be entered manually."
                )
                return

            descriptions = [network.display_name for network in self.networks]
            self.network_selection.items = descriptions
            self.network_selection.value = descriptions[0]
            self.network_selection.enabled = True
            self.network_changed(self.network_selection)
            self.set_status(f"Found {len(self.networks)} visible networks.")
        except NmcliError as error:
            self.set_status(f"Wi-Fi scan failed: {error}")
            await self.show_error("Wi-Fi scan failed", str(error))
        finally:
            self.set_busy(False)

    def parse_wifi_list(self, output: str) -> list[WifiNetwork]:
        strongest: dict[str, WifiNetwork] = {}

        for line in output.splitlines():
            fields = self.split_nmcli_fields(line)
            if len(fields) < 4:
                continue

            ssid = fields[1].strip()
            if not ssid:
                continue

            try:
                signal = int(fields[2])
            except ValueError:
                signal = 0

            network = WifiNetwork(
                ssid=ssid,
                signal=signal,
                security=fields[3].strip(),
                in_use=fields[0].strip() == "*",
            )

            old = strongest.get(ssid)
            if old is None or network.signal > old.signal:
                strongest[ssid] = network

        return sorted(
            strongest.values(),
            key=lambda item: (
                not item.in_use,
                -item.signal,
                item.ssid.casefold(),
            ),
        )

    @staticmethod
    def split_nmcli_fields(line: str) -> list[str]:
        fields: list[str] = []
        current: list[str] = []
        escaped = False

        for character in line:
            if escaped:
                current.append(character)
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == ":":
                fields.append("".join(current))
                current = []
            else:
                current.append(character)

        if escaped:
            current.append("\\")
        fields.append("".join(current))
        return fields

    def selected_network(self) -> WifiNetwork | None:
        value = self.network_selection.value
        if value is None:
            return None
        return self.network_by_description.get(str(value))

    def network_changed(self, widget: toga.Selection) -> None:
        network = self.selected_network()

        if network is None:
            self.password_label.text = "Wi-Fi password:"
            self.password_input.enabled = False
            self.connect_button.enabled = False
        elif network.is_enterprise:
            self.password_label.text = "Use Enterprise or Certificate Network"
            self.password_input.value = ""
            self.password_input.enabled = False
            self.connect_button.enabled = True
        elif network.is_wep:
            self.password_label.text = "Use Legacy WEP Network"
            self.password_input.value = ""
            self.password_input.enabled = False
            self.connect_button.enabled = True
        elif network.is_open:
            self.password_label.text = "Wi-Fi password: Not required"
            self.password_input.value = ""
            self.password_input.enabled = False
            self.connect_button.enabled = True
        else:
            self.password_label.text = "Wi-Fi password:"
            self.password_input.enabled = True
            self.connect_button.enabled = True

    def focus_connected_network(self, ssid: str) -> None:
        """Select and focus the just-connected SSID in the network list
        without re-scanning, so screen-reader users land back on the
        network they just joined."""
        for description, network in self.network_by_description.items():
            if network.ssid == ssid:
                self.network_selection.value = description
                break

        if self.network_selection.enabled:
            self.network_selection.focus()

    async def connect_selected_network(self, widget: toga.Widget) -> None:
        network = self.selected_network()
        if network is None:
            await self.show_error("No network selected", "Choose a network first.")
            return

        if network.is_enterprise:
            self.show_enterprise_window(widget)
            self.enterprise_ssid.value = network.ssid
            return

        if network.is_wep:
            self.show_wep_window(widget)
            self.wep_ssid.value = network.ssid
            return

        password = self.password_input.value or ""
        if not network.is_open and not password:
            await self.show_error(
                "Password required",
                f"Enter the password for {network.ssid}.",
            )
            return

        security = (
            "open"
            if network.is_open
            else "wpa3"
            if network.is_wpa3_only
            else "wpa-personal"
        )
        await self.connect_personal(
            network.ssid,
            password,
            security,
            hidden=False,
        )

    async def connect_personal(
        self,
        ssid: str,
        password: str,
        security: str,
        hidden: bool,
    ) -> None:
        self.set_busy(True, f"Connecting to {ssid}.")
        profile = self.profile_name(
            ssid,
            "Hidden" if hidden else "Personal",
        )

        try:
            self.validate_ssid(ssid)
            if security != "open" and not password:
                raise NmcliError("A password is required.")

            key_management = {
                "open": None,
                "wpa-personal": "wpa-psk",
                "wpa3": "sae",
            }[security]

            secrets = (
                None
                if security == "open"
                else {"802-11-wireless-security.psk": password}
            )

            async with self.connecting_ticker():
                await self.delete_profile(profile)
                await self.add_base_profile(
                    ssid,
                    profile,
                    hidden,
                    key_management,
                )
                await self.activate(profile, secrets)
            self.password_input.value = ""
            await self.handle_connection_result(ssid)
            self.focus_connected_network(ssid)
        except (NmcliError, KeyError) as error:
            await self.cleanup_failed_profile(profile)
            self.set_status(f"Connection failed: {error}")
            await self.show_error(
                "Could not connect",
                f"Could not connect to {ssid}.\n\n{error}",
            )
        finally:
            self.set_busy(False)

    # Hidden network window

    def show_hidden_window(self, widget: toga.Widget) -> None:
        if self.hidden_window is not None:
            self.hidden_window.show()
            self.hidden_ssid.focus()
            return

        self.hidden_ssid = toga.TextInput(style=Pack(flex=1))
        self.hidden_security = toga.Selection(
            items=[
                "Open, no password",
                "WPA or WPA2 Personal",
                "WPA3 Personal",
            ],
            on_change=self.hidden_security_changed,
            style=Pack(flex=1),
        )
        self.hidden_security.value = "WPA or WPA2 Personal"
        self.hidden_password_label = toga.Label("Wi-Fi password:")
        self.hidden_password = RevealablePasswordInput(
            on_confirm=self.connect_hidden,
            speak_callback=self.speak,
        )

        content = toga.Box(
            children=[
                toga.Label(
                    "Enter the exact hidden network name. It is case-sensitive.",
                    style=Pack(margin_bottom=10),
                ),
                toga.Label("Hidden network name:"),
                self.hidden_ssid,
                toga.Label("Security type:", style=Pack(margin_top=8)),
                self.hidden_security,
                self.hidden_password_label,
                self.hidden_password.box,
                self.button_row(
                    toga.Button(
                        "Connect",
                        on_press=self.connect_hidden,
                        style=Pack(flex=1, margin_right=5),
                    ),
                    toga.Button(
                        "Cancel",
                        on_press=self.close_hidden_window,
                        style=Pack(flex=1, margin_left=5),
                    ),
                ),
            ],
            style=Pack(direction=COLUMN, margin=20),
        )

        self.hidden_window = toga.Window(
            title="Hidden Personal or Open Wi-Fi",
            size=(600, 390),
        )
        self.hidden_window.content = content
        self.hidden_window.show()
        self.hidden_ssid.focus()

    def hidden_security_changed(self, widget: toga.Selection) -> None:
        is_open = str(self.hidden_security.value) == "Open, no password"
        self.hidden_password.enabled = not is_open
        self.hidden_password_label.text = (
            "Wi-Fi password: Not required" if is_open else "Wi-Fi password:"
        )
        if is_open:
            self.hidden_password.value = ""

    def close_hidden_window(self, widget: toga.Widget) -> None:
        if self.hidden_window is not None:
            self.hidden_window.close()
            self.hidden_window = None

    async def connect_hidden(self, widget: toga.Widget) -> None:
        ssid = (self.hidden_ssid.value or "").strip()
        password = self.hidden_password.value or ""
        selected = str(self.hidden_security.value or "")
        security = {
            "Open, no password": "open",
            "WPA or WPA2 Personal": "wpa-personal",
            "WPA3 Personal": "wpa3",
        }.get(selected)

        try:
            self.validate_ssid(ssid)
            if security is None:
                raise NmcliError("Choose a security type.")
            if security != "open" and not password:
                raise NmcliError("Enter the Wi-Fi password.")
        except NmcliError as error:
            await self.show_error(
                "Cannot connect",
                str(error),
                self.hidden_window,
            )
            return

        self.close_hidden_window(widget)
        await self.connect_personal(ssid, password, security, hidden=True)

    # Enterprise window

    def show_enterprise_window(self, widget: toga.Widget) -> None:
        if self.enterprise_window is not None:
            self.enterprise_window.show()
            self.enterprise_ssid.focus()
            return

        self.enterprise_ssid = toga.TextInput(style=Pack(flex=1))
        self.enterprise_visibility = toga.Selection(
            items=["Visible network", "Hidden network"],
            style=Pack(flex=1),
        )
        self.enterprise_visibility.value = "Visible network"

        self.enterprise_method = toga.Selection(
            items=[
                "PEAP with username and password",
                "TTLS with username and password",
                "TLS with client certificate",
            ],
            on_change=self.enterprise_method_changed,
            style=Pack(flex=1),
        )
        self.enterprise_method.value = "PEAP with username and password"

        self.enterprise_inner = toga.Selection(
            items=["MSCHAPv2", "GTC", "MD5", "PAP", "CHAP", "MSCHAP"],
            style=Pack(flex=1),
        )
        self.enterprise_inner.value = "MSCHAPv2"

        self.enterprise_identity = toga.TextInput(style=Pack(flex=1))
        self.enterprise_anonymous = toga.TextInput(style=Pack(flex=1))
        self.enterprise_password = RevealablePasswordInput(speak_callback=self.speak)
        self.enterprise_ca = toga.TextInput(style=Pack(flex=1))
        self.enterprise_domain = toga.TextInput(style=Pack(flex=1))
        self.enterprise_client_cert = toga.TextInput(style=Pack(flex=1))
        self.enterprise_private_key = toga.TextInput(style=Pack(flex=1))
        self.enterprise_key_password = RevealablePasswordInput(speak_callback=self.speak)

        self.enterprise_inner_label = toga.Label("Inner authentication:")
        self.enterprise_password_label = toga.Label("Account password:")
        self.enterprise_client_label = toga.Label("Client certificate path:")
        self.enterprise_key_label = toga.Label("Private key path:")
        self.enterprise_key_password_label = toga.Label(
            "Private-key or PKCS#12 password:"
        )

        content = toga.Box(
            children=[
                toga.Label(
                    "Use the exact settings supplied by the network "
                    "administrator. CA validation is strongly recommended.",
                    style=Pack(margin_bottom=10),
                ),
                toga.Label("Network name, SSID:"),
                self.enterprise_ssid,
                toga.Label("Visibility:", style=Pack(margin_top=8)),
                self.enterprise_visibility,
                toga.Label("Authentication method:", style=Pack(margin_top=8)),
                self.enterprise_method,
                self.enterprise_inner_label,
                self.enterprise_inner,
                toga.Label("Identity or username:", style=Pack(margin_top=8)),
                self.enterprise_identity,
                toga.Label("Anonymous identity, optional:", style=Pack(margin_top=8)),
                self.enterprise_anonymous,
                self.enterprise_password_label,
                self.enterprise_password.box,
                toga.Label("CA certificate path, recommended:", style=Pack(margin_top=8)),
                self.enterprise_ca,
                toga.Label("Authentication server domain, recommended:", style=Pack(margin_top=8)),
                self.enterprise_domain,
                self.enterprise_client_label,
                self.enterprise_client_cert,
                self.enterprise_key_label,
                self.enterprise_private_key,
                self.enterprise_key_password_label,
                self.enterprise_key_password.box,
                self.button_row(
                    toga.Button(
                        "Connect",
                        on_press=self.connect_enterprise,
                        style=Pack(flex=1, margin_right=5),
                    ),
                    toga.Button(
                        "Cancel",
                        on_press=self.close_enterprise_window,
                        style=Pack(flex=1, margin_left=5),
                    ),
                ),
            ],
            style=Pack(direction=COLUMN, margin=20),
        )

        self.enterprise_window = toga.Window(
            title="Enterprise or Certificate Wi-Fi",
            size=(760, 850),
        )
        self.enterprise_window.content = content
        self.enterprise_window.show()
        self.enterprise_method_changed(self.enterprise_method)
        self.enterprise_ssid.focus()

    def enterprise_method_changed(self, widget: toga.Selection) -> None:
        is_tls = (
            str(self.enterprise_method.value)
            == "TLS with client certificate"
        )

        self.enterprise_inner.enabled = not is_tls
        self.enterprise_anonymous.enabled = not is_tls
        self.enterprise_password.enabled = not is_tls
        self.enterprise_client_cert.enabled = is_tls
        self.enterprise_private_key.enabled = is_tls
        self.enterprise_key_password.enabled = is_tls

        self.enterprise_inner_label.text = (
            "Inner authentication: Not used for TLS"
            if is_tls
            else "Inner authentication:"
        )
        self.enterprise_password_label.text = (
            "Account password: Not used for TLS"
            if is_tls
            else "Account password:"
        )
        self.enterprise_client_label.text = (
            "Client certificate path, PEM, DER, or PKCS#12:"
            if is_tls
            else "Client certificate path: Not used"
        )
        self.enterprise_key_label.text = (
            "Private key path, or same PKCS#12 file:"
            if is_tls
            else "Private key path: Not used"
        )

    def close_enterprise_window(self, widget: toga.Widget) -> None:
        if self.enterprise_window is not None:
            self.enterprise_window.close()
            self.enterprise_window = None

    async def connect_enterprise(self, widget: toga.Widget) -> None:
        ssid = (self.enterprise_ssid.value or "").strip()
        hidden = str(self.enterprise_visibility.value) == "Hidden network"
        method_text = str(self.enterprise_method.value or "")
        inner = str(self.enterprise_inner.value or "").lower()
        identity = (self.enterprise_identity.value or "").strip()
        anonymous = (self.enterprise_anonymous.value or "").strip()
        password = self.enterprise_password.value or ""
        ca_cert_text = (self.enterprise_ca.value or "").strip()
        domain = (self.enterprise_domain.value or "").strip()
        client_text = (self.enterprise_client_cert.value or "").strip()
        key_text = (self.enterprise_private_key.value or "").strip()
        key_password = self.enterprise_key_password.value or ""

        try:
            self.validate_ssid(ssid)
            if not identity:
                raise NmcliError("Enter the identity or username.")

            ca_cert = self.validate_file(
                ca_cert_text,
                "CA certificate",
                required=False,
            )

            if method_text == "TLS with client certificate":
                eap = "tls"
                client_cert = self.validate_file(
                    client_text,
                    "Client certificate",
                    required=True,
                )
                private_key = self.validate_file(
                    key_text,
                    "Private key",
                    required=True,
                )
            elif method_text == "TTLS with username and password":
                eap = "ttls"
                client_cert = ""
                private_key = ""
                if not password:
                    raise NmcliError("Enter the account password.")
            else:
                eap = "peap"
                client_cert = ""
                private_key = ""
                if not password:
                    raise NmcliError("Enter the account password.")
        except NmcliError as error:
            await self.show_error(
                "Cannot connect",
                str(error),
                self.enterprise_window,
            )
            return

        if not ca_cert:
            proceed = await self.main_window.dialog(
                toga.ConfirmDialog(
                    "No CA certificate provided",
                    "Without a CA certificate, this app cannot verify the "
                    "network's authentication server. A rogue access "
                    "point broadcasting the same network name could "
                    f"capture the username and password for {ssid}. "
                    "Connect anyway?",
                )
            )
            if not proceed:
                return

        self.close_enterprise_window(widget)
        self.set_busy(True, f"Connecting to enterprise network {ssid}.")
        profile = self.profile_name(ssid, "Enterprise")

        try:
            modify = [
                "connection",
                "modify",
                "id",
                profile,
                "802-1x.eap",
                eap,
                "802-1x.identity",
                identity,
            ]

            if anonymous:
                modify.extend(["802-1x.anonymous-identity", anonymous])
            if ca_cert:
                modify.extend(["802-1x.ca-cert", ca_cert])
            if domain:
                modify.extend(["802-1x.domain-suffix-match", domain])

            if eap in {"peap", "ttls"}:
                modify.extend(["802-1x.phase2-auth", inner])
            else:
                modify.extend(
                    [
                        "802-1x.client-cert",
                        client_cert,
                        "802-1x.private-key",
                        private_key,
                    ]
                )

            secrets: dict[str, str] = {}
            if eap in {"peap", "ttls"}:
                secrets["802-1x.password"] = password
            elif key_password:
                secrets["802-1x.private-key-password"] = key_password

            async with self.connecting_ticker():
                await self.delete_profile(profile)
                await self.add_base_profile(
                    ssid,
                    profile,
                    hidden,
                    "wpa-eap",
                )
                await self.run_nmcli(*modify, timeout=45)
                await self.activate(profile, secrets or None)
            await self.handle_connection_result(ssid)
            self.focus_connected_network(ssid)
        except NmcliError as error:
            await self.cleanup_failed_profile(profile)
            self.set_status(f"Enterprise connection failed: {error}")
            await self.show_error(
                "Could not connect",
                f"Could not connect to enterprise network {ssid}.\n\n{error}",
            )
        finally:
            self.set_busy(False)

    # WEP window

    def show_wep_window(self, widget: toga.Widget) -> None:
        if self.wep_window is not None:
            self.wep_window.show()
            self.wep_ssid.focus()
            return

        self.wep_ssid = toga.TextInput(style=Pack(flex=1))
        self.wep_visibility = toga.Selection(
            items=["Visible network", "Hidden network"],
            style=Pack(flex=1),
        )
        self.wep_visibility.value = "Visible network"
        self.wep_auth = toga.Selection(
            items=["Open-system authentication", "Shared-key authentication"],
            style=Pack(flex=1),
        )
        self.wep_auth.value = "Open-system authentication"
        self.wep_key_type = toga.Selection(
            items=["Hexadecimal or ASCII key", "Passphrase"],
            style=Pack(flex=1),
        )
        self.wep_key_type.value = "Hexadecimal or ASCII key"
        self.wep_key = RevealablePasswordInput(
            on_confirm=self.connect_wep,
            speak_callback=self.speak,
        )
        self.wep_index = toga.Selection(
            items=["Key 1", "Key 2", "Key 3", "Key 4"],
            style=Pack(flex=1),
        )
        self.wep_index.value = "Key 1"

        content = toga.Box(
            children=[
                toga.Label(
                    "Warning: WEP is obsolete and insecure. Use it only for "
                    "legacy equipment.",
                    style=Pack(margin_bottom=10),
                ),
                toga.Label("Network name, SSID:"),
                self.wep_ssid,
                toga.Label("Visibility:", style=Pack(margin_top=8)),
                self.wep_visibility,
                toga.Label("Authentication:", style=Pack(margin_top=8)),
                self.wep_auth,
                toga.Label("Key type:", style=Pack(margin_top=8)),
                self.wep_key_type,
                toga.Label("WEP key or passphrase:", style=Pack(margin_top=8)),
                self.wep_key.box,
                toga.Label("Key index:", style=Pack(margin_top=8)),
                self.wep_index,
                self.button_row(
                    toga.Button(
                        "Connect",
                        on_press=self.connect_wep,
                        style=Pack(flex=1, margin_right=5),
                    ),
                    toga.Button(
                        "Cancel",
                        on_press=self.close_wep_window,
                        style=Pack(flex=1, margin_left=5),
                    ),
                ),
            ],
            style=Pack(direction=COLUMN, margin=20),
        )

        self.wep_window = toga.Window(
            title="Legacy WEP Wi-Fi",
            size=(650, 560),
        )
        self.wep_window.content = content
        self.wep_window.show()
        self.wep_ssid.focus()

    def close_wep_window(self, widget: toga.Widget) -> None:
        if self.wep_window is not None:
            self.wep_window.close()
            self.wep_window = None

    async def connect_wep(self, widget: toga.Widget) -> None:
        ssid = (self.wep_ssid.value or "").strip()
        hidden = str(self.wep_visibility.value) == "Hidden network"
        auth = (
            "shared"
            if str(self.wep_auth.value) == "Shared-key authentication"
            else "open"
        )
        key_type = (
            "1"
            if str(self.wep_key_type.value) == "Passphrase"
            else "0"
        )
        key = self.wep_key.value or ""
        key_index = {
            "Key 1": "0",
            "Key 2": "1",
            "Key 3": "2",
            "Key 4": "3",
        }.get(str(self.wep_index.value), "0")

        try:
            self.validate_ssid(ssid)
            if not key:
                raise NmcliError("Enter the WEP key or passphrase.")
        except NmcliError as error:
            await self.show_error("Cannot connect", str(error), self.wep_window)
            return

        self.close_wep_window(widget)
        self.set_busy(True, f"Connecting to WEP network {ssid}.")
        profile = self.profile_name(ssid, "WEP")

        try:
            async with self.connecting_ticker():
                await self.delete_profile(profile)
                await self.add_base_profile(
                    ssid,
                    profile,
                    hidden,
                    "none",
                )

                await self.run_nmcli(
                    "connection",
                    "modify",
                    "id",
                    profile,
                    "802-11-wireless-security.auth-alg",
                    auth,
                    "802-11-wireless-security.wep-key-type",
                    key_type,
                    "802-11-wireless-security.wep-tx-keyidx",
                    key_index,
                    timeout=30,
                )

                await self.activate(
                    profile,
                    {f"802-11-wireless-security.wep-key{key_index}": key},
                )
            await self.handle_connection_result(ssid)
            self.focus_connected_network(ssid)
        except NmcliError as error:
            await self.cleanup_failed_profile(profile)
            self.set_status(f"WEP connection failed: {error}")
            await self.show_error(
                "Could not connect",
                f"Could not connect to WEP network {ssid}.\n\n{error}",
            )
        finally:
            self.set_busy(False)

    # Captive portal

    async def get_connectivity(self) -> str:
        result = await self.run_nmcli(
            "networking",
            "connectivity",
            "check",
            timeout=45,
        )
        value = result.strip().lower()
        return value if value in {
            "full",
            "portal",
            "limited",
            "none",
            "unknown",
        } else "unknown"

    async def handle_connection_result(self, ssid: str) -> None:
        self.set_status(f"Connected to {ssid}. Checking Internet access.")
        await asyncio.sleep(3)

        try:
            connectivity = await self.get_connectivity()
        except NmcliError as error:
            self.portal_button.enabled = True
            self.set_status(
                f"Connected to {ssid}, but Internet access could not be "
                f"checked: {error}"
            )
            return

        await self.report_connectivity(connectivity, ssid)

    async def report_connectivity(
        self,
        connectivity: str,
        ssid: str | None = None,
    ) -> None:
        name = ssid or "the current network"

        if connectivity == "full":
            self.portal_button.enabled = False
            self.set_status(
                f"Connected to {name}. Internet access is available."
            )
            return

        self.portal_button.enabled = True

        if connectivity == "portal":
            self.set_status(
                f"Connected to {name}. A web sign-in is required."
            )
            open_page = await self.main_window.dialog(
                toga.ConfirmDialog(
                    "Wi-Fi sign-in required",
                    f"{name} requires a web-page sign-in. Open it now?",
                )
            )
            if open_page:
                await self.launch_portal_browser()
        elif connectivity == "limited":
            self.set_status(
                f"Connected to {name}, but Internet access is limited."
            )
            open_page = await self.main_window.dialog(
                toga.ConfirmDialog(
                    "Limited Internet access",
                    "A captive-portal sign-in may be required. Open a "
                    "sign-in page?",
                )
            )
            if open_page:
                await self.launch_portal_browser()
        elif connectivity == "none":
            self.set_status(
                f"Connected to {name}, but no Internet access was detected."
            )
        else:
            self.set_status(
                f"Connected to {name}. Internet status is unknown."
            )

    async def open_portal_page(self, widget: toga.Widget) -> None:
        await self.launch_portal_browser()

    async def launch_portal_browser(self) -> None:
        try:
            opened = webbrowser.open(PORTAL_URL, new=1, autoraise=True)
        except Exception as error:
            opened = False
            details = str(error)
        else:
            details = "The desktop did not report that a browser was opened."

        if opened:
            self.set_status(
                "The sign-in page was opened. After signing in, return and "
                "press Check Internet Again."
            )
        else:
            await self.show_error(
                "Could not open browser",
                f"Open a browser and visit {PORTAL_URL}\n\n{details}",
            )

    async def check_internet_again(self, widget: toga.Widget) -> None:
        self.set_busy(True, "Checking Internet access.")
        try:
            await self.report_connectivity(await self.get_connectivity())
        except NmcliError as error:
            await self.show_error("Internet check failed", str(error))
        finally:
            self.set_busy(False)

    async def restart_wifi(self, widget: toga.Widget) -> None:
        self.set_busy(True, "Restarting Wi-Fi.")
        try:
            await self.run_nmcli("radio", "wifi", "off", timeout=15)
            await asyncio.sleep(2)
            await self.run_nmcli("radio", "wifi", "on", timeout=15)
            await asyncio.sleep(3)
            await self.scan_for_networks()
        except NmcliError as error:
            await self.show_error("Could not restart Wi-Fi", str(error))
        finally:
            self.set_busy(False)


def main() -> AccessibleWifi:
    return AccessibleWifi(
        formal_name="Accessible Wi-Fi",
        app_id="org.example.accessiblewifi",
    )


if __name__ == "__main__":
    app = main()
    app.main_loop()
