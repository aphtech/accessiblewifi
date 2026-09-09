"""Regression tests for captive-portal detection and browser launch.

The app has to find captive portals by itself: NetworkManager's own
connectivity checking is off by default on the target devices (and turning it
on would be a system-wide change), while forcing a recheck through nmcli is a
PolicyKit-guarded call that fails with "Not authorized to recheck
connectivity". These tests pin the behaviour that replaced it.

Probes run against a throwaway HTTP server on localhost rather than a mocked
socket layer, so the redirect handling, body reading, and error paths are the
real ones. Everything past the probe (dialogs, browser launch) uses the same
lightweight recording-harness style as `test_wifi_connection.py`.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from accessiblewifi.app import (
    PORTAL_URL,
    AccessibleWifi,
    ConnectivityResult,
    PortalProbe,
    classify_probe_response,
    probe_connectivity,
    safe_portal_url,
)


# Safe portal URLs


def test_relative_redirect_is_resolved_against_the_probe():
    resolved = safe_portal_url("/login?token=abc", "http://probe.example/generate_204")

    assert resolved == "http://probe.example/login?token=abc"


def test_absolute_redirect_is_kept():
    url = "https://portal.hotel.example/welcome"

    assert safe_portal_url(url, "http://probe.example/") == url


@pytest.mark.parametrize(
    "candidate",
    [
        None,
        "",
        "   ",
        # A portal is unauthenticated network equipment, so a Location header
        # is attacker-controlled: these must never reach a browser.
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "ftp://portal.example/login",
        # Malformed address that urlsplit itself refuses to parse.
        "http://[::1/login",
        # Header smuggling attempt.
        "http://portal.example/login\r\nX-Injected: 1",
    ],
)
def test_untrusted_redirect_targets_are_refused(candidate):
    assert safe_portal_url(candidate, "http://probe.example/") is None


def test_absurdly_long_redirect_target_is_refused():
    assert safe_portal_url("http://a.example/" + "x" * 4000, "http://p.example/") is None


# Classifying one probe response


def test_expected_response_means_full_access():
    probe = PortalProbe("http://probe.example/", 204)

    assert classify_probe_response(probe, 204, None, b"") == ("full", None)


def test_expected_body_must_also_match():
    probe = PortalProbe("http://probe.example/success.txt", 200, "success")

    assert classify_probe_response(probe, 200, None, b"success\n") == ("full", None)
    assert classify_probe_response(probe, 200, None, b"<html>Sign in</html>") == (
        "portal",
        None,
    )


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308, 511])
def test_redirect_reports_the_portal_address(status):
    probe = PortalProbe("http://probe.example/generate_204", 204)

    assert classify_probe_response(
        probe, status, "http://portal.example/login", b""
    ) == ("portal", "http://portal.example/login")


def test_redirect_without_a_usable_location_still_reports_a_portal():
    probe = PortalProbe("http://probe.example/generate_204", 204)

    assert classify_probe_response(probe, 302, "javascript:alert(1)", b"") == (
        "portal",
        None,
    )


def test_unexpected_status_is_treated_as_interception():
    probe = PortalProbe("http://probe.example/generate_204", 204)

    assert classify_probe_response(probe, 403, None, b"blocked") == ("portal", None)


# Probing a live server


class _Server:
    """A throwaway HTTP server answering every request the same way."""

    def __init__(self, respond):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                respond(self)

            def log_message(self, *args):
                pass

        self._httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def probe(self, expected_status=204, expected_body=""):
        return PortalProbe(
            f"http://127.0.0.1:{self.port}/generate_204",
            expected_status,
            expected_body,
        )


def _no_content(handler):
    handler.send_response(204)
    handler.end_headers()


def _redirect_to_portal(handler):
    handler.send_response(302)
    handler.send_header("Location", "http://portal.example/login?mac=aa-bb")
    handler.end_headers()


def _login_page(handler):
    body = b"<html><body>Please sign in</body></html>"
    handler.send_response(200)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def test_probe_reports_full_when_the_endpoint_answers_correctly():
    with _Server(_no_content) as server:
        assert probe_connectivity(server.probe(), 5) == ("full", None)


def test_probe_does_not_follow_the_portal_redirect():
    # Following it would land on the login page and report an ordinary 200,
    # hiding the redirect that is the whole detection signal.
    with _Server(_redirect_to_portal) as server:
        assert probe_connectivity(server.probe(), 5) == (
            "portal",
            "http://portal.example/login?mac=aa-bb",
        )


def test_probe_detects_a_login_page_served_without_a_redirect():
    with _Server(_login_page) as server:
        assert probe_connectivity(server.probe(), 5) == ("portal", None)


def test_probe_reports_none_when_nothing_answers():
    # Port 1 is reserved and never listening, so this is a refused connection.
    assert probe_connectivity(PortalProbe("http://127.0.0.1:1/x", 204), 2) == (
        "none",
        None,
    )


# Aggregating the probes


class _Connectivity:
    get_connectivity = AccessibleWifi.get_connectivity


def _connectivity_with(monkeypatch, outcomes):
    """Run `get_connectivity` with each probe returning a canned outcome."""
    from accessiblewifi import app as app_module

    probes = tuple(
        PortalProbe(f"http://probe{index}.example/", 204)
        for index in range(len(outcomes))
    )
    answers = dict(zip(probes, outcomes))
    monkeypatch.setattr(app_module, "PORTAL_PROBES", probes)
    monkeypatch.setattr(
        app_module, "probe_connectivity", lambda probe, timeout: answers[probe]
    )
    return asyncio.run(_Connectivity().get_connectivity())


def test_one_successful_probe_is_enough_to_call_it_online(monkeypatch):
    # A portal has to intercept every plain-HTTP request to work, so a single
    # untouched response proves nothing is in the way.
    result = _connectivity_with(
        monkeypatch, [("none", None), ("full", None), ("portal", "http://p/login")]
    )

    assert result == ConnectivityResult("full", PORTAL_URL)


def test_portal_wins_over_unreachable_probes(monkeypatch):
    result = _connectivity_with(
        monkeypatch, [("none", None), ("portal", "http://portal.example/login")]
    )

    assert result == ConnectivityResult("portal", "http://portal.example/login")


def test_portal_without_an_address_falls_back_to_the_generic_page(monkeypatch):
    result = _connectivity_with(monkeypatch, [("portal", None), ("none", None)])

    assert result == ConnectivityResult("portal", PORTAL_URL)


def test_all_probes_failing_reports_no_access(monkeypatch):
    result = _connectivity_with(monkeypatch, [("none", None), ("none", None)])

    assert result == ConnectivityResult("none", PORTAL_URL)


def test_connectivity_check_never_raises(monkeypatch):
    # It runs on the connection-result path, where an exception would leave a
    # screen-reader user with no spoken outcome at all.
    from accessiblewifi import app as app_module

    def explode(probe, timeout):
        raise OSError("network stack is on fire")

    monkeypatch.setattr(app_module, "probe_connectivity", explode)

    assert asyncio.run(_Connectivity().get_connectivity()) == ConnectivityResult(
        "none", PORTAL_URL
    )


# Reporting the result to the user


def _dialog_text(dialog_object) -> tuple[str, str]:
    """Read back a dialog's title and message.

    Toga keeps them only on the GTK widget the dialog builds, so this reaches
    into the backend the same way `test_app.py` does. The wording matters
    here: it is what a screen reader reads out when the dialog takes focus.
    """
    native = dialog_object._impl.native
    return native.get_property("text"), native.get_property("secondary-text")


class _FakeButton:
    def __init__(self) -> None:
        self.enabled = False


class _RecordingPortal:
    """Harness exposing the real reporting and browser-launch paths."""

    report_connectivity = AccessibleWifi.report_connectivity
    set_portal_available = AccessibleWifi.set_portal_available
    open_portal_page = AccessibleWifi.open_portal_page
    launch_portal_browser = AccessibleWifi.launch_portal_browser

    def __init__(self, *, confirm: bool = True, browser: str | None = "/bin/true"):
        self.portal_url = PORTAL_URL
        self.portal_button = _FakeButton()
        self._portal_available = False
        self._browser_processes: list = []
        self.status_messages: list[str] = []
        self.errors: list[tuple[str, str]] = []
        self.dialogs: list[tuple[str, str]] = []
        self.launched: list[str | None] = []
        self._confirm = confirm
        self._browser = browser
        self.main_window = self

    def set_status(self, message: str) -> None:
        self.status_messages.append(message)

    async def show_error(self, title: str, message: str, window=None) -> None:
        self.errors.append((title, message))

    async def dialog(self, dialog_object):
        self.dialogs.append(_dialog_text(dialog_object))
        return self._confirm

    def browser_command(self) -> str | None:
        return self._browser


class _NoLaunch(_RecordingPortal):
    async def launch_portal_browser(self, url: str | None = None) -> None:
        self.launched.append(url)


def test_full_access_offers_nothing_and_disables_the_sign_in_button():
    app = _NoLaunch()
    app.portal_button.enabled = True

    asyncio.run(app.report_connectivity(ConnectivityResult("full", PORTAL_URL), "Cafe"))

    assert app.dialogs == []
    assert app.launched == []
    assert app.portal_button.enabled is False
    assert "Internet access is available" in app.status_messages[-1]


def test_portal_offers_the_sign_in_page_and_opens_the_address_found():
    app = _NoLaunch()

    asyncio.run(
        app.report_connectivity(
            ConnectivityResult("portal", "http://portal.example/login"), "Cafe"
        )
    )

    assert app.portal_button.enabled is True
    assert app.dialogs[0][0] == "Wi-Fi sign-in required"
    assert app.launched == ["http://portal.example/login"]
    # Announced as a full sentence naming the network, for screen readers.
    assert "Cafe" in app.status_messages[-1]
    assert "web sign-in is required" in app.status_messages[-1]


def test_declining_the_dialog_does_not_open_a_browser():
    app = _NoLaunch(confirm=False)

    asyncio.run(
        app.report_connectivity(
            ConnectivityResult("portal", "http://portal.example/login"), "Cafe"
        )
    )

    assert app.launched == []
    # The button stays available so the user can change their mind.
    assert app.portal_button.enabled is True


def test_no_detected_access_still_offers_a_sign_in_page():
    # Portals that drop traffic instead of redirecting it are indistinguishable
    # from a dead network from here, so the offer has to be made anyway.
    app = _NoLaunch()

    asyncio.run(app.report_connectivity(ConnectivityResult("none", PORTAL_URL), "Cafe"))

    assert app.dialogs[0][0] == "No Internet access"
    assert app.launched == [PORTAL_URL]


def test_sign_in_button_reopens_the_last_portal_address():
    app = _NoLaunch()
    asyncio.run(
        app.report_connectivity(
            ConnectivityResult("portal", "http://portal.example/login"), "Cafe"
        )
    )
    app.launched.clear()

    asyncio.run(app.open_portal_page(None))

    assert app.portal_url == "http://portal.example/login"
    assert app.launched == [None]


# Launching the browser


def test_browser_that_hands_off_and_exits_cleanly_is_a_success():
    # This is what an already-running Firefox does: it passes the address to
    # the existing window and exits 0 immediately.
    app = _RecordingPortal(browser="/bin/true")

    asyncio.run(app.launch_portal_browser("http://portal.example/login"))

    assert app.errors == []
    assert "was opened in true" in app.status_messages[-1]
    assert "Check Internet Again" in app.status_messages[-1]


def test_browser_failing_immediately_is_reported():
    app = _RecordingPortal(browser="/bin/false")

    asyncio.run(app.launch_portal_browser("http://portal.example/login"))

    assert app.errors[-1][0] == "Could not open the sign-in page"
    assert PORTAL_URL in app.errors[-1][1]


def test_missing_browser_tells_the_user_where_to_go():
    app = _RecordingPortal(browser=None)

    asyncio.run(app.launch_portal_browser())

    assert app.errors[-1][0] == "No browser found"
    assert PORTAL_URL in app.errors[-1][1]


def test_unlaunchable_browser_does_not_escape_as_an_exception():
    app = _RecordingPortal(browser="/nonexistent/browser")

    asyncio.run(app.launch_portal_browser("http://portal.example/login"))

    assert app.errors[-1][0] == "Could not open the sign-in page"


def test_browser_is_given_the_display_environment():
    from accessiblewifi.app import BROWSER_ENV

    # The app can be started from a launcher with a trimmed environment; the
    # browser still has to reach the user's desktop session.
    assert BROWSER_ENV.get("DISPLAY")
    assert BROWSER_ENV.get("XDG_RUNTIME_DIR")
