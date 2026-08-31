import gi

gi.require_version("Gdk", "3.0")
from gi.repository import Gdk

from accessiblewifi.app import RevealablePasswordInput, make_escape_close_handler


def test_first():
    """An initial test for the app."""
    assert 1 + 1 == 2


class _FakeKeyEvent:
    def __init__(self, keyval: int) -> None:
        self.keyval = keyval


def test_escape_key_closes_window():
    calls = []
    handler = make_escape_close_handler(lambda: calls.append(True))

    handled = handler(None, _FakeKeyEvent(Gdk.KEY_Escape))

    assert handled is True
    assert calls == [True]


def test_other_keys_do_not_close_window():
    calls = []
    handler = make_escape_close_handler(lambda: calls.append(True))

    handled = handler(None, _FakeKeyEvent(Gdk.KEY_a))

    assert handled is False
    assert calls == []


def test_show_password_switch_has_accessible_name():
    password_input = RevealablePasswordInput()

    accessible = password_input.show_switch._impl.native_switch.get_accessible()

    assert accessible.get_name() == "Show password"


def test_show_password_toggles_single_entry_widget():
    password_input = RevealablePasswordInput()
    password_input.value = "hunter2"

    assert password_input.entry._impl.native.get_visibility() is False

    password_input.show_switch.value = True

    assert password_input.entry._impl.native.get_visibility() is True
    assert password_input.value == "hunter2"
    assert len(password_input.box.children) == 2
