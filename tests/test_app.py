import gi

gi.require_version("Gdk", "3.0")
from gi.repository import Gdk

from accessiblewifi.app import make_escape_close_handler


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
