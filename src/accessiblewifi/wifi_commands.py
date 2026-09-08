"""
Defines and registers keyboard-accessible commands for the Accessible WiFi application.

This module sets up navigation and speech-related controls using Toga's Command system,
allowing users to access key application features via keyboard shortcuts.
"""


from toga import Command, Group, Key, InfoDialog, ConfirmDialog, Icon
import subprocess
import os
import urllib.request

CURRENT_VERSION_CMD = ["dpkg-query", "-W", "-f=${Version}", "accessiblewifi"]
LATEST_VERSION_URL = "https://iris.aphtech.org/wifiupdate/latest.txt"
DEB_URL_TEMPLATE = "https://iris.aphtech.org/wifiupdate/accessiblewifi_{}.deb"
UPDATER_SCRIPT = os.path.expanduser("~/.local/bin/accessiblewifi-self-update.sh")

def define_wifi_commands(app):
    """
    Define and register application-level commands for the Accessible WiFi app.

    This function sets up navigation and settings-related commands with keyboard shortcuts
    and adds them to the application's command registry.

    Args:
        app (toga.App): The instance of the Accessible WiFi application.
    """
            
    help_group = Group.HELP        
    
    def get_installed_version():
        result = subprocess.run(CURRENT_VERSION_CMD, capture_output=True, text=True)
        return result.stdout.strip()

    def get_latest_version():
        req = urllib.request.Request(
            LATEST_VERSION_URL,
            headers={"User-Agent": "AccessibleWifi-UpdateCheck/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode().strip()

    def version_tuple(v):
        return tuple(int(p) for p in v.split("."))

    async def check_for_updates(widget):
        """Check the update server for a newer version and offer to install it."""
        try:
            current = get_installed_version()
            latest = get_latest_version()
        except Exception as e:
            await app.main_window.dialog(
                InfoDialog("Update Check Failed", f"Could not check for updates: {e}")
            )
            return

        if version_tuple(latest) <= version_tuple(current):
            await app.main_window.dialog(
                InfoDialog("No Updates", f"You're up to date (version {current}).")
            )
            return

        should_update = await app.main_window.dialog(
            ConfirmDialog(
                "Update Available",
                f"Version {latest} is available (you have {current}). Update now?  App will restart on its own.",
            )
        )
        if not should_update:
            return

        deb_url = DEB_URL_TEMPLATE.format(latest)
        subprocess.Popen(
            [UPDATER_SCRIPT, str(os.getpid()), deb_url],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        app.exit()
    
    cmd_check_updates = Command(
        check_for_updates,
        text="Check for _Updates",
        tooltip="Check for a newer version of Accessible WiFi",
        group=help_group,
        order=0,
    )
    
    app.commands.add(cmd_check_updates)