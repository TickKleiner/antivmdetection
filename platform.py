import os
import sys


def require_admin():
    if os.name == "nt":
        import ctypes

        if not ctypes.windll.shell32.IsUserAnAdmin():
            sys.exit("\n[*] You need to run this script as an administrator\n")
    else:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            sys.exit("\n[*] You need to run this script as root\n")


def check_dependencies(repo_root):
    if os.name == "nt":
        dependencies = [
            "VBoxManage.exe",
            "VolumeId.exe",
            "DevManView.exe",
            "computer.lst",
            "user.lst",
        ]
        missing = [
            dep for dep in dependencies if not os.path.exists(os.path.join(repo_root, dep))
        ]
    else:
        dependencies = [
            "/usr/bin/cd-drive",
            "/usr/bin/acpidump",
            "/usr/bin/glxinfo",
            "/usr/sbin/smartctl",
        ]
        missing = [dep for dep in dependencies if not os.path.exists(dep)]

    if missing:
        for dep in missing:
            print("[WARNING] Dependencies are missing, please verify that you have installed: ", dep)
        sys.exit(1)
