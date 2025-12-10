import os
import shutil
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
        executable_deps = ["VBoxManage.exe", "VolumeId.exe", "DevManView.exe"]
        data_files = ["computer.lst", "user.lst"]

        missing = [
            exe
            for exe in executable_deps
            if not (
                os.path.exists(os.path.join(repo_root, exe))
                or shutil.which(exe) is not None
            )
        ]

        missing.extend(
            data for data in data_files if not os.path.exists(os.path.join(repo_root, data))
        )
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
