# Antivmdetection

## Overview

Generate host- and guest-side templates for VirtualBox to make simple VM detection heuristics harder. The refactor is in progress: the new CLI wraps the legacy Linux script so behavior is unchanged while collectors and generators are extracted.

## Project status

* Linux live mode is fully refactored (`python -m antivmdetection` invokes the new collectors/generators).
* Snapshot mode works: collect on Linux and replay on any OS (including Windows) without needing VirtualBox tooling installed.

## Compatibility

| Platform | Live mode | Snapshot mode |
| --- | --- | --- |
| Linux | Supported (new collectors/generators) | Supported (`--collect-snapshot`) |
| Windows | Best effort (ACPI via `acpidump.exe` if available; synthetic fallback) | Supported for generation (`--from-snapshot` created on Linux) |

## Running on Linux (live mode)

* System packages: `sudo apt install python3-pip libcdio-utils acpica-tools mesa-utils smartmontools`
* Python deps: `python3 -m pip install -r requirements.txt` (or `python3 -m pip install -e .`)
* Windows binaries in repo root: `wget https://download.sysinternals.com/files/VolumeId.zip https://www.nirsoft.net/utils/devmanview-x64.zip`
* Prepare inputs: `hostname > computer.lst`, `whoami > user.lst` (fill with multiple names for variety).
* Run as root (the legacy script touches VirtualBox and hardware): `sudo python -m antivmdetection --output-dir ./artifacts --seed 1337`
* Outputs: a host shell script, a guest PowerShell script, and a DSDT dump. The CLI still relies on the legacy behavior, so existing workflows continue to function.

## Snapshot workflow

Collect on Linux, replay anywhere:

* Collect: `sudo python -m antivmdetection --collect-snapshot /tmp/snapshot.json --seed 1337`
* Generate from snapshot (Linux or Windows): `python -m antivmdetection --from-snapshot /tmp/snapshot.json --output-dir ./artifacts`

Snapshots include the DSDT blob and base64-encoded helper files (DevManView, Volumeid, computer.lst, user.lst) so generation works cross-platform without extra binaries. A small fixture lives at `tests/fixtures/sample_snapshot.json` for testing the snapshot helpers.

## Windows usage

Live mode now runs on Windows, with ACPI data best-effort:

* Optional: place `acpidump.exe` in the project root to capture real DSDT/FACP/SSDT data. Without it, synthetic ACPI values are generated and logged.
* Run as an elevated user so WMI can read hardware details: `python -m antivmdetection --output-dir C:\path\to\artifacts --seed 1337`.
* Snapshot mode still works the same and remains the most accurate for ACPI data: collect on Linux, then `python -m antivmdetection --from-snapshot snapshot.json --output-dir C:\path\to\artifacts` on Windows.

Apply the guest PowerShell script inside your Windows VM. Host-side changes still have to be applied from the VirtualBox host.

## CLI flags

* `--seed <int>`: deterministic randomness for reproducible runs. Example: `python -m antivmdetection --seed 42 --dry-run`.
* `--output-dir <path>`: where generated artifacts are written. Example: `python -m antivmdetection --output-dir ./artifacts`.
* `--collect-snapshot <path>`: save hardware data (including DSDT and helper files) to JSON (Linux only). Example: `python -m antivmdetection --collect-snapshot /tmp/snapshot.json`.
* `--from-snapshot <path>`: generate outputs from a saved snapshot (works cross-platform). Example: `python -m antivmdetection --from-snapshot /tmp/snapshot.json --output-dir ./artifacts`.
* `--dry-run`: parse arguments and log actions without touching the system. Example: `python -m antivmdetection --dry-run --seed 99`.

## Testing

* Install test deps: `python3 -m pip install pytest`
* Run tests: `pytest`
* Snapshot helpers and RNG determinism are covered by tests using `tests/fixtures/sample_snapshot.json`.

## Legacy VM setup notes

* Create the VM but don't start it, also exit the VirtualBox GUI. The host script needs to be run before installation.
* Verify that "I/O APIC" is enabled (System > Motherboard tab) and "Paravirtualization Interface" is set to "None" (System > Acceleration tab).
* Change CPU count to 2 or more if possible, and set the VM IP (File > Host Network Manager > Configure Adapter Manually > IPv4 address).
* The script expects the storage layout to look like the following: IDE primary master (Disk) and primary slave (CD-ROM), ATA Port 0 (Disk) and Port 1 (CD-ROM).
* Run the generated host script as the user that owns the VMs: `/bin/bash xxxxx.sh my-virtual-machine-name`
* Move the generated PowerShell script into the guest and run it (twice if prompted for reboot). On Windows 10, run as administrator with UAC disabled before the first run.
* If you see "ACPI tables bigger than 64KB (VERR_TOO_MUCH_DATA)", this is a VirtualBox limitation; see <https://github.com/nsmfoo/antivmdetection/issues/37> for context.
* When the script cannot find suitable values, lines are commented with `#` for manual review.

![alt text](vmdetect0.1.5.png "VMDetect 1.5.x")

## Version History

* 0.1.9:
    <br>Python3 compatible 
    <br>First stab at trying to extract the correct disk, has been a source for headache for many. (Issue #35 (and a few others old issues), thanks @oaustin)
    <br>Improved the string handing in the shell script (Issue #35 and #36 and PR #44, thanks @oaustin, @dashjuvi and @corownik)
    <br>Added a link to a online DSDT resource (Issue #37, thanks @MasterCATZ) 
    <br>Updated the README to make installations instructions more clear, thanks @jorants (issue #38)
    <br>Check if the DSDT dump is really created, thanks @nov3mb3r (Issue: #42)
    <br>Added a license notice. thanks @obilodeau (issue #43)
    <br>Code clean-up: removed RAID disk support due to lack of access to server hardware.. and a lot of other small improvements

* 0.1.8:
    <br>Improved support for Windows 10
    <br>Merged markup fix from @bryant1410 (PR #14)
    <br>Solved an issue for people using macOS + VBox/VMWare Fusion to create the templates.
    <br>Creating the template from a virtual machine is not the best way regardless .. (issue #12 and possibly #15)

* 0.1.7:
    <br>Windows 10 is now supported (feedback welcome)
    <br>Several new artifacts "corrected" for W10 installations
    <br>New dependency: mesa-utils
    <br>Merged bug fix from @Fullmetal5 (#10)
    <br>Misc code fix
    <br>Updated the readme

* 0.1.6:
    <br>Added a pop-up after the second run, to make it more clear that you are good to go
    <br>Added a function that spawns a few instances of notepad, this feature will be extended in future versions
    <br>Reworked the RandomDate function, thanks to @Antelox for making me aware of the issue with the old one (#8)
    <br>Acpidump shipped with older versions of Ubuntu, does not support the "-s" switch. This is now handled with an error message. Thanks to @Antelox for this issue (#7)
    <br>Devmanview.exe was not removed after the second run, fixed

* 0.1.5:
    <br>Added support for associating and de-associating (default disabled) file extensions. Reference: <https://www.proofpoint.com/us/threat-insight/post/massive-adgholas-malvertising-campaigns-use-steganography-and-file-whitelisting-to-hide-in-plain-sight>
    <br>Added support for user supplied clipboard buffer. If not present a random string will be generated. Fill the file with Honeytokens of your choice
    <br>Removed XP support
    <br>Converted the batch script sections to Powershell. Moved more logic to the guest script, in short there is less reason to create/re-generate the template often, as more items are randomized on the guest.
    <br>Added a function that randomizes the Desktop background image
    <br>Added a function that creates documents of "all" sorts on the guest
    <br>Added a function that creates documents of "all" sorts on the guest and moves them to the recycle bin
    <br>Randomizing the DigitalProductId in two more locations:
      <br>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Registration\DigitalProductId.
      <br>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DefaultProductKey\DigitalProductId.
    <br>Use paravirtualization Interface: None (verified with VBox 5.1.4)  - Check updated to reflect this change. I assume this change in VBox came about thanks to: TiTi87, thanks!

* 0.1.4:
    <br>Fixed a bug for users of python-dmidecode 3.10.13-3, this one was all me..
    <br>Added a function that randomizes VolumeID (new prerequisite: VolumeID.exe), this information is for example collected by Rovnix
    <br>Added a function that randomizes username and computername/hostname (new prerequisites: list of usernames and computernames)
    <br>First attempt to add information to the clipboard buffer, idea (command) came from a tweet by @shanselman . Will be improved in the next release
    <br>Updated the readme: new dependencies and new features that requires reboot

* 0.1.3:
    <br>Copy and set the CPU brand string.
    <br>Check if an audio device is attached to the guest. Reference: <http://www.joesecurity.org/reports/report-61f847bcb69d0fe86ad7a4ba3f057be5.html>
    <br>Check OS architecture vs DevManView binary.
    <br>Randomizing the ProductId in two more locations:
        <br>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Registration\ProductId.
        <br>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DefaultProductKey\ProductId.
    <br>Purge the Windows product key from the registry (to prevent someone from stealing it...).
    <br>Edit the DigitalProductId (HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId) to match the new ProductId.
* 0.1.2:
    <br>Check if the Legacy paravirtualization interface is being used (Usage of the Legacy interface will mitigate the "cpuid feature" detection).
* 0.1.1:
    <br>Check for CPU count (Less than 2 == alert).
    <br>Check for memory size (Less than 2GB == alert).
    <br>Check if the default IP/IP-range is being used for vboxnet0 (You can ignore the notification if you don't use it).
    <br>Randomizing the ProductId.
    <br>Merged PR #3 from r-sierra (Thanks for helping out!
    <br>Fixed a bug in the AcpiCreatorId (Thanks @Nadacsc for reporting it to me!).
    <br>Fixed a bug in the DmiBIOSReleaseDate parsing.
    <br>Fixed a bug in DmiBIOSReleaseDate, to handle both the "default" misspelled variant and the correctly spelled one (Thanks @WanpengQian for reporting it to me!).
    <br>The DevManView inclusion did not work as expected, It should be fixed in this release.
    <br>Supports SATA controller as well (Previously only IDE settings was modified)
    <br>Updated the readme
* 0.1.0:
    <br>Resolved the WMI detection make famous by the HT. Added <br>DevManView.exe (your choice of architecture) to the prerequisites.
* < 0.1.0 No version history kept prior to this, need to start somewhere I guess.

/Mikael

Feedback is always welcome! =)
