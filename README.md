# Linux CIS & STIG Partitioning Advisor

A small Windows desktop app that suggests a disk layout for a hardened Linux
server. It keeps the directories that CIS Benchmarks and DISA STIGs expect on
their own filesystems (`/tmp`, `/var`, `/var/tmp`, `/var/log`, `/var/log/audit`,
`/home`) and sizes them to fit your disk.

Pick your distribution, LVM or standard partitions, disk size and RAM. The app
gives you sizes, mount options and installer tips, and you can copy the whole
plan to paste into a ticket or build notes.

## Download and run (Windows)

1. Go to the **[Releases](../../releases)** page.
2. Download **`PartitionAdvisor.exe`** from the latest release.
3. Double-click it. No install and no Python needed.

> **Windows SmartScreen warning:** the app isn't code-signed, so Windows may say
> "Windows protected your PC". Click **More info → Run anyway**.

## What it does

- **Fits the disk.** Every volume gets a minimum, and the rest of the disk is
  shared out by weight. `/tmp`, `/var/tmp` and the log volumes are capped so
  extra space goes to `/`, `/var` and `/home`. The plan never adds up to more
  than the disk.
- **Small test/lab disks.** You can enter a disk as small as 13 GB (for example
  a 20 GB test VM). The app still lays out every CIS/STIG partition with the
  correct mount options, shrinking volumes and swap to fit, and shows a red
  **TEST / LAB** warning that 50–60 GB is the practical minimum for a real server.
- **Swap from RAM.** 2× RAM up to 2 GB, equal to RAM up to 8 GB, 4 GB above that.
- **LVM.** `/boot/efi` and `/boot` are plain partitions, everything else is a
  logical volume, and about 10% of the volume group is left free so you can
  grow volumes later with `lvextend`.
- **Distro-aware.** RHEL, Rocky, AlmaLinux and CentOS Stream use XFS and get
  Anaconda/OpenSCAP tips. Ubuntu uses ext4 and gets Ubuntu Security Guide tips.
- **Mount options.** `nodev`, `nosuid` and `noexec` where CIS and STIG call for them.

| Mount point      | Normal minimum | Mount options          |
|------------------|----------------|------------------------|
| /boot/efi        | 1 GB    | umask=0077             |
| /boot            | 1 GB    | nodev,nosuid           |
| swap             | from RAM| –                      |
| /                | 10 GB   | defaults               |
| /home            | 2 GB    | nodev,nosuid           |
| /tmp             | 2 GB    | nodev,nosuid,noexec    |
| /var             | 6 GB    | nodev,nosuid           |
| /var/tmp         | 2 GB    | nodev,nosuid,noexec    |
| /var/log         | 4 GB    | nodev,nosuid,noexec    |
| /var/log/audit   | 4 GB    | nodev,nosuid,noexec    |

This is a planning aid. Always check against the current CIS Benchmark or STIG
for your exact OS version.

## Run from source (any OS)

Needs Python 3.9+ with Tkinter (included with the python.org Windows and macOS installers).

```
python partition_advisor.py
```

Run the tests:

```
python -m unittest discover -s tests -v
```

## How the .exe gets built

You don't build it yourself. GitHub Actions does it on a Windows machine using
[PyInstaller](https://pyinstaller.org) (see `.github/workflows/build-windows.yml`).

- **Every push to `main`:** the workflow runs the tests and builds the .exe. You
  can download it from the run's page under the **Actions** tab (needs a GitHub login).
- **To publish a release anyone can download**, tag a version and push the tag:

  ```
  git tag v1.2.0
  git push origin v1.2.0
  ```

  Or, on GitHub, click **Releases → Draft a new release**, type a new tag such
  as `v1.3.0`, and click **Publish release**.

  A few minutes later `PartitionAdvisor.exe` appears on the Releases page.

**If you forked this repo:** GitHub turns Actions off in forks by default. Open
your fork's **Actions** tab and click the button to enable workflows, then push
a tag as above.
