"""
Linux CIS & STIG Partitioning Advisor

Suggests a disk layout for a hardened Linux server that keeps the directories
CIS Benchmarks and DISA STIGs expect on their own filesystems, sized to fit the
disk you actually have.

Run it:   python partition_advisor.py
"""

import math

APP_TITLE = "Linux CIS & STIG Partitioning Advisor"
VERSION = "1.2.0"

# --------------------------------------------------------------------------- #
# Options
# --------------------------------------------------------------------------- #

DISTROS = {
    "Red Hat Enterprise Linux (RHEL 8 / 9 / 10)": {
        "family": "rhel",
        "fs": "xfs",
        "vg": "rhel",
    },
    "Rocky Linux / AlmaLinux / CentOS Stream": {
        "family": "rhel",
        "fs": "xfs",
        "vg": "vg_os",
    },
    "Ubuntu Server (22.04 LTS / 24.04 LTS)": {
        "family": "ubuntu",
        "fs": "ext4",
        "vg": "ubuntu-vg",
    },
}

STORAGE_LVM = "LVM (recommended for STIG)"
STORAGE_STD = "Standard partitions"
STORAGE_TYPES = [STORAGE_LVM, STORAGE_STD]

# Share of the volume group left unallocated with LVM, so any volume can be
# grown later without repartitioning.
LVM_FREE_SHARE = 0.10

EFI_GB = 1.0
BOOT_GB = 1.0

# Volumes that share the remaining space.
# (mount point, LV name, minimum GB, weight, cap GB or None, mount options, purpose)
VOLUMES = [
    ("/",              "root",          10.0, 30, None, "defaults",            "Root filesystem"),
    ("/home",          "home",           2.0, 20, None, "nodev,nosuid",        "User home directories"),
    ("/tmp",           "tmp",            2.0,  3, 10.0, "nodev,nosuid,noexec", "Temporary files"),
    ("/var",           "var",            6.0, 30, None, "nodev,nosuid",        "Packages, databases, containers"),
    ("/var/tmp",       "var_tmp",        2.0,  3, 10.0, "nodev,nosuid,noexec", "Temporary files kept across reboots"),
    ("/var/log",       "var_log",        4.0,  8, 50.0, "nodev,nosuid,noexec", "System logs"),
    ("/var/log/audit", "var_log_audit",  4.0,  6, 50.0, "nodev,nosuid,noexec", "auditd logs (STIG)"),
]

# Smallest size each volume may shrink to on undersized test/lab disks.
LAB_MINIMUMS = {
    "/": 4.0,
    "/home": 0.5,
    "/tmp": 0.5,
    "/var": 2.0,
    "/var/tmp": 0.5,
    "/var/log": 1.0,
    "/var/log/audit": 1.0,
}

# Below this size the plan is still built, but flagged as test/lab only.
RECOMMENDED_DISK_GB = 50


# --------------------------------------------------------------------------- #
# Sizing logic (no GUI code here, so it can be tested on its own)
# --------------------------------------------------------------------------- #

def floor1(x):
    """Round down to one decimal so the plan never adds up to more than the disk."""
    return math.floor(x * 10 + 1e-9) / 10


def swap_size(ram_gb):
    """Swap sized from RAM, following Red Hat's guidance for systems without hibernation."""
    if ram_gb <= 2:
        size = ram_gb * 2
    elif ram_gb <= 8:
        size = ram_gb
    else:
        size = 4.0
    return max(1.0, floor1(size))


def minimum_disk(ram_gb):
    """Smallest disk that gets every volume its normal minimum."""
    return EFI_GB + BOOT_GB + swap_size(ram_gb) + sum(v[2] for v in VOLUMES)


def absolute_minimum_disk():
    """Smallest disk the app will lay out at all (test/lab use, 1 GB swap)."""
    return EFI_GB + BOOT_GB + 1.0 + sum(LAB_MINIMUMS.values())


def _distribute(extra):
    """Hand out `extra` GB above each volume's minimum by weight, respecting caps."""
    alloc = {v[0]: v[2] for v in VOLUMES}
    active = list(VOLUMES)
    while extra > 1e-9 and active:
        weights = sum(v[3] for v in active)
        handed_out = 0.0
        still_active = []
        for mount, _lv, _mn, weight, cap, _opt, _purpose in active:
            share = extra * weight / weights
            if cap is not None and alloc[mount] + share >= cap:
                share = cap - alloc[mount]
            else:
                still_active.append((mount, _lv, _mn, weight, cap, _opt, _purpose))
            alloc[mount] += share
            handed_out += share
        extra -= handed_out
        if len(still_active) == len(active):
            break
        active = still_active
    return alloc


def calculate(distro, storage, disk_gb, ram_gb):
    """
    Build a partition plan. Returns a dict with:
      rows      list of dicts (mount, size, kind, device, fs, options, purpose)
      used      GB allocated
      free      GB left unallocated
      warnings  list of strings
      notes     list of strings
    Raises ValueError with a readable message if the inputs don't work.
    """
    if distro not in DISTROS:
        raise ValueError("Pick a Linux distribution.")
    if storage not in STORAGE_TYPES:
        raise ValueError("Pick a storage type.")
    if ram_gb <= 0:
        raise ValueError("RAM must be greater than 0 GB.")

    info = DISTROS[distro]
    lvm = storage == STORAGE_LVM
    fs = info["fs"]
    vg = info["vg"]
    swap = swap_size(ram_gb)

    floor_disk = absolute_minimum_disk()
    if disk_gb < floor_disk:
        raise ValueError(
            f"A {disk_gb:g} GB disk is too small to hold all the separate "
            f"partitions CIS and STIG require.\n\n"
            f"The smallest test layout needs {floor_disk:g} GB, and "
            f"{RECOMMENDED_DISK_GB}-60 GB or more is recommended."
        )

    warnings = []
    lab = disk_gb < minimum_disk(ram_gb)
    reserve = 0.0

    if lab:
        # Undersized disk: shrink swap and scale every volume between its
        # lab minimum and its normal minimum.
        lab_total = sum(LAB_MINIMUMS.values())
        full_total = sum(v[2] for v in VOLUMES)
        swap = max(1.0, min(swap, floor1(disk_gb * 0.10),
                            floor1(disk_gb - EFI_GB - BOOT_GB - lab_total)))
        available = disk_gb - EFI_GB - BOOT_GB - swap
        t = max(0.0, min(1.0, (available - lab_total) / (full_total - lab_total)))
        alloc = {v[0]: LAB_MINIMUMS[v[0]] + t * (v[2] - LAB_MINIMUMS[v[0]])
                 for v in VOLUMES}
    else:
        pool = disk_gb - EFI_GB - BOOT_GB - swap      # space for the shared volumes
        extra = pool - sum(v[2] for v in VOLUMES)     # space above the minimums
        if lvm:
            target = (disk_gb - EFI_GB - BOOT_GB) * LVM_FREE_SHARE
            reserve = min(target, extra)
            extra -= reserve
            if reserve < target - 0.05 and disk_gb >= RECOMMENDED_DISK_GB:
                warnings.append(
                    f"Only {floor1(reserve):g} GB is left free in the volume group "
                    f"(about {floor1(target):g} GB is recommended). A larger disk "
                    "gives you room to grow volumes later."
                )
        alloc = _distribute(extra)

    if disk_gb < RECOMMENDED_DISK_GB:
        warnings.append(
            f"TEST / LAB USE ONLY: {RECOMMENDED_DISK_GB}-60 GB is the practical minimum "
            f"for a CIS or STIG server. This {disk_gb:g} GB plan keeps every required "
            "partition and mount option, but the volumes are small. /var and "
            "/var/log/audit can fill quickly, and with STIG audit settings a full "
            "audit volume can suspend or halt the system."
        )
    if lab and swap < swap_size(ram_gb):
        warnings.append(
            f"Swap was reduced to {swap:g} GB to fit the disk "
            f"({swap_size(ram_gb):g} GB is normal for {ram_gb:g} GB of RAM)."
        )

    def device(lv_name):
        return f"{vg}/{lv_name}" if lvm else "partition"

    def kind():
        return "Logical volume" if lvm else "Partition"

    rows = [
        dict(mount="/boot/efi", size=EFI_GB, kind="Partition", device="partition",
             fs="vfat", options="umask=0077", purpose="UEFI system partition"),
        dict(mount="/boot", size=BOOT_GB, kind="Partition", device="partition",
             fs=fs, options="nodev,nosuid", purpose="Kernels and bootloader"),
        dict(mount="swap", size=swap, kind=kind(), device=device("swap"),
             fs="swap", options="-", purpose=(f"Swap (reduced to fit disk)" if swap < swap_size(ram_gb)
                      else f"Swap (sized for {ram_gb:g} GB RAM)")),
    ]
    for mount, lv_name, _mn, _w, _cap, options, purpose in VOLUMES:
        rows.append(dict(mount=mount, size=floor1(alloc[mount]), kind=kind(),
                         device=device(lv_name), fs=fs, options=options,
                         purpose=purpose))

    used = round(sum(r["size"] for r in rows), 1)
    free = round(disk_gb - used, 1)

    notes = []
    if info["family"] == "rhel":
        notes.append("Installer: in Anaconda choose Custom storage configuration and "
                     "create the mount points above.")
        notes.append("Hardening: on the Security Policy screen pick the DISA STIG or "
                     "CIS profile, or run OpenSCAP (scap-security-guide) after install.")
    else:
        notes.append("Installer: in the Ubuntu installer choose Custom storage layout "
                     "and create the mount points above.")
        notes.append("Hardening: the Ubuntu Security Guide (usg, part of Ubuntu Pro) "
                     "can audit and apply the CIS and DISA STIG profiles.")
    if lvm:
        lvm_note = (f"LVM: /boot/efi and /boot are plain partitions; everything else "
                    f"is a logical volume in volume group '{vg}'.")
        if free >= 0.5:
            lvm_note += (f" Leave the {free:g} GB of free space unallocated so volumes "
                         "can be grown with lvextend later.")
        notes.append(lvm_note)
    else:
        notes.append("Standard partitions: use a GPT partition table. Resizing later "
                     "is hard, so consider LVM if you can.")
    notes.append("Also mount /dev/shm (tmpfs, not on disk) with nodev,nosuid,noexec.")

    return dict(rows=rows, used=used, free=free, warnings=warnings, notes=notes,
                disk=disk_gb, ram=ram_gb, distro=distro, storage=storage, lvm=lvm,
                lab=disk_gb < RECOMMENDED_DISK_GB)


def plan_as_text(plan):
    """Plain-text version of a plan for copying and pasting."""
    lines = [
        f"{APP_TITLE} v{VERSION}",
        f"Distribution: {plan['distro']}",
        f"Storage:      {plan['storage']}",
        f"Disk: {plan['disk']:g} GB   RAM: {plan['ram']:g} GB",
        "",
        f"{'Mount point':<16}{'Size':>9}  {'Device':<24}{'FS':<6}{'Mount options':<22}Purpose",
        "-" * 100,
    ]
    for r in plan["rows"]:
        lines.append(f"{r['mount']:<16}{r['size']:>6.1f} GB  {r['device']:<24}"
                     f"{r['fs']:<6}{r['options']:<22}{r['purpose']}")
    lines.append("-" * 100)
    free_label = "free in volume group" if plan["lvm"] else "unallocated"
    lines.append(f"Allocated {plan['used']:g} GB, {plan['free']:g} GB {free_label}.")
    lines.append("")
    for w in plan["warnings"]:
        lines.append(f"WARNING: {w}")
    for n in plan["notes"]:
        lines.append(f"- {n}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# GUI
# --------------------------------------------------------------------------- #

def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox

    # Sharp text on high-DPI Windows screens.
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    root = tk.Tk()
    root.title(f"{APP_TITLE} v{VERSION}")
    root.geometry("980x640")
    root.minsize(820, 520)

    state = {"plan": None}

    # ---- Inputs ----------------------------------------------------------- #
    frm_in = ttk.LabelFrame(root, text=" System configuration ", padding=10)
    frm_in.pack(fill="x", padx=10, pady=(10, 5))

    ttk.Label(frm_in, text="Linux distribution:").grid(row=0, column=0, sticky="w", pady=4)
    cmb_distro = ttk.Combobox(frm_in, values=list(DISTROS), state="readonly", width=44)
    cmb_distro.current(0)
    cmb_distro.grid(row=0, column=1, columnspan=3, sticky="w", padx=6, pady=4)

    ttk.Label(frm_in, text="Storage type:").grid(row=1, column=0, sticky="w", pady=4)
    cmb_storage = ttk.Combobox(frm_in, values=STORAGE_TYPES, state="readonly", width=44)
    cmb_storage.current(0)
    cmb_storage.grid(row=1, column=1, columnspan=3, sticky="w", padx=6, pady=4)

    ttk.Label(frm_in, text="Disk size (GB):").grid(row=2, column=0, sticky="w", pady=4)
    ent_disk = ttk.Entry(frm_in, width=10)
    ent_disk.insert(0, "60")
    ent_disk.grid(row=2, column=1, sticky="w", padx=6, pady=4)

    ttk.Label(frm_in, text="RAM (GB):").grid(row=2, column=2, sticky="e", padx=(16, 0), pady=4)
    ent_ram = ttk.Entry(frm_in, width=10)
    ent_ram.insert(0, "8")
    ent_ram.grid(row=2, column=3, sticky="w", padx=6, pady=4)

    frm_btn = ttk.Frame(frm_in)
    frm_btn.grid(row=0, column=4, rowspan=3, sticky="ne", padx=(30, 0))
    frm_in.columnconfigure(4, weight=1)

    # ---- Output ----------------------------------------------------------- #
    frm_out = ttk.LabelFrame(root, text=" Partition plan ", padding=10)
    frm_out.pack(fill="both", expand=True, padx=10, pady=5)

    lbl_summary = ttk.Label(frm_out, text="", font=("Segoe UI", 10, "bold"))
    lbl_summary.pack(anchor="w", pady=(0, 6))

    cols = ("mount", "size", "device", "fs", "options", "purpose")
    headings = ("Mount point", "Size", "Device", "Filesystem", "Mount options", "Purpose")
    widths = (120, 80, 170, 80, 160, 260)

    frm_tree = ttk.Frame(frm_out)
    frm_tree.pack(fill="both", expand=True)
    tree = ttk.Treeview(frm_tree, columns=cols, show="headings", height=11)
    for c, h, w in zip(cols, headings, widths):
        tree.heading(c, text=h)
        tree.column(c, width=w, anchor="e" if c == "size" else "w",
                    stretch=(c == "purpose"))
    sb = ttk.Scrollbar(frm_tree, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    tree.tag_configure("free", foreground="#777777")

    txt_notes = tk.Text(frm_out, height=9, wrap="word", relief="flat",
                        background=root.cget("background"), font=("Segoe UI", 9))
    txt_notes.pack(fill="x", pady=(8, 0))
    txt_notes.tag_configure("warn", foreground="#c0392b", font=("Segoe UI", 9, "bold"))
    txt_notes.configure(state="disabled")

    # ---- Actions ---------------------------------------------------------- #
    def read_number(entry, label):
        try:
            value = float(entry.get().strip())
        except ValueError:
            raise ValueError(f"Enter a number for {label} (for example 60).")
        if value <= 0:
            raise ValueError(f"{label} must be greater than 0.")
        return value

    def calculate_clicked(_event=None, quiet=False):
        try:
            disk = read_number(ent_disk, "disk size")
            ram = read_number(ent_ram, "RAM")
            plan = calculate(cmb_distro.get(), cmb_storage.get(), disk, ram)
        except ValueError as e:
            if not quiet:
                messagebox.showwarning("Check your inputs", str(e))
            return
        state["plan"] = plan

        tree.delete(*tree.get_children())
        for r in plan["rows"]:
            tree.insert("", "end", values=(r["mount"], f"{r['size']:.1f} GB", r["device"],
                                           r["fs"], r["options"], r["purpose"]))
        if plan["free"] > 0:
            label = "(free in VG)" if plan["lvm"] else "(unallocated)"
            tree.insert("", "end", tags=("free",),
                        values=(label, f"{plan['free']:.1f} GB", "", "", "",
                                "Room to grow volumes later" if plan["lvm"] else ""))

        prefix = "TEST / LAB LAYOUT  ·  " if plan["lab"] else ""
        lbl_summary.config(text=f"{prefix}Allocated {plan['used']:g} GB of {plan['disk']:g} GB  ·  "
                                f"{cmb_storage.get()}  ·  {cmb_distro.get()}",
                           foreground="#c0392b" if plan["lab"] else "")

        txt_notes.configure(state="normal")
        txt_notes.delete("1.0", "end")
        for w in plan["warnings"]:
            txt_notes.insert("end", f"⚠ {w}\n", "warn")
        for n in plan["notes"]:
            txt_notes.insert("end", f"• {n}\n")
        txt_notes.configure(state="disabled")

    def copy_clicked():
        if not state["plan"]:
            calculate_clicked()
        if state["plan"]:
            root.clipboard_clear()
            root.clipboard_append(plan_as_text(state["plan"]))
            btn_copy.config(text="Copied ✓")
            root.after(1500, lambda: btn_copy.config(text="Copy plan"))

    ttk.Button(frm_btn, text="Calculate", command=calculate_clicked, width=14).pack(pady=(0, 6))
    btn_copy = ttk.Button(frm_btn, text="Copy plan", command=copy_clicked, width=14)
    btn_copy.pack()

    # Recalculate whenever a choice changes, and on Enter.
    cmb_distro.bind("<<ComboboxSelected>>", lambda e: calculate_clicked(quiet=True))
    cmb_storage.bind("<<ComboboxSelected>>", lambda e: calculate_clicked(quiet=True))
    root.bind("<Return>", calculate_clicked)

    calculate_clicked(quiet=True)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
