"""
Linux CIS & STIG Partitioning Advisor

Suggests a disk layout for a hardened Linux server that keeps the directories
CIS Benchmarks and DISA STIGs expect on their own filesystems, sized to fit the
disk you actually have.

Run it:   python partition_advisor.py
"""

import math

APP_TITLE = "Linux CIS & STIG Partitioning Advisor"
VERSION = "1.3.0"

# --------------------------------------------------------------------------- #
# Options
# --------------------------------------------------------------------------- #

STIG = "DISA STIG"
CIS_L1 = "CIS Level 1 - Server"
CIS_L2 = "CIS Level 2 - Server"
STANDARDS = [STIG, CIS_L1, CIS_L2]

# Hardening tool profile for each family and standard.
#  RHEL family: OpenSCAP / scap-security-guide profile IDs
#  Ubuntu:      Ubuntu Security Guide (usg) profile names
PROFILES = {
    "rhel":   {STIG: "stig", CIS_L1: "cis_server_l1", CIS_L2: "cis"},
    "ubuntu": {STIG: "disa_stig", CIS_L1: "cis_level1_server", CIS_L2: "cis_level2_server"},
}

DISTROS = {
    "Red Hat Enterprise Linux (RHEL 8 / 9 / 10)": {"family": "rhel", "fs": "xfs", "vg": "rhel"},
    "Rocky Linux / AlmaLinux / CentOS Stream":    {"family": "rhel", "fs": "xfs", "vg": "vg_os"},
    "Ubuntu Server (22.04 LTS / 24.04 LTS)":      {"family": "ubuntu", "fs": "ext4", "vg": "ubuntu-vg"},
}

STORAGE_LVM = "LVM (recommended)"
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
    ("/var/log/audit", "var_log_audit",  4.0,  6, 50.0, "nodev,nosuid,noexec", "auditd logs"),
]

# STIG wants audit storage for at least a week of records, so the audit
# volume gets a bigger share of spare space.
WEIGHT_OVERRIDES = {STIG: {"/var/log/audit": 12}}

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
    """
    Modern default: a small fixed swap as a safety cushion, not RAM-sized.
    Servers rarely hibernate, and large swap mostly just delays an out-of-memory
    situation while the system crawls.
    """
    return 2.0 if ram_gb < 16 else 4.0


def requirement(standard, mount):
    """Whether the chosen standard requires this mount point as its own filesystem."""
    if mount in ("/boot/efi", "/boot", "swap", "/"):
        return "-"
    if standard == STIG:
        return "Required"
    if mount == "/tmp":
        return "Required (L1)"
    return "Required (L2)" if standard == CIS_L2 else "Recommended (L2)"


def minimum_disk(ram_gb, swap_gb=None):
    """Smallest disk that gets every volume its normal minimum."""
    swap = swap_size(ram_gb) if swap_gb is None else swap_gb
    return EFI_GB + BOOT_GB + swap + sum(v[2] for v in VOLUMES)


def absolute_minimum_disk(swap_gb=1.0):
    """Smallest disk the app will lay out at all (test/lab use)."""
    return EFI_GB + BOOT_GB + min(swap_gb, 1.0) + sum(LAB_MINIMUMS.values())


def _distribute(extra, standard):
    """Hand out `extra` GB above each volume's minimum by weight, respecting caps."""
    overrides = WEIGHT_OVERRIDES.get(standard, {})
    weight_of = {v[0]: overrides.get(v[0], v[3]) for v in VOLUMES}
    alloc = {v[0]: v[2] for v in VOLUMES}
    active = list(VOLUMES)
    while extra > 1e-9 and active:
        weights = sum(weight_of[v[0]] for v in active)
        handed_out = 0.0
        still_active = []
        for vol in active:
            mount, cap = vol[0], vol[4]
            share = extra * weight_of[mount] / weights
            if cap is not None and alloc[mount] + share >= cap:
                share = cap - alloc[mount]
            else:
                still_active.append(vol)
            alloc[mount] += share
            handed_out += share
        extra -= handed_out
        if len(still_active) == len(active):
            break
        active = still_active
    return alloc


def calculate(distro, storage, disk_gb, ram_gb, standard=STIG, swap_gb=None):
    """
    Build a partition plan.

    swap_gb: None picks the modern default from RAM; 0 means no swap.

    Returns a dict with rows (mount, size, device, fs, options, purpose, req),
    used, free, warnings, notes and the inputs. Raises ValueError with a
    readable message if the inputs don't work.
    """
    if distro not in DISTROS:
        raise ValueError("Pick a Linux distribution.")
    if storage not in STORAGE_TYPES:
        raise ValueError("Pick a storage type.")
    if standard not in STANDARDS:
        raise ValueError("Pick a security standard.")
    if ram_gb <= 0:
        raise ValueError("RAM must be greater than 0 GB.")
    if swap_gb is not None and swap_gb < 0:
        raise ValueError("Swap can't be negative. Use 0 for no swap.")

    info = DISTROS[distro]
    lvm = storage == STORAGE_LVM
    fs = info["fs"]
    vg = info["vg"]
    auto_swap = swap_gb is None
    requested_swap = swap_size(ram_gb) if auto_swap else floor1(swap_gb)
    swap = requested_swap

    floor_disk = absolute_minimum_disk(requested_swap)
    if disk_gb < floor_disk:
        raise ValueError(
            f"A {disk_gb:g} GB disk is too small to hold all the separate "
            f"partitions CIS and STIG require.\n\n"
            f"The smallest test layout needs {floor_disk:g} GB, and "
            f"{RECOMMENDED_DISK_GB}-60 GB or more is recommended."
        )

    warnings = []
    lab = disk_gb < minimum_disk(ram_gb, requested_swap)
    reserve = 0.0

    if lab:
        # Undersized disk: shrink swap if needed and scale every volume
        # between its lab minimum and its normal minimum.
        lab_total = sum(LAB_MINIMUMS.values())
        full_total = sum(v[2] for v in VOLUMES)
        swap = min(requested_swap,
                   max(min(requested_swap, 1.0), floor1(disk_gb * 0.10)),
                   floor1(disk_gb - EFI_GB - BOOT_GB - lab_total))
        swap = max(0.0, swap)
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
        alloc = _distribute(extra, standard)

    if disk_gb < RECOMMENDED_DISK_GB:
        audit_risk = (" With STIG audit settings, a full audit volume can suspend "
                      "or halt the system." if standard == STIG else "")
        warnings.append(
            f"TEST / LAB USE ONLY: {RECOMMENDED_DISK_GB}-60 GB is the practical minimum "
            f"for a {standard} server. This {disk_gb:g} GB plan keeps every required "
            "partition and mount option, but the volumes are small and /var and "
            f"/var/log/audit can fill quickly.{audit_risk}"
        )
    if swap < requested_swap:
        warnings.append(f"Swap was reduced from {requested_swap:g} GB to {swap:g} GB "
                        "to fit the disk.")

    def device(lv_name):
        return f"{vg}/{lv_name}" if lvm else "partition"

    efi_options = "umask=0077,nosuid" if standard == STIG else "umask=0077"
    rows = [
        dict(mount="/boot/efi", size=EFI_GB, device="partition", fs="vfat",
             options=efi_options, purpose="UEFI system partition"),
        dict(mount="/boot", size=BOOT_GB, device="partition", fs=fs,
             options="nodev,nosuid", purpose="Kernels and bootloader"),
    ]
    if swap > 0:
        if swap < requested_swap:
            swap_purpose = "Swap (reduced to fit disk)"
        elif auto_swap:
            swap_purpose = "Swap (safety cushion)"
        else:
            swap_purpose = "Swap (your size)"
        rows.append(dict(mount="swap", size=swap, device=device("swap"), fs="swap",
                         options="-", purpose=swap_purpose))
    for mount, lv_name, _mn, _w, _cap, options, purpose in VOLUMES:
        rows.append(dict(mount=mount, size=floor1(alloc[mount]), device=device(lv_name),
                         fs=fs, options=options, purpose=purpose))
    for r in rows:
        r["req"] = requirement(standard, r["mount"])

    used = round(sum(r["size"] for r in rows), 1)
    free = round(disk_gb - used, 1)

    notes = _notes(info["family"], standard, lvm, vg, free, swap, auto_swap)

    return dict(rows=rows, used=used, free=free, warnings=warnings, notes=notes,
                disk=disk_gb, ram=ram_gb, distro=distro, storage=storage,
                standard=standard, lvm=lvm, lab=disk_gb < RECOMMENDED_DISK_GB)


def _notes(family, standard, lvm, vg, free, swap, auto_swap):
    notes = []
    profile = PROFILES[family][standard]

    # What the standard asks for.
    if standard == STIG:
        notes.append("STIG: every partition above is required. Size /var/log/audit to "
                     "hold at least a week of audit records; auditd must warn at 75% "
                     "full and take action when the volume is full.")
        notes.append("STIG also requires FIPS mode and encryption of data at rest "
                     "(LUKS). Turn on disk encryption in the installer if your site "
                     "requires it for this system.")
    elif standard == CIS_L1:
        notes.append("CIS Level 1: only /tmp must be its own partition. Separate /var, "
                     "/var/tmp, /var/log, /var/log/audit and /home are Level 2 items, "
                     "but they are kept here because adding them later is hard. "
                     "Their mount options apply whenever the partition exists.")
    else:
        notes.append("CIS Level 2: /tmp, /var, /var/tmp, /var/log, /var/log/audit and "
                     "/home must all be separate partitions with the options shown.")

    # How to install and harden on this distro.
    if family == "rhel":
        notes.append("Installer: in Anaconda choose Custom storage configuration and "
                     "create the mount points above.")
        notes.append(f"Hardening: pick the {standard} profile on the installer's Security "
                     f"Policy screen, or run OpenSCAP after install with profile "
                     f"'{profile}' (oscap xccdf eval --remediate --profile {profile} "
                     "with your release's ssg-*-ds.xml).")
    else:
        notes.append("Installer: in the Ubuntu installer choose Custom storage layout "
                     "and create the mount points above.")
        stig_note = (" Check that the DISA STIG profile is published for your Ubuntu "
                     "release." if standard == STIG else "")
        notes.append(f"Hardening: Ubuntu Security Guide (Ubuntu Pro): sudo pro enable usg, "
                     f"sudo apt install usg, then sudo usg fix {profile}.{stig_note}")

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

    if swap == 0:
        notes.append("No swap: fine for many servers with enough RAM, but the system "
                     "has no cushion if memory runs out.")
    elif auto_swap:
        notes.append(f"Swap: {swap:g} GB is a modern default. Neither CIS nor STIG sets "
                     "a swap size. Enter a size in the Swap box to override, or 0 for none.")
    notes.append("Also mount /dev/shm (tmpfs, not on disk) with nodev,nosuid,noexec.")
    return notes


def plan_as_text(plan):
    """Plain-text version of a plan for copying and pasting."""
    lines = [
        f"{APP_TITLE} v{VERSION}",
        f"Standard:     {plan['standard']}",
        f"Distribution: {plan['distro']}",
        f"Storage:      {plan['storage']}",
        f"Disk: {plan['disk']:g} GB   RAM: {plan['ram']:g} GB",
        "",
        f"{'Mount point':<16}{'Size':>9}  {'Device':<22}{'FS':<6}{'Mount options':<22}"
        f"{'Requirement':<18}Purpose",
        "-" * 118,
    ]
    for r in plan["rows"]:
        lines.append(f"{r['mount']:<16}{r['size']:>6.1f} GB  {r['device']:<22}"
                     f"{r['fs']:<6}{r['options']:<22}{r['req']:<18}{r['purpose']}")
    lines.append("-" * 118)
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
    root.geometry("1080x720")
    root.minsize(880, 580)

    state = {"plan": None}

    # ---- Inputs ----------------------------------------------------------- #
    frm_in = ttk.LabelFrame(root, text=" System configuration ", padding=10)
    frm_in.pack(fill="x", padx=10, pady=(10, 5))

    def combo(row, label, values):
        ttk.Label(frm_in, text=label).grid(row=row, column=0, sticky="w", pady=4)
        cmb = ttk.Combobox(frm_in, values=values, state="readonly", width=44)
        cmb.current(0)
        cmb.grid(row=row, column=1, columnspan=5, sticky="w", padx=6, pady=4)
        return cmb

    cmb_standard = combo(0, "Security standard:", STANDARDS)
    cmb_distro = combo(1, "Linux distribution:", list(DISTROS))
    cmb_storage = combo(2, "Storage type:", STORAGE_TYPES)

    def entry(col, label, default, pad_left):
        ttk.Label(frm_in, text=label).grid(row=3, column=col, sticky="w",
                                           padx=(pad_left, 0), pady=4)
        ent = ttk.Entry(frm_in, width=8)
        ent.insert(0, default)
        ent.grid(row=3, column=col + 1, sticky="w", padx=6, pady=4)
        return ent

    ent_disk = entry(0, "Disk size (GB):", "60", 0)
    ent_ram = entry(2, "RAM (GB):", "8", 16)
    ent_swap = entry(4, "Swap (GB):", "", 16)
    ttk.Label(frm_in, text="blank = auto, 0 = none", foreground="#777777").grid(
        row=3, column=6, sticky="w", pady=4)

    frm_btn = ttk.Frame(frm_in)
    frm_btn.grid(row=0, column=7, rowspan=4, sticky="ne", padx=(30, 0))
    frm_in.columnconfigure(7, weight=1)

    # ---- Output ----------------------------------------------------------- #
    frm_out = ttk.LabelFrame(root, text=" Partition plan ", padding=10)
    frm_out.pack(fill="both", expand=True, padx=10, pady=5)

    lbl_summary = ttk.Label(frm_out, text="", font=("Segoe UI", 10, "bold"))
    lbl_summary.pack(anchor="w", pady=(0, 6))

    cols = ("mount", "size", "device", "fs", "options", "req", "purpose")
    headings = ("Mount point", "Size", "Device", "Filesystem", "Mount options",
                "Requirement", "Purpose")
    widths = (115, 75, 160, 75, 150, 115, 230)

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

    txt_notes = tk.Text(frm_out, height=11, wrap="word", relief="flat",
                        background=root.cget("background"), font=("Segoe UI", 9))
    txt_notes.pack(fill="x", pady=(8, 0))
    txt_notes.tag_configure("warn", foreground="#c0392b", font=("Segoe UI", 9, "bold"))
    txt_notes.configure(state="disabled")

    # ---- Actions ---------------------------------------------------------- #
    def read_number(ent, label, allow_blank=False, allow_zero=False):
        text = ent.get().strip()
        if allow_blank and text == "":
            return None
        try:
            value = float(text)
        except ValueError:
            raise ValueError(f"Enter a number for {label}.")
        if value < 0 or (value == 0 and not allow_zero):
            raise ValueError(f"{label} must be greater than 0.")
        return value

    def calculate_clicked(_event=None, quiet=False):
        try:
            disk = read_number(ent_disk, "disk size")
            ram = read_number(ent_ram, "RAM")
            swap = read_number(ent_swap, "swap", allow_blank=True, allow_zero=True)
            plan = calculate(cmb_distro.get(), cmb_storage.get(), disk, ram,
                             cmb_standard.get(), swap)
        except ValueError as e:
            if not quiet:
                messagebox.showwarning("Check your inputs", str(e))
            return
        state["plan"] = plan

        tree.delete(*tree.get_children())
        for r in plan["rows"]:
            tree.insert("", "end", values=(r["mount"], f"{r['size']:.1f} GB", r["device"],
                                           r["fs"], r["options"], r["req"], r["purpose"]))
        if plan["free"] > 0:
            label = "(free in VG)" if plan["lvm"] else "(unallocated)"
            tree.insert("", "end", tags=("free",),
                        values=(label, f"{plan['free']:.1f} GB", "", "", "", "",
                                "Room to grow volumes later" if plan["lvm"] else ""))

        prefix = "TEST / LAB LAYOUT  ·  " if plan["lab"] else ""
        lbl_summary.config(
            text=f"{prefix}{plan['standard']}  ·  Allocated {plan['used']:g} GB of "
                 f"{plan['disk']:g} GB  ·  {plan['storage']}  ·  {plan['distro']}",
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
    for cmb in (cmb_standard, cmb_distro, cmb_storage):
        cmb.bind("<<ComboboxSelected>>", lambda e: calculate_clicked(quiet=True))
    root.bind("<Return>", calculate_clicked)

    calculate_clicked(quiet=True)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
