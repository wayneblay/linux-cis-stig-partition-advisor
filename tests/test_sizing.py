import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import partition_advisor as pa  # noqa: E402

RHEL = "Red Hat Enterprise Linux (RHEL 8 / 9 / 10)"
UBUNTU = "Ubuntu Server (22.04 LTS / 24.04 LTS)"


class SizingTests(unittest.TestCase):
    def test_never_exceeds_disk(self):
        for distro in pa.DISTROS:
            for storage in pa.STORAGE_TYPES:
                for standard in pa.STANDARDS:
                    for ram in (1, 4, 8, 16, 64):
                        for swap in (None, 0, 8):
                            start = pa.absolute_minimum_disk(8 if swap is None else swap)
                            disks = [start, start + 0.3] + list(range(int(start) + 1, 120, 3))
                            for disk in disks + [250, 1000, 4000]:
                                plan = pa.calculate(distro, storage, disk, ram, standard, swap)
                                ctx = (distro, storage, standard, disk, ram, swap)
                                self.assertLessEqual(plan["used"], disk, ctx)
                                self.assertGreaterEqual(plan["free"], 0, ctx)

    def test_minimums_respected(self):
        plan = pa.calculate(RHEL, pa.STORAGE_STD, pa.minimum_disk(8), 8)
        sizes = {r["mount"]: r["size"] for r in plan["rows"]}
        for mount, _lv, minimum, *_ in pa.VOLUMES:
            self.assertGreaterEqual(sizes[mount], minimum)

    def test_too_small_disk_rejected(self):
        with self.assertRaises(ValueError):
            pa.calculate(RHEL, pa.STORAGE_LVM, 10, 8)

    def test_20gb_lab_layout(self):
        for storage in pa.STORAGE_TYPES:
            plan = pa.calculate(RHEL, storage, 20, 8, pa.STIG)
            mounts = {r["mount"] for r in plan["rows"]}
            for required in ("/tmp", "/var", "/var/tmp", "/var/log", "/var/log/audit", "/home"):
                self.assertIn(required, mounts)
            self.assertTrue(plan["lab"])
            self.assertTrue(any("TEST / LAB" in w for w in plan["warnings"]))
            self.assertLessEqual(plan["used"], 20)
            sizes = {r["mount"]: r["size"] for r in plan["rows"]}
            for mount, minimum in pa.LAB_MINIMUMS.items():
                self.assertGreaterEqual(sizes[mount], minimum)

    def test_warning_below_50(self):
        self.assertTrue(pa.calculate(RHEL, pa.STORAGE_LVM, 45, 8)["lab"])
        plan = pa.calculate(RHEL, pa.STORAGE_LVM, 60, 8)
        self.assertFalse(plan["lab"])
        self.assertFalse(any("TEST / LAB" in w for w in plan["warnings"]))

    def test_caps_respected(self):
        plan = pa.calculate(RHEL, pa.STORAGE_STD, 2000, 16)
        sizes = {r["mount"]: r["size"] for r in plan["rows"]}
        self.assertLessEqual(sizes["/tmp"], 10)
        self.assertLessEqual(sizes["/var/log/audit"], 50)

    def test_distro_changes_filesystem(self):
        rhel = pa.calculate(RHEL, pa.STORAGE_LVM, 100, 8)
        ubu = pa.calculate(UBUNTU, pa.STORAGE_LVM, 100, 8)
        self.assertEqual({r["fs"] for r in rhel["rows"] if r["mount"] == "/"}, {"xfs"})
        self.assertEqual({r["fs"] for r in ubu["rows"] if r["mount"] == "/"}, {"ext4"})

    def test_lvm_leaves_free_space(self):
        lvm = pa.calculate(RHEL, pa.STORAGE_LVM, 100, 8)
        std = pa.calculate(RHEL, pa.STORAGE_STD, 100, 8)
        self.assertGreater(lvm["free"], 8)
        self.assertLess(std["free"], 1)
        self.assertTrue(any(r["device"].startswith("rhel/") for r in lvm["rows"]))

    def test_swap_is_small(self):
        self.assertEqual(pa.swap_size(2), 2)
        self.assertEqual(pa.swap_size(8), 2)
        self.assertEqual(pa.swap_size(32), 4)
        self.assertEqual(pa.swap_size(512), 4)

    def test_swap_override_and_none(self):
        plan = pa.calculate(RHEL, pa.STORAGE_LVM, 100, 8, pa.STIG, 0)
        self.assertNotIn("swap", {r["mount"] for r in plan["rows"]})
        plan = pa.calculate(RHEL, pa.STORAGE_LVM, 100, 8, pa.STIG, 6)
        self.assertEqual({r["mount"]: r["size"] for r in plan["rows"]}["swap"], 6)

    def test_standard_requirements(self):
        stig = pa.calculate(RHEL, pa.STORAGE_LVM, 100, 8, pa.STIG)
        l1 = pa.calculate(RHEL, pa.STORAGE_LVM, 100, 8, pa.CIS_L1)
        l2 = pa.calculate(RHEL, pa.STORAGE_LVM, 100, 8, pa.CIS_L2)
        req = lambda p, m: {r["mount"]: r["req"] for r in p["rows"]}[m]
        self.assertEqual(req(stig, "/var"), "Required")
        self.assertEqual(req(l1, "/tmp"), "Required (L1)")
        self.assertEqual(req(l1, "/var"), "Recommended (L2)")
        self.assertEqual(req(l2, "/var/log/audit"), "Required (L2)")

    def test_stig_gives_audit_more_room(self):
        size = lambda std: {r["mount"]: r["size"] for r in
                            pa.calculate(RHEL, pa.STORAGE_LVM, 200, 8, std)["rows"]}["/var/log/audit"]
        self.assertGreater(size(pa.STIG), size(pa.CIS_L1))

    def test_profiles_in_notes(self):
        ubu = pa.calculate(UBUNTU, pa.STORAGE_LVM, 100, 8, pa.CIS_L1)
        self.assertTrue(any("cis_level1_server" in n for n in ubu["notes"]))
        rhel = pa.calculate(RHEL, pa.STORAGE_LVM, 100, 8, pa.CIS_L2)
        self.assertTrue(any("profile 'cis'" in n for n in rhel["notes"]))

    def test_text_export(self):
        text = pa.plan_as_text(pa.calculate(UBUNTU, pa.STORAGE_LVM, 80, 4))
        self.assertIn("/var/log/audit", text)


if __name__ == "__main__":
    unittest.main()
