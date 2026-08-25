from __future__ import annotations

import unittest

from tools import xbl_rawdump_gate_inventory as gate
from tools.sm8150_shrm_dump_export_inventory import ElfImage


class ParamLayoutTests(unittest.TestCase):
    def test_offsets_match_xbl_reads(self) -> None:
        layout = gate._validate_param_layout()
        self.assertEqual(layout["derived_offsets"]["debuglevel"], "0x000")
        self.assertEqual(layout["derived_offsets"]["force_upload_flag"], "0x3f4")
        self.assertEqual(layout["derived_offsets"]["FMM_lock"], "0x3fc")
        self.assertEqual(layout["derived_offsets"]["dump_sink"], "0x400")

    def test_dump_sink_is_fail_closed_to_known_storage_magics(self) -> None:
        self.assertEqual(gate.dump_sink_label(0), "USB_DEFAULT")
        self.assertEqual(gate.dump_sink_label(gate.DUMP_SINK_SDCARD), "SDCARD")
        self.assertEqual(
            gate.dump_sink_label(gate.DUMP_SINK_BOOTDEV), "BOOTDEV_INTERNAL"
        )
        self.assertEqual(gate.dump_sink_label(0xDEADBEEF), "USB_DEFAULT")


class GateTruthTests(unittest.TestCase):
    def evaluate(self, **overrides: bool) -> dict[str, object]:
        values = {
            "fmm_locked": False,
            "debug_low": True,
            "force_upload_enabled": False,
            "three_key_override": False,
            "tz_allows_memory_dump": False,
            "quest_ddr_special_cause": False,
            "dload_cookie_full_bit": True,
            "sec_debug_restart_reason": True,
        }
        values.update(overrides)
        return gate.evaluate_gate(gate.GateInputs(**values))

    def test_current_visible_state_skips_when_tz_denies(self) -> None:
        result = self.evaluate()
        self.assertFalse(result["enters_dload_call_chain"])
        self.assertEqual(result["entry_reason"], "LOW_DEBUG_AND_TZ_DENY_SKIP")

    def test_debug_non_low_alone_is_sufficient(self) -> None:
        result = self.evaluate(debug_low=False)
        self.assertTrue(result["enters_dload_call_chain"])
        self.assertTrue(result["shrm_descriptor_registered"])
        self.assertEqual(result["entry_reason"], "VENDOR_ALLOW")

    def test_mid_without_outer_dump_trigger_does_not_select_rawdump(self) -> None:
        result = self.evaluate(
            debug_low=False,
            saved_dload_cookie_mask_0x30=False,
            dload_cookie_full_bit=False,
            sec_debug_restart_reason=False,
        )
        self.assertTrue(result["rawdump_app_gate_allows"])
        self.assertFalse(result["outer_dload_trigger_present"])
        self.assertFalse(result["enters_dload_call_chain"])

    def test_force_value_five_is_alternate_not_joint_requirement(self) -> None:
        result = self.evaluate(force_upload_enabled=True)
        self.assertTrue(result["enters_dload_call_chain"])

    def test_tz_allow_is_sufficient_only_when_vendor_gate_is_false(self) -> None:
        result = self.evaluate(tz_allows_memory_dump=True)
        self.assertTrue(result["enters_dload_call_chain"])
        self.assertEqual(result["entry_reason"], "TZ_ALLOWS_MEMORY_DUMP")

    def test_fmm_lock_denies_every_other_positive_gate(self) -> None:
        result = self.evaluate(
            fmm_locked=True,
            debug_low=False,
            force_upload_enabled=True,
            three_key_override=True,
            tz_allows_memory_dump=True,
        )
        self.assertFalse(result["enters_dload_call_chain"])
        self.assertEqual(result["entry_reason"], "FMM_LOCK_HARD_RESET")

    def test_quest_ddr_special_cause_takes_separate_path(self) -> None:
        result = self.evaluate(debug_low=False, quest_ddr_special_cause=True)
        self.assertFalse(result["enters_dload_call_chain"])
        self.assertEqual(result["entry_reason"], "QUEST_DDR_SPECIAL_PATH")

    def test_entry_without_either_catalog_qualifier_does_not_register_shrm(self) -> None:
        result = self.evaluate(
            debug_low=False,
            dload_cookie_full_bit=False,
            sec_debug_restart_reason=False,
        )
        self.assertTrue(result["enters_dload_call_chain"])
        self.assertFalse(result["shrm_descriptor_registered"])


class ExactArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = gate.DEFAULT_XBL.read_bytes()

    def test_exact_analysis_recovers_minimal_state(self) -> None:
        result = gate.analyze(self.data)
        self.assertEqual(
            result["classification"],
            "DEBUG_ONLY_SUFFICIENT_WHEN_OUTER_DUMP_TRIGGER_PRESENT",
        )
        self.assertEqual(
            result["minimal_next_state"]["change_debuglevel_to"], "0x44494d44"
        )
        self.assertEqual(result["minimal_next_state"]["keep_force_upload_flag"], "0x00000000")

    def test_wrong_xbl_hash_is_rejected(self) -> None:
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            gate.analyze(bytes(changed))

    def test_instruction_pin_rejects_local_mutation(self) -> None:
        changed = bytearray(self.data)
        image = ElfImage(self.data)
        offset = image.vaddr_to_offset(0x14901B68)
        self.assertIsNotNone(offset)
        changed[int(offset)] ^= 1
        with self.assertRaisesRegex(ValueError, "entry_gate code SHA-256"):
            gate._validate_code(ElfImage(bytes(changed)))

    def test_shared_table_resolves_exact_restart_check(self) -> None:
        imports = gate._validate_import_resolution(ElfImage(self.data))
        self.assertEqual(
            imports["sec_debug_restart_reason_override"]["target"], "0x1482afe8"
        )
        self.assertEqual(
            imports["boot_dload_read_saved_cookie"]["target"], "0x14829a14"
        )


if __name__ == "__main__":
    unittest.main()
