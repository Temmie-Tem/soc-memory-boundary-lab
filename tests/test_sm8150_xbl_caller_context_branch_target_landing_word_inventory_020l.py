from __future__ import annotations
import copy, json, tempfile, unittest
from pathlib import Path
from unittest import mock
from tools import sm8150_xbl_caller_context_branch_target_landing_word_inventory_020l as inv

class LandingInventoryTests(unittest.TestCase):
    def test_exact_seven_targets_and_expected_families(self):
        m = inv.build_manifest(inv.k.FIRMWARE_DIR)
        self.assertEqual(m["classification"], "CLASS C (TRANSFORM ONLY)")
        self.assertEqual(m["eligibility"], "NOT_ELIGIBLE")
        rows = m["census"]["targets"]
        self.assertEqual(len(rows), 7)
        self.assertEqual([r["target_va"] for r in rows], sorted(inv.EXPECTED_TARGETS, key=lambda x:int(x,16)))
        self.assertEqual([r["family"] for r in rows], [inv.EXPECTED_FAMILIES[inv.EXPECTED_TARGETS.index(r["target_va"])] for r in rows])
        self.assertNotIn('"word":', json.dumps(m)); self.assertNotIn("evidence/private", json.dumps(m))

    def test_source_manifest_and_firmware_hash_mutations_fail_closed(self):
        with mock.patch.object(inv, "XBL_SHA256", "0" * 64):
            with self.assertRaises(inv.TraceError): inv.build_manifest(inv.k.FIRMWARE_DIR)
        with mock.patch.object(inv, "K_SHA256", "0" * 64):
            with self.assertRaises(inv.TraceError): inv.build_manifest(inv.k.FIRMWARE_DIR)
        with mock.patch.object(inv, "K_TOOL_SHA256", "0" * 64):
            with self.assertRaises(inv.TraceError): inv.build_manifest(inv.k.FIRMWARE_DIR)
        with mock.patch.object(inv, "DECODER_020D_SHA256", "0" * 64):
            with self.assertRaises(inv.TraceError): inv.build_manifest(inv.k.FIRMWARE_DIR)
        with mock.patch.object(inv, "DECODER_020F_SHA256", "0" * 64):
            with self.assertRaises(inv.TraceError): inv.build_manifest(inv.k.FIRMWARE_DIR)

    def test_target_set_mutation_fails_closed(self):
        original = inv._dependency
        def altered():
            d = copy.deepcopy(original()); d["census"]["stops"][0]["operands"]["target_va"] = "0x1000"; return d
        with mock.patch.object(inv, "_dependency", altered):
            with self.assertRaises(inv.TraceError): inv.build_manifest(inv.k.FIRMWARE_DIR)

    def test_strict_decoder_rejects_unknown_and_nonexec(self):
        image = inv.Image(inv._read(inv.k.FIRMWARE_DIR / inv.XBL_NAME, inv.XBL_SIZE, inv.XBL_SHA256, "XBL"))
        with self.assertRaises(inv.TraceError): inv._decode(0, 0x9fc264d0, image)
        with self.assertRaises(inv.TraceError): inv._decode(image.word(0x9fc264d0), 0x1000, image)

    def test_unaligned_landing_va_is_rejected_before_decode(self):
        image = inv.Image(inv._read(inv.k.FIRMWARE_DIR / inv.XBL_NAME, inv.XBL_SIZE, inv.XBL_SHA256, "XBL"))
        with self.assertRaises(inv.TraceError):
            inv._decode(image.word(0x9fc264d0), 0x9fc264d1, image)

    def test_unaligned_landing_va_is_rejected_before_word_read(self):
        image = mock.Mock()
        with self.assertRaisesRegex(inv.TraceError, "not instruction-aligned"):
            inv._read_landing_word(image, 0x9fc264d1)
        image.word.assert_not_called()

    def test_no_clobber_publication(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.json"; payload = inv.encode_manifest(inv.build_manifest(inv.k.FIRMWARE_DIR))
            inv.write_no_clobber(p, payload)
            with self.assertRaises(inv.TraceError): inv.write_no_clobber(p, payload)

if __name__ == "__main__": unittest.main()
