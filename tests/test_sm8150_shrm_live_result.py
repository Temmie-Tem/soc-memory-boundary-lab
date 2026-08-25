from __future__ import annotations

import unittest

from tools import sm8150_shrm_live_result as result


class Sm8150ShrmLiveResultTests(unittest.TestCase):
    def test_parses_exact_watchdog_markers(self) -> None:
        payload = (
            b"Watchdog bark! Now = 40.280410\n"
            b"Watchdog last pet at 29.280131\n"
            b"cpu alive mask from last pet 07\n"
            b"UploadCause[Non Secure Watchdog Bark]\n"
            b"TZBSP_ERR_FATAL_NON_SECURE_WDT\n"
        )
        parsed = result.parse_watchdog(payload)
        self.assertEqual(parsed["bark_minus_last_pet_seconds"], "11.000279")
        self.assertEqual(parsed["cpu_alive_mask"], "0x7")
        self.assertFalse(parsed["a90r_result_present"])

    def test_rejects_missing_or_ambiguous_watchdog_time(self) -> None:
        with self.assertRaisesRegex(ValueError, "match count"):
            result.parse_watchdog(b"")


if __name__ == "__main__":
    unittest.main()
