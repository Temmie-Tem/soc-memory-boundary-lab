from __future__ import annotations

import unittest

from tools import gf2


class GF2Tests(unittest.TestCase):
    def test_identity_and_composition(self) -> None:
        rows = gf2.identity(5)
        for value in range(1 << 5):
            self.assertEqual(gf2.apply(rows, value, 5), value)
        self.assertEqual(gf2.compose(rows, rows, 5), rows)

    def test_xor_transform(self) -> None:
        rows = gf2.rows_from_bit_sets(({0, 2}, {1}, {2}), 3)
        self.assertEqual(gf2.apply(rows, 0b101, 3), 0b100)
        self.assertEqual(gf2.rank(rows, 3), 3)

    def test_unique_solution(self) -> None:
        rows = gf2.rows_from_bit_sets(({0, 1}, {1, 2}, {2}), 3)
        original = 0b101
        solution = gf2.solve(rows, gf2.apply(rows, original, 3), 3)
        self.assertIsNotNone(solution)
        assert solution is not None
        self.assertEqual(solution.particular, original)
        self.assertEqual(solution.nullspace, ())

    def test_rank_deficient_solution_and_nullspace(self) -> None:
        rows = (0b011, 0b011)
        solution = gf2.solve(rows, 0b11, 3)
        self.assertIsNotNone(solution)
        assert solution is not None
        self.assertEqual(len(solution.nullspace), 2)
        for candidate in range(8):
            self.assertEqual(
                solution.contains(candidate),
                gf2.apply(rows, candidate, 3) == 0b11,
            )

    def test_inconsistent_target(self) -> None:
        self.assertIsNone(gf2.solve((0b01, 0b01), 0b01, 2))

    def test_validation(self) -> None:
        with self.assertRaises(ValueError):
            gf2.apply((0b100,), 0, 2)
        with self.assertRaises(ValueError):
            gf2.solve((1,), 2, 2)


if __name__ == "__main__":
    unittest.main()
