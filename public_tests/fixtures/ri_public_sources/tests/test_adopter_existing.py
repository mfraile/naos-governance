"""Executed host checks for FR-001/002 and NFR-001/002 in src/adopter_existing.py."""

from contextlib import ExitStack
import unittest
from unittest.mock import patch
from src.adopter_existing import normalize_label


class AdopterExistingTests(unittest.TestCase):
    def test_label_table_and_fixed_points(self):
        examples = {"  Hello World  ": "hello-world", "A-B C9": "a-b-c9", "7": "7"}
        for phrase, expected in examples.items():
            with self.subTest(phrase=phrase):
                first = normalize_label(phrase)
                repeated = [normalize_label(phrase) for _ in range(3)]
                self.assertEqual([first, normalize_label(first), *repeated], [expected] * 5)

    def test_rejection_types_for_invalid_values(self):
        invalid = [(None, TypeError), (23, TypeError), ("", ValueError),
                   ("bad/label", ValueError), ("hello--world", ValueError),
                   ("two  spaces", ValueError), ("-leading", ValueError)]
        for supplied, exception in invalid:
            with self.subTest(value=supplied, expected=exception.__name__):
                with self.assertRaises(exception):
                    normalize_label(supplied)

    def test_local_execution_never_calls_io_spies(self):
        with ExitStack() as stack:
            spies = [stack.enter_context(patch(target))
                     for target in ("builtins.open", "socket.socket")]
            values = tuple(map(normalize_label, ("Safe Label", "ASCII-9")))
            self.assertTupleEqual(values, ("safe-label", "ascii-9"))
            for spy in spies:
                spy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
