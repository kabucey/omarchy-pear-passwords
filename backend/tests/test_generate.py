"""The generated-password shape. These pin the promises the UI makes about it."""

import random
import re
import unittest

from icp.vault import generate as g


class ShapeTests(unittest.TestCase):
    def setUp(self):
        self.samples = [g.generate() for _ in range(400)]

    def test_apple_shape(self):
        for p in self.samples:
            self.assertRegex(p, r"^[A-Za-z0-9]{6}-[A-Za-z0-9]{6}-[A-Za-z0-9]{6}$")

    def test_exactly_one_digit_and_one_uppercase(self):
        # Sites that demand "a number and a capital" must be satisfied without the user
        # editing the password afterwards, which is how generated passwords get weakened.
        for p in self.samples:
            body = p.replace("-", "")
            self.assertEqual(sum(c.isdigit() for c in body), 1, p)
            self.assertEqual(sum(c.isupper() for c in body), 1, p)

    def test_never_uses_easily_misread_characters(self):
        for p in self.samples:
            self.assertNotIn("l", p.lower())
            self.assertNotIn("o", p.lower())
            self.assertNotIn("0", p)
            self.assertNotIn("1", p)

    def test_letters_alternate_consonant_vowel(self):
        # This is what makes each group pronounceable, and therefore rehearsable.
        for p in self.samples:
            for i, c in enumerate(p.replace("-", "")):
                if not c.isalpha() or c.isupper():
                    continue          # the injected digit and the shifted letter break the run
                expected = g.CONSONANTS if i % 2 == 0 else g.VOWELS
                self.assertIn(c, expected, f"{c!r} at {i} in {p}")

    def test_does_not_repeat(self):
        self.assertEqual(len(set(self.samples)), len(self.samples))

    def test_entropy_is_what_we_claim(self):
        self.assertGreater(g.entropy_bits(), 64)

    def test_deterministic_under_a_seeded_rng(self):
        a = g.generate(random.Random(7))
        b = g.generate(random.Random(7))
        self.assertEqual(a, b)


class StyleTests(unittest.TestCase):
    def test_apple_style_is_the_apple_shape(self):
        self.assertRegex(g.generate_style("apple"), r"^[A-Za-z0-9]{6}-[A-Za-z0-9]{6}-[A-Za-z0-9]{6}$")
        self.assertEqual(g.style_entropy_bits("apple"), g.entropy_bits())

    def test_random_has_the_length_and_every_class_asked_for(self):
        for flags in ("", "d", "s", "ds"):
            for n in (8, 20, 64):
                for _ in range(50):
                    p = g.generate_style(f"random:{n}:{flags}")
                    self.assertEqual(len(p), n)
                    self.assertTrue(any(c in g.LOWER for c in p), p)
                    self.assertTrue(any(c in g.UPPER for c in p), p)
                    self.assertEqual(any(c in g.ALL_DIGITS for c in p), "d" in flags, p)
                    self.assertEqual(any(c in g.SYMBOLS for c in p), "s" in flags, p)

    def test_pin_is_digits(self):
        for n in (4, 6, 12):
            self.assertRegex(g.generate_style(f"pin:{n}"), rf"^\d{{{n}}}$")

    def test_entropy_grows_with_options(self):
        self.assertLess(g.style_entropy_bits("random:20:"), g.style_entropy_bits("random:20:ds"))
        self.assertLess(g.style_entropy_bits("random:12:ds"), g.style_entropy_bits("random:20:ds"))

    def test_bad_styles_are_refused(self):
        for bad in ("", "Apple", "random", "random:7:ds", "random:65:ds", "random:20:sd",
                    "random:020:ds", "random:20:x", "pin:3", "pin:13", "pin:6:d", "random:-1:",
                    "random: 20:", None, 20, "x" * 40):
            with self.assertRaises(g.StyleError, msg=repr(bad)):
                g.parse_style(bad)


if __name__ == "__main__":
    unittest.main()
