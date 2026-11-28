"""Generate a strong password in the shape Apple's Passwords app uses.

`xxxxxx-xxxxxx-xxxxxx` - three six-character groups. The point of the shape is that it can be
read off a screen and typed on a phone without losing your place, and the groups are built from
consonant-vowel pairs so each one is a pronounceable nonsense syllable you can actually rehearse.

The honest trade: pronounceable means fewer possibilities per character than random. This lands
around 68 bits, against ~103 for 20 fully random alphanumerics. 68 bits is far beyond anything
an online attacker reaches, and the memorability is what stops someone reusing a password they
already know - which is the threat that actually bites. `entropy_bits()` reports it rather than
leaving the claim vague.
"""

from __future__ import annotations

import math
import secrets

# 'l' and 'o' are left out: against '1' and '0' they are the two that get misread when someone
# reads a password off one screen and types it into another.
CONSONANTS = "bcdfghjkmnpqrstvwxz"
VOWELS = "aeiu"
DIGITS = "23456789"          # no 0/1, same reason
GROUPS = 3
PAIRS_PER_GROUP = 3          # 3 consonant-vowel pairs = 6 characters


def _syllables(rng) -> list:
    return ["".join(rng.choice(CONSONANTS) + rng.choice(VOWELS)
                    for _ in range(PAIRS_PER_GROUP))
            for _ in range(GROUPS)]


def entropy_bits() -> float:
    """Bits of entropy in one generated password, for the shape above."""
    per_pair = math.log2(len(CONSONANTS) * len(VOWELS))
    letters = per_pair * PAIRS_PER_GROUP * GROUPS
    total_chars = GROUPS * PAIRS_PER_GROUP * 2
    digit = math.log2(total_chars) + math.log2(len(DIGITS))   # where it goes, and which digit
    upper = math.log2(total_chars - 1)                        # which remaining letter shifts
    return letters + digit + upper


def generate(rng=None) -> str:
    """A password of the form `hupmyj-8ryTdu-zebqem`.

    Exactly one digit and exactly one uppercase letter, placed at random - the same guarantee
    Apple's generator makes, so the result satisfies sites that demand "a number and a capital"
    without the user having to edit it and weaken it.
    """
    rng = rng or secrets.SystemRandom()
    chars = list("".join(_syllables(rng)))
    n = len(chars)
    digit_at = rng.randrange(n)
    chars[digit_at] = rng.choice(DIGITS)
    upper_at = rng.choice([i for i in range(n) if i != digit_at])
    chars[upper_at] = chars[upper_at].upper()
    joined = "".join(chars)
    size = PAIRS_PER_GROUP * 2
    return "-".join(joined[i:i + size] for i in range(0, n, size))


# --- styles the window can pick -----------------------------------------------------------------
#
# A style is one short string, so it can be kept as a single setting and checked in one place:
#
#   "apple"                Apple's six-six-six shape above
#   "random:<n>:<flags>"   n characters (RANDOM_LENGTH) of letters in both cases, plus digits if
#                          flags holds "d" and symbols if it holds "s" (flags in that order)
#   "pin:<n>"              n digits (PIN_LENGTH)
#
# Every character class a style asks for is guaranteed to appear: a random password is drawn
# again until it does, so the result stays uniform over the passwords that satisfy the rule.

STYLE_DEFAULT = "apple"
RANDOM_LENGTH = (8, 64)
PIN_LENGTH = (4, 12)
LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = LOWER.upper()
ALL_DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*-_+=?.,:;~"


class StyleError(ValueError):
    pass


def parse_style(style) -> dict:
    """{"kind": "apple"|"random"|"pin", "length", "digits", "symbols"}, or raise StyleError."""
    if not isinstance(style, str) or len(style) > 32:
        raise StyleError("a style is a short string")
    if style == "apple":
        return {"kind": "apple", "length": GROUPS * PAIRS_PER_GROUP * 2 + GROUPS - 1,
                "digits": True, "symbols": True}
    parts = style.split(":")
    if parts[0] == "random" and len(parts) == 3:
        n, flags = parts[1], parts[2]
        lo, hi = RANDOM_LENGTH
        if flags not in ("", "d", "s", "ds"):
            raise StyleError("unknown flags")
    elif parts[0] == "pin" and len(parts) == 2:
        n, flags = parts[1], ""
        lo, hi = PIN_LENGTH
    else:
        raise StyleError("unknown style")
    if not n.isdigit() or n != str(int(n)) or not lo <= int(n) <= hi:
        raise StyleError("length out of range")
    if parts[0] == "pin":
        return {"kind": "pin", "length": int(n), "digits": True, "symbols": False}
    return {"kind": "random", "length": int(n), "digits": "d" in flags, "symbols": "s" in flags}


def _classes(cfg: dict) -> list:
    if cfg["kind"] == "pin":
        return [ALL_DIGITS]
    out = [LOWER, UPPER]
    if cfg["digits"]:
        out.append(ALL_DIGITS)
    if cfg["symbols"]:
        out.append(SYMBOLS)
    return out


def style_entropy_bits(style: str) -> float:
    cfg = parse_style(style)
    if cfg["kind"] == "apple":
        return entropy_bits()
    return cfg["length"] * math.log2(len("".join(_classes(cfg))))


def generate_style(style: str, rng=None) -> str:
    """A password in the given style (see above). Raises StyleError for a bad style."""
    cfg = parse_style(style)
    rng = rng or secrets.SystemRandom()
    if cfg["kind"] == "apple":
        return generate(rng)
    classes = _classes(cfg)
    alphabet = "".join(classes)
    while True:
        pw = "".join(rng.choice(alphabet) for _ in range(cfg["length"]))
        # A class has at most 26 of ~80 characters, so for 8+ characters this rarely loops.
        if all(any(c in cls for c in pw) for cls in classes):
            return pw
