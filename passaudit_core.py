"""passaudit core — auditing, entropy math, breach check, generation.
UI-agnostic. Pure functions. Importable from Streamlit, CLI, or tests.
"""
from __future__ import annotations

import hashlib
import math
import secrets
import string
from dataclasses import dataclass, field
from typing import Optional

import requests
from zxcvbn import zxcvbn

# ---------- character set detection ----------

_CHARSETS = [
    ("lowercase", set(string.ascii_lowercase), 26),
    ("uppercase", set(string.ascii_uppercase), 26),
    ("digits",    set(string.digits),          10),
    ("symbols",   set(string.punctuation),     len(string.punctuation)),
    ("space",     {" "},                       1),
]

def charset_size(pw: str) -> tuple[int, list[str]]:
    """Return (effective charset size, list of categories present)."""
    used, size = [], 0
    chars = set(pw)
    for name, alphabet, count in _CHARSETS:
        if chars & alphabet:
            used.append(name)
            size += count
    # account for non-ASCII / unicode chars (each unique counts as +1)
    extras = chars - set().union(*[a for _, a, _ in _CHARSETS])
    if extras:
        used.append(f"other({len(extras)})")
        size += len(extras)
    return size, used


def shannon_entropy_bits(pw: str) -> float:
    """Naive entropy assuming uniform random over detected charset.
    Real entropy ≤ this; zxcvbn gives a better attacker-aware estimate.
    """
    if not pw:
        return 0.0
    size, _ = charset_size(pw)
    return len(pw) * math.log2(max(size, 1))


# ---------- HIBP k-anonymity check ----------

class BreachCheckError(Exception):
    pass


def hibp_check(pw: str, timeout: int = 8) -> int:
    """Return number of times pw appears in HIBP breach corpus.
    Uses k-anonymity: only first 5 chars of SHA1 hash are sent.
    """
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true", "User-Agent": "passaudit/1.0"},
            timeout=timeout,
        )
        r.raise_for_status()
    except requests.RequestException as e:
        raise BreachCheckError(str(e)) from e
    for line in r.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0].strip() == suffix:
            return int(parts[1])
    return 0


# ---------- crack-time estimates at multiple attacker speeds ----------

ATTACKER_PROFILES = {
    "Online throttled (10/s)":          1e1,
    "Online no-throttle (1k/s)":        1e3,
    "Offline, slow hash (10k/s)":       1e4,
    "Offline, fast hash (10B/s)":       1e10,
    "Nation-state cluster (100T/s)":    1e14,
}

def human_seconds(s: float) -> str:
    if s < 1:                  return "instant"
    if s < 60:                 return f"{s:.0f} sec"
    if s < 3600:               return f"{s/60:.1f} min"
    if s < 86400:              return f"{s/3600:.1f} hours"
    if s < 86400 * 365:        return f"{s/86400:.1f} days"
    if s < 86400 * 365 * 100:  return f"{s/(86400*365):.1f} years"
    if s < 86400 * 365 * 1e6:  return f"{s/(86400*365):,.0f} years"
    return "geological time"

def crack_times(guesses: float) -> dict[str, str]:
    # divide by 2 = average-case (50% of keyspace)
    return {name: human_seconds((guesses / 2) / rate)
            for name, rate in ATTACKER_PROFILES.items()}


# ---------- main audit ----------

@dataclass
class AuditResult:
    password_length: int
    charset_size: int
    charset_used: list[str]
    entropy_bits: float
    zxcvbn_score: int            # 0..4
    zxcvbn_guesses: float
    crack_times: dict[str, str]
    feedback_warning: str
    feedback_suggestions: list[str]
    breach_count: Optional[int] = None
    breach_error: Optional[str] = None

SCORE_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
SCORE_COLORS = ["#A32D2D", "#BA7517", "#854F0B", "#3B6D11", "#0F6E56"]

def audit(pw: str, breach: bool = True) -> AuditResult:
    z = zxcvbn(pw)
    size, used = charset_size(pw)
    res = AuditResult(
        password_length=len(pw),
        charset_size=size,
        charset_used=used,
        entropy_bits=shannon_entropy_bits(pw),
        zxcvbn_score=z["score"],
        zxcvbn_guesses=float(z["guesses"]),
        crack_times=crack_times(float(z["guesses"])),
        feedback_warning=z["feedback"]["warning"] or "",
        feedback_suggestions=list(z["feedback"]["suggestions"]),
    )
    if breach:
        try:
            res.breach_count = hibp_check(pw)
        except BreachCheckError as e:
            res.breach_error = str(e)
    return res


# ---------- generation ----------

# ambiguous chars users often misread
_AMBIGUOUS = set("Il1O0o`'\"")

@dataclass
class GenerateOptions:
    length: int = 20
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False
    custom_excludes: str = ""

def generate_password(opt: GenerateOptions) -> str:
    """Cryptographically-secure password generator.
    Uses secrets.choice. Guarantees at least one char from each enabled class.
    """
    pools = []
    if opt.use_lower:   pools.append(string.ascii_lowercase)
    if opt.use_upper:   pools.append(string.ascii_uppercase)
    if opt.use_digits:  pools.append(string.digits)
    if opt.use_symbols: pools.append(string.punctuation)

    if not pools:
        raise ValueError("Select at least one character class.")
    if opt.length < len(pools):
        raise ValueError(f"Length must be ≥ {len(pools)} to include each class.")

    excludes = set(opt.custom_excludes)
    if opt.exclude_ambiguous:
        excludes |= _AMBIGUOUS

    pools = [[c for c in p if c not in excludes] for p in pools]
    if any(len(p) == 0 for p in pools):
        raise ValueError("Exclusions removed every char of a selected class.")

    # one from each class, then fill, then shuffle
    chars = [secrets.choice(p) for p in pools]
    all_chars = [c for p in pools for c in p]
    chars += [secrets.choice(all_chars) for _ in range(opt.length - len(pools))]

    # Fisher-Yates with secrets
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def generate_passphrase(words: int = 5, sep: str = "-", capitalize: bool = True,
                        add_digit: bool = True) -> str:
    """Diceware-style passphrase from a small built-in list.
    For real use, swap WORDS for the full EFF long list (7776 words).
    """
    pw_words = [secrets.choice(WORDS) for _ in range(words)]
    if capitalize:
        pw_words = [w.capitalize() for w in pw_words]
    out = sep.join(pw_words)
    if add_digit:
        out += str(secrets.randbelow(100)).zfill(2)
    return out


# Trimmed EFF-style word list (~200 words). Replace with full 7776-word EFF list
# in production for maximum entropy. Source pattern: eff.org/dice.
WORDS = """
abacus abdomen abide ablaze able abnormal abolish above abruptly absence absolute absorb
abstract absurd abundant abuse academy acceptance access accident acclaim accompany account
accuse achieve acid acoustic acquire acrobat actress addicted address adequate adjust admire
adopt advance adverb advice afar affair afraid agency agile airport alarm albatross alcohol
alfalfa algebra alibi alkaline almanac almost aloha alpine already amaze amber ambush amend
amnesty amusing analyst anchor android angle animal annoying annual answer antelope antique
anyone apparel appear apple aquarium aqueduct arena argument armchair aroma arrival arrow
artisan artwork ascent ashamed asleep aspect asset astronaut athlete atlas atom attic auburn
audio august aunt author auto avalanche average avocado awake award awesome awful awkward
balcony bamboo bandage banjo banker barber baseball basket battle bazooka beacon beanstalk
beehive belief belong beneath benefit beverage bicycle bifocals biology birthday biscuit
bismuth blade blanket blender blizzard blooper blueprint bobcat bodily bonus border bossy
bottle bouquet boxing bracelet bravado breath briefcase brigade broaden buckle buffalo
bugle bulldog burrito butane button buyer buzzard cabin cable cactus cadillac caffeine cage
cake camera canary candle canine cannabis canopy canyon cardboard carefree cargo carnival
""".split()
