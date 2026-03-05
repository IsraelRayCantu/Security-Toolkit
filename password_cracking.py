# topic: Password Security
# title: Password Cracking Demo
# priority: 1

"""
password_cracking.py - Password Cracking Techniques Demo
=========================================================
Demonstrates five password attack techniques against SHA-256
hashed passwords. All attacks operate on hashes - never on
plaintext passwords stored anywhere.

PURPOSE
--------
This module exists to demonstrate WHY weak passwords are
dangerous and HOW attackers approach password cracking.
Understanding the attack is the first step to defending against it.

THE FIVE TECHNIQUES
--------------------
1. Brute Force
   Tries every possible combination of characters up to a
   given length. Guaranteed to find the password eventually
   but exponentially slower as length increases.
   Time: O(charset^length) - very slow for long passwords.

2. Dictionary Attack
   Tries words from a wordlist. Most users choose real words,
   names, or common phrases. Dictionary attacks succeed against
   the vast majority of real-world passwords.
   Time: O(wordlist_size) - fast if password is in the list.

3. Rainbow Table
   Pre-computed table of hash->password mappings. Trading disk
   space for time - the lookup is O(1) if the hash is in the
   table. Defeated entirely by salting.

4. Hybrid Attack
   Combines dictionary words with common modifications:
   appending numbers, adding symbols, capitalising. Attacks
   passwords like "password123" and "P@ssword".

5. Rule-Based (Leet Speak)
   Applies character substitution rules (a->@, e->3, etc.)
   to dictionary words. Attacks passwords like "p@55w0rd".

WHY SALTING DEFEATS RAINBOW TABLES
------------------------------------
A salt is a random string appended to the password before
hashing. Even if two users have the same password, their
hashes will be different because their salts differ.
Pre-computed rainbow tables are useless against salted hashes
because you would need a separate table for every possible salt.

Modern systems use bcrypt, Argon2, or PBKDF2 which include
salting, stretching (many iterations), and memory-hardness to
make cracking computationally expensive even with the hash.

PLATFORM SUPPORT
-----------------
Works identically on Windows 11 and Linux/Kali.
No elevated privileges required.
No external dependencies - uses Python standard library only.

EDUCATIONAL USE ONLY.
Only crack hashes you own or have explicit permission to test.

Requirements: Python standard library only
"""

import hashlib
import itertools
import os
import string
import sys
import time
from typing import Optional

IS_WINDOWS = os.name == "nt"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Sample wordlist - in real attacks this would be millions of entries
# Common sources: rockyou.txt, SecLists, Have I Been Pwned corpus
SAMPLE_WORDLIST = [
    "password", "123456", "password123", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "sunshine",
    "princess", "shadow", "superman", "qwerty", "michael",
    "football", "baseball", "abc123", "login", "passw0rd",
    "iloveyou", "trustno1", "hello", "charlie", "donald",
    "password1", "1234567890", "starwars", "computer", "test",
]

# Leet speak substitution rules
# Applied during rule-based attacks to mutate dictionary words
LEET_RULES = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"],
    "l": ["1"],
    "g": ["9"],
}

# Number suffixes used in hybrid attack
COMMON_SUFFIXES = [
    "1", "12", "123", "1234", "12345", "123456",
    "!", "!!", "2023", "2024", "2025", "2026",
    "1!", "123!", "99", "01", "00",
]

# Common prefixes used in hybrid attack
COMMON_PREFIXES = ["1", "the", "my", "your", "a"]

# Rainbow table - pre-computed hash to password mappings
# In real attacks this is a multi-gigabyte file
RAINBOW_TABLE = {
    hashlib.sha256(word.encode()).hexdigest(): word
    for word in SAMPLE_WORDLIST
}


# ---------------------------------------------------------------------------
# Hash utilities
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """
    Hash a password string using SHA-256.

    SHA-256 is a one-way cryptographic hash function - you cannot
    reverse it to get the original password. Cracking works by
    hashing candidate passwords and comparing against the target
    hash until a match is found.

    Parameters
    ----------
    password : str   Plaintext password to hash.

    Returns
    -------
    64-character hex string (256 bits).
    """
    return hashlib.sha256(password.encode()).hexdigest()


def verify_crack(password: str, target_hash: str) -> bool:
    """
    Check if a candidate password matches the target hash.

    Parameters
    ----------
    password    : str   Candidate plaintext password.
    target_hash : str   SHA-256 hash we are trying to crack.

    Returns
    -------
    True if hash(password) == target_hash.
    """
    return hash_password(password) == target_hash


# ---------------------------------------------------------------------------
# Attack 1: Brute Force
# ---------------------------------------------------------------------------

def brute_force_attack(
    target_hash: str,
    charset: str,
    max_length: int,
) -> Optional[str]:
    """
    Try every possible combination of characters up to max_length.

    itertools.product(charset, repeat=length) generates all
    combinations of length characters from the charset.
    For example with charset='ab' and length=2:
      aa, ab, ba, bb

    Complexity: len(charset) ^ max_length total attempts.
    For a 62-character charset (a-z A-Z 0-9):
      Length 4: 62^4  =  14,776,336 combinations
      Length 6: 62^6  =  56,800,235,584 combinations
      Length 8: 62^8  = 218,340,105,584,896 combinations

    This demonstrates why length is the most important factor
    in password strength.

    Parameters
    ----------
    target_hash : str   Hash to crack.
    charset     : str   Characters to use in combinations.
    max_length  : int   Maximum password length to try.

    Returns
    -------
    Cracked password string, or None if not found.
    """
    attempts = 0
    start    = time.perf_counter()

    for length in range(1, max_length + 1):
        print(f"  [*] Trying length {length}...")

        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1

            if verify_crack(candidate, target_hash):
                elapsed = time.perf_counter() - start
                print(
                    f"\n  [+] CRACKED: '{candidate}' "
                    f"in {attempts:,} attempts ({elapsed:.3f}s)"
                )
                return candidate

            # Progress update every 100,000 attempts
            if attempts % 100_000 == 0:
                elapsed = time.perf_counter() - start
                rate    = attempts / elapsed if elapsed > 0 else 0
                print(
                    f"\r  [*] {attempts:>10,} attempts  |  "
                    f"{rate:>10,.0f}/s  |  "
                    f"Current: {candidate}          ",
                    end="",
                    flush=True,
                )

    elapsed = time.perf_counter() - start
    print(
        f"\n  [-] Not found after {attempts:,} attempts "
        f"({elapsed:.3f}s)"
    )
    return None


# ---------------------------------------------------------------------------
# Attack 2: Dictionary Attack
# ---------------------------------------------------------------------------

def dictionary_attack(
    target_hash: str,
    wordlist: list,
) -> Optional[str]:
    """
    Try each word in the wordlist against the target hash.

    Real-world effectiveness: the rockyou.txt wordlist contains
    14 million passwords from a 2009 breach. Analysis of subsequent
    breaches shows that approximately 80% of real-world passwords
    appear in or are trivially derived from this list.

    Parameters
    ----------
    target_hash : str   Hash to crack.
    wordlist    : list  List of candidate passwords to try.

    Returns
    -------
    Cracked password string, or None if not found.
    """
    attempts = 0
    start    = time.perf_counter()

    for word in wordlist:
        attempts += 1
        if verify_crack(word, target_hash):
            elapsed = time.perf_counter() - start
            print(
                f"  [+] CRACKED: '{word}' "
                f"in {attempts:,} attempts ({elapsed:.4f}s)"
            )
            return word

    elapsed = time.perf_counter() - start
    print(
        f"  [-] Not found after {attempts:,} attempts "
        f"({elapsed:.4f}s)"
    )
    return None


# ---------------------------------------------------------------------------
# Attack 3: Rainbow Table
# ---------------------------------------------------------------------------

def rainbow_table_attack(
    target_hash: str,
    table: dict,
) -> Optional[str]:
    """
    Look up the target hash in a pre-computed hash->password table.

    Rainbow table lookup is O(1) - instantaneous regardless of
    how complex the password is, as long as it appears in the table.

    This is why password databases MUST use salted hashes.
    A salt makes every hash unique even for identical passwords,
    meaning a pre-computed table is useless - you would need to
    recompute the entire table for every possible salt value.

    Parameters
    ----------
    target_hash : str    Hash to look up.
    table       : dict   Pre-computed {hash: password} dictionary.

    Returns
    -------
    Cracked password string, or None if hash not in table.
    """
    start  = time.perf_counter()
    result = table.get(target_hash)
    elapsed = time.perf_counter() - start

    if result:
        print(
            f"  [+] CRACKED: '{result}' "
            f"(lookup in {elapsed:.6f}s)"
        )
        return result

    print(f"  [-] Hash not found in rainbow table.")
    return None


# ---------------------------------------------------------------------------
# Attack 4: Hybrid Attack
# ---------------------------------------------------------------------------

def hybrid_attack(
    target_hash: str,
    wordlist: list,
) -> Optional[str]:
    """
    Try dictionary words combined with common suffixes and prefixes.

    Many users think adding numbers to a word makes it secure.
    Hybrid attacks specifically target this pattern.
    Examples targeted: password123, admin2024, 1football, abc123!

    Parameters
    ----------
    target_hash : str   Hash to crack.
    wordlist    : list  Base words to mutate.

    Returns
    -------
    Cracked password string, or None if not found.
    """
    attempts = 0
    start    = time.perf_counter()

    candidates = []

    # Build candidate list: word, word+suffix, prefix+word,
    # word+suffix capitalised, WORD+suffix
    for word in wordlist:
        candidates.append(word)
        candidates.append(word.capitalize())
        candidates.append(word.upper())

        for suffix in COMMON_SUFFIXES:
            candidates.append(word + suffix)
            candidates.append(word.capitalize() + suffix)

        for prefix in COMMON_PREFIXES:
            candidates.append(prefix + word)

    for candidate in candidates:
        attempts += 1
        if verify_crack(candidate, target_hash):
            elapsed = time.perf_counter() - start
            print(
                f"  [+] CRACKED: '{candidate}' "
                f"in {attempts:,} attempts ({elapsed:.4f}s)"
            )
            return candidate

    elapsed = time.perf_counter() - start
    print(
        f"  [-] Not found after {attempts:,} attempts "
        f"({elapsed:.4f}s)"
    )
    return None


# ---------------------------------------------------------------------------
# Attack 5: Rule-Based (Leet Speak)
# ---------------------------------------------------------------------------

def apply_leet_substitutions(word: str) -> list:
    """
    Generate leet speak variants of a word by substituting
    characters according to LEET_RULES.

    For a word with N substitutable characters, this generates
    up to 2^N variants (each character either stays or is replaced).
    We apply single substitutions only to keep the list manageable.

    Parameters
    ----------
    word : str   Base word to mutate.

    Returns
    -------
    List of leet speak variants including the original word.
    """
    variants = [word]

    for i, char in enumerate(word.lower()):
        if char in LEET_RULES:
            for replacement in LEET_RULES[char]:
                variant = word[:i] + replacement + word[i + 1:]
                variants.append(variant)
                variants.append(variant.capitalize())

    return variants


def rule_based_attack(
    target_hash: str,
    wordlist: list,
) -> Optional[str]:
    """
    Apply leet speak substitution rules to dictionary words.

    Targets passwords like: p@ssword, p455w0rd, @dmin, s3cur1ty

    Parameters
    ----------
    target_hash : str   Hash to crack.
    wordlist    : list  Base words to apply rules to.

    Returns
    -------
    Cracked password string, or None if not found.
    """
    attempts = 0
    start    = time.perf_counter()

    for word in wordlist:
        for variant in apply_leet_substitutions(word):
            attempts += 1
            if verify_crack(variant, target_hash):
                elapsed = time.perf_counter() - start
                print(
                    f"  [+] CRACKED: '{variant}' "
                    f"(from base '{word}') "
                    f"in {attempts:,} attempts ({elapsed:.4f}s)"
                )
                return variant

    elapsed = time.perf_counter() - start
    print(
        f"  [-] Not found after {attempts:,} attempts "
        f"({elapsed:.4f}s)"
    )
    return None


# ---------------------------------------------------------------------------
# Demo targets
# ---------------------------------------------------------------------------

DEMO_TARGETS = {
    "1": {
        "label":    "Short brute-force target (3 chars, digits only)",
        "password": "abc",
        "hint":     "3 lowercase letters - try brute force",
    },
    "2": {
        "label":    "Common dictionary word",
        "password": "dragon",
        "hint":     "Very common password - try dictionary attack",
    },
    "3": {
        "label":    "Rainbow table target",
        "password": "admin",
        "hint":     "Pre-computed - try rainbow table",
    },
    "4": {
        "label":    "Hybrid target (word + numbers)",
        "password": "password123",
        "hint":     "Word with suffix - try hybrid attack",
    },
    "5": {
        "label":    "Leet speak target",
        "password": "p@ssword",
        "hint":     "Leet speak variant - try rule-based attack",
    },
}

ATTACK_MENU = {
    "1": "Brute Force",
    "2": "Dictionary Attack",
    "3": "Rainbow Table",
    "4": "Hybrid Attack",
    "5": "Rule-Based (Leet Speak)",
    "6": "Run All Attacks",
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Interactive password cracking demonstration.

    Lets the user select a target hash and attack method.
    Hashes are generated from known passwords - the point is to
    demonstrate how each technique works, not to crack unknown hashes.
    """
    print("\n  Password Cracking Demo")
    print("  " + "-" * 22)
    print(f"  Platform : {sys.platform}")
    print("  [!] EDUCATIONAL USE ONLY.")
    print("  [!] Only crack hashes you own or have permission to test.")
    print("  [*] All attacks operate on SHA-256 hashes - never plaintext.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    # Target selection
    print("  Select a target:\n")
    for key, target in DEMO_TARGETS.items():
        print(f"    {key}. {target['label']}")
    print("    C. Enter custom SHA-256 hash\n")

    target_choice = input("  Select target: ").strip().lower()
    if target_choice == "0":
        return

    if target_choice == "c":
        custom_hash = input(
            "  Enter SHA-256 hash (64 hex chars): "
        ).strip().lower()
        if len(custom_hash) != 64 or not all(
            c in "0123456789abcdef" for c in custom_hash
        ):
            print("  [!] Invalid SHA-256 hash.")
            return
        target_hash = custom_hash
        hint        = "Custom hash - try multiple attacks"
        known_pass  = None
    elif target_choice in DEMO_TARGETS:
        target      = DEMO_TARGETS[target_choice]
        target_hash = hash_password(target["password"])
        hint        = target["hint"]
        known_pass  = target["password"]
    else:
        print("  [!] Invalid selection.")
        return

    print(f"\n  Target hash : {target_hash[:32]}...{target_hash[32:]}")
    print(f"  Hint        : {hint}")
    if known_pass:
        print(f"  [*] (Known plaintext for demo: '{known_pass}')")

    # Attack selection
    print("\n  Select attack method:\n")
    for key, name in ATTACK_MENU.items():
        print(f"    {key}. {name}")
    print()

    attack_choice = input("  Select attack: ").strip()
    if attack_choice == "0":
        return
    if attack_choice not in ATTACK_MENU:
        print("  [!] Invalid selection.")
        return

    print(
        f"\n  Running: {ATTACK_MENU[attack_choice]} "
        f"against hash {target_hash[:16]}...\n"
    )

    # Run selected attack
    if attack_choice == "1":
        print("  Charset options:")
        print("    1. Digits only     (0-9)")
        print("    2. Lowercase only  (a-z)")
        print("    3. Alpha + digits  (a-z 0-9)")
        cs_choice = input("  Charset [2]: ").strip() or "2"

        if cs_choice == "1":
            charset = string.digits
        elif cs_choice == "3":
            charset = string.ascii_lowercase + string.digits
        else:
            charset = string.ascii_lowercase

        raw_len = input("  Max password length [4]: ").strip() or "4"
        if not raw_len.isdigit():
            print("  [!] Must be a number.")
            return
        max_len = min(int(raw_len), 6)
        if max_len != int(raw_len):
            print(f"  [*] Capped at 6 to keep demo manageable.")

        print(
            f"\n  Brute forcing: charset='{charset}' "
            f"max_length={max_len}\n"
        )
        brute_force_attack(target_hash, charset, max_len)

    elif attack_choice == "2":
        print(f"  Wordlist size: {len(SAMPLE_WORDLIST)} words\n")
        dictionary_attack(target_hash, SAMPLE_WORDLIST)

    elif attack_choice == "3":
        print(f"  Rainbow table: {len(RAINBOW_TABLE)} entries\n")
        rainbow_table_attack(target_hash, RAINBOW_TABLE)

    elif attack_choice == "4":
        print(f"  Wordlist: {len(SAMPLE_WORDLIST)} base words\n")
        hybrid_attack(target_hash, SAMPLE_WORDLIST)

    elif attack_choice == "5":
        print(f"  Wordlist: {len(SAMPLE_WORDLIST)} base words\n")
        rule_based_attack(target_hash, SAMPLE_WORDLIST)

    elif attack_choice == "6":
        print("  Running all attacks in sequence...\n")
        found = None

        for name, func, args in [
            ("Dictionary",  dictionary_attack,  (target_hash, SAMPLE_WORDLIST)),
            ("Rainbow",     rainbow_table_attack, (target_hash, RAINBOW_TABLE)),
            ("Hybrid",      hybrid_attack,       (target_hash, SAMPLE_WORDLIST)),
            ("Rule-Based",  rule_based_attack,   (target_hash, SAMPLE_WORDLIST)),
        ]:
            print(f"  --- {name} Attack ---")
            if name == "Rainbow":
                result = func(*args)
            else:
                result = func(*args)
            if result:
                found = result
                print(f"  [+] Stopped - password found by {name} attack.\n")
                break
            print()

        if not found:
            print(
                "  [-] Password not found by any attack.\n"
                "      Try brute force with a longer max length."
            )

    # Education summary
    print("\n  " + "-" * 56)
    print("  Key takeaways:")
    print("    - Length matters more than complexity for brute force")
    print("    - Salting defeats rainbow tables entirely")
    print("    - bcrypt/Argon2 make ALL attacks much slower")
    print("    - Most real passwords are in wordlists (rockyou.txt)")
    print("    - A 20+ char passphrase beats a 10-char complex password")
    print("  " + "-" * 56)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()