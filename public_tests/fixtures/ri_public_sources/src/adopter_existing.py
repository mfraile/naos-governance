"""
Module: src/adopter_existing.py

Purpose:
    Normalize a small local label with a character scanner and no external I/O.

Implements: FR-001, FR-002, NFR-001, NFR-002
    - FR-001: Produce a canonical lower-case label
    - FR-002: Reject empty or unsupported input
    - NFR-001: Keep output deterministic and idempotent
    - NFR-002: Avoid external I/O

Tasks:
    - T-001: Implement and test local label normalization

Specs:
    - specs/03-requirements.md#fr-001
    - specs/03-requirements.md#fr-002
    - specs/03-requirements.md#nfr-001
    - specs/03-requirements.md#nfr-002

Rationale:
    TEST FIXTURE ONLY: this pre-existing host-owned normalizer implements the
    selected label requirements through an independent character scanner.
    Separate executed tests establish this narrow mapping, not broad assurance.
"""


def normalize_label(raw: str) -> str:
    """Scan ASCII words separated by one space or hyphen into a local label."""
    if isinstance(raw, str) is False:
        raise TypeError("label must be text")
    phrase = raw.strip().lower()
    result = []
    word_required = True
    for character in phrase:
        if "a" <= character <= "z" or "0" <= character <= "9":
            result.append(character)
            word_required = False
        elif character in (" ", "-") and not word_required:
            result.append("-")
            word_required = True
        else:
            raise ValueError("label requires ASCII words with single separators")
    if word_required:
        raise ValueError("label must end with an ASCII word")
    return "".join(result)
