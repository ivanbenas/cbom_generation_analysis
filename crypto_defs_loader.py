#!/usr/bin/env python3
"""
Load cryptography definitions from CycloneDX specification/schema/cryptography-defs.json.
Provides OID lookup (from elliptic curves) and algorithm detection (from algorithm families).
Supports PQC primitives: ML-DSA, ML-KEM, SLH-DSA, EdDSA, XMSS, LMS.
"""

import json
import re
from pathlib import Path
from typing import Optional

# PQC algorithm families (NIST quantum security level 5)
PQC_FAMILIES = frozenset({"ML-DSA", "ML-KEM", "SLH-DSA", "EdDSA", "XMSS", "LMS"})


def _find_cryptography_defs() -> Path:
    """Locate cryptography-defs.json relative to this script or workspace."""
    candidates = [
        Path(__file__).parent / "specification" / "schema" / "cryptography-defs.json",
        Path(__file__).parent / "specification" / "schema" / "cryptography-defs.json",
        Path("specification/schema/cryptography-defs.json"),
    ]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError(
        "cryptography-defs.json not found. Expected at specification/schema/cryptography-defs.json"
    )


def _pattern_to_regex(pattern: str) -> re.Pattern:
    """Convert spec pattern to regex. [..] = optional, {x} = placeholder."""
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "[":
            # Optional group: [...] -> (?:...)?
            j = pattern.find("]", i)
            if j >= 0:
                inner = _pattern_to_regex_inner(pattern[i + 1 : j])
                out.append("(?:")
                out.append(inner)
                out.append(")?")
                i = j + 1
                continue
        if c == "{":
            j = pattern.find("}", i)
            if j >= 0:
                out.append(r"[^\s\-]+")
                i = j + 1
                continue
        if c in ".+*?\\":
            out.append("\\" + c)
        # Do NOT escape ^ $ ( ) - anchors and grouping
        else:
            out.append(c)
        i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE)


def _pattern_to_regex_inner(s: str) -> str:
    """Convert inner part of optional group."""
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "{":
            j = s.find("}", i)
            if j >= 0:
                out.append(r"[^\s\-]+")
                i = j + 1
                continue
        if c in ".+*?\\":
            out.append("\\" + c)
        else:
            out.append(c)
        i += 1
    return "".join(out)


def load_cryptography_defs(path: Optional[Path] = None) -> dict:
    """Load and parse cryptography-defs.json."""
    p = path or _find_cryptography_defs()
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def build_curve_canonical_map(defs: dict) -> dict[str, str]:
    """
    Build curve name/alias -> canonical "family/curvename" map.
    Used for ellipticCurve in algorithmProperties.
    """
    curve_map: dict[str, str] = {}
    for family in defs.get("ellipticCurves", []):
        family_name = family.get("name", "")
        for curve in family.get("curves", []):
            cname = curve.get("name", "")
            canonical = f"{family_name}/{cname}" if family_name and cname else ""
            if not canonical:
                continue
            for alias in [cname] + [a.get("name", "") for a in curve.get("aliases", [])]:
                if alias:
                    curve_map[alias] = canonical
                    curve_map[alias.upper()] = canonical
                    curve_map[alias.lower()] = canonical
    return curve_map


def match_elliptic_curve(algo_name: str, curve_map: dict[str, str]) -> Optional[str]:
    """
    If algo_name contains a known curve name, return canonical "family/curvename".
    Matches longest curve names first to avoid partial matches.
    """
    if not algo_name or not curve_map:
        return None
    name_upper = algo_name.upper()
    name_lower = algo_name.lower()
    # Sort keys by length descending so "secp256r1" matches before "256"
    for curve_key in sorted(curve_map.keys(), key=len, reverse=True):
        if len(curve_key) < 2:  # skip very short keys
            continue
        if curve_key in name_upper or curve_key in name_lower or curve_key in algo_name:
            return curve_map[curve_key]
    return None


def build_oid_map(defs: dict) -> dict[str, str]:
    """
    Build name -> OID map from ellipticCurves.
    Includes curve names and all aliases (e.g. secp256r1, P-256, prime256v1).
    """
    oid_map: dict[str, str] = {}
    for family in defs.get("ellipticCurves", []):
        family_name = family.get("name", "")
        for curve in family.get("curves", []):
            oid = curve.get("oid")
            if not oid:
                continue
            name = curve.get("name", "")
            if name:
                oid_map[name] = oid
                oid_map[name.upper()] = oid
                oid_map[name.lower()] = oid
            # Prefixed form (family/name)
            prefixed = f"{family_name}/{name}"
            if prefixed:
                oid_map[prefixed] = oid
            # Aliases
            for alias in curve.get("aliases", []):
                aname = alias.get("name", "")
                if aname:
                    oid_map[aname] = oid
                    oid_map[aname.upper()] = oid
                    oid_map[aname.lower()] = oid
    return oid_map


def build_algorithm_matchers(defs: dict) -> list[tuple[re.Pattern, str, str, bool]]:
    """
    Build list of (regex, family, primitive, is_pqc) for matching algorithm names.
    """
    matchers: list[tuple[re.Pattern, str, str, bool]] = []
    for algo in defs.get("algorithms", []):
        family = algo.get("family", "")
        is_pqc = family in PQC_FAMILIES
        for v in algo.get("variant", []):
            pattern_str = v.get("pattern", "")
            primitive = v.get("primitive", "other")
            if not pattern_str:
                continue
            try:
                rx = _pattern_to_regex(pattern_str)
                matchers.append((rx, family, primitive, is_pqc))
            except re.error:
                continue
    return matchers


def get_oid(algorithm: str, oid_map: dict[str, str]) -> Optional[str]:
    """Get OID for algorithm/curve name. Checks exact and case variants."""
    v = oid_map.get(algorithm)
    if v:
        return v
    v = oid_map.get(algorithm.upper())
    if v:
        return v
    v = oid_map.get(algorithm.lower())
    if v:
        return v
    return None


def match_algorithm(
    name: str, matchers: list[tuple[re.Pattern, str, str, bool]]
) -> Optional[tuple[str, str, bool]]:
    """
    Match algorithm name against spec. Returns (family, primitive, is_pqc) or None.
    """
    for rx, family, primitive, is_pqc in matchers:
        if rx.search(name):
            return (family, primitive, is_pqc)
    return None


# Fallback algorithm -> family when pattern doesn't match (e.g. Java "HmacSHA512")
ALGORITHM_FAMILY_FALLBACK: dict[str, str] = {
    "HmacSHA256": "HMAC",
    "HmacSHA512": "HMAC",
    "HmacSHA384": "HMAC",
    "HmacSHA1": "HMAC",
    "HMAC-SHA256": "HMAC",
    "HMAC-SHA512": "HMAC",
    "HMAC-SHA384": "HMAC",
    "HMAC-SHA1": "HMAC",
}

# Well-known algorithm OIDs not in elliptic curves (NIST/IANA/PKCS)
# Used when curve OID lookup fails but algorithm is known
ALGORITHM_OIDS_FALLBACK = {
    "SHA-1": "2.16.840.1.101.3.4.2.1",
    "SHA1": "2.16.840.1.101.3.4.2.1",
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3",
    "SHA512": "2.16.840.1.101.3.4.2.3",
    "HmacSHA512": "1.2.840.113549.2.11",
    "HmacSHA256": "1.2.840.113549.2.9",
    "HMAC-SHA512": "1.2.840.113549.2.11",
    "HMAC-SHA256": "1.2.840.113549.2.9",
    "RSA": "1.2.840.113549.1.1.1",
    "DSA": "1.2.840.10040.4.1",
    "SHA256withRSA": "1.2.840.113549.1.1.11",
    "SHA256withECDSA": "1.2.840.10045.4.3.2",
    "SHA256withDSA": "1.2.840.10040.4.3",
    "X.509": "1.3.6.1.5.5.7.1.1",
    "PKCS12": "1.2.840.113549.1.12.1.1",
    "MD5": "1.2.840.113549.2.5",
}


def get_oid_for_algorithm(
    algorithm: str, oid_map: dict[str, str], matchers: list[tuple[re.Pattern, str, str, bool]]
) -> Optional[str]:
    """
    Get OID for an algorithm. Uses elliptic curve OIDs first, then fallback.
    """
    oid = get_oid(algorithm, oid_map)
    if oid:
        return oid
    return ALGORITHM_OIDS_FALLBACK.get(
        algorithm, ALGORITHM_OIDS_FALLBACK.get(algorithm.upper())
    )


class CryptographyDefs:
    """Cached loader for cryptography-defs.json."""

    _instance: Optional["CryptographyDefs"] = None

    def __init__(self, path: Optional[Path] = None):
        self._defs = load_cryptography_defs(path)
        self._oid_map = build_oid_map(self._defs)
        self._curve_map = build_curve_canonical_map(self._defs)
        self._matchers = build_algorithm_matchers(self._defs)

    @classmethod
    def get(cls, path: Optional[Path] = None) -> "CryptographyDefs":
        if cls._instance is None:
            cls._instance = cls(path)
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset cached instance (for testing)."""
        cls._instance = None

    @property
    def oid_map(self) -> dict[str, str]:
        return self._oid_map

    @property
    def matchers(self) -> list[tuple[re.Pattern, str, str, bool]]:
        return self._matchers

    def get_oid(self, algorithm: str) -> Optional[str]:
        return get_oid_for_algorithm(algorithm, self._oid_map, self._matchers)

    def match_algorithm(self, name: str) -> Optional[tuple[str, str, bool]]:
        return match_algorithm(name, self._matchers)

    def get_algorithm_family(self, algo_name: str) -> Optional[str]:
        """Return algorithm family from spec when matched (e.g. SHA-2, HMAC, ECDH)."""
        m = self.match_algorithm(algo_name)
        if m:
            return m[0]
        return ALGORITHM_FAMILY_FALLBACK.get(
            algo_name, ALGORITHM_FAMILY_FALLBACK.get(algo_name.upper())
        )

    def get_elliptic_curve(self, algo_name: str) -> Optional[str]:
        """Return canonical ellipticCurve (family/curvename) when algo references a curve."""
        return match_elliptic_curve(algo_name, self._curve_map)

    def nist_quantum_level(self, category: str, algo_name: str) -> int:
        """Return NIST quantum security level. PQC = 5, classic = 0–3."""
        match = self.match_algorithm(algo_name)
        if match:
            _family, _primitive, is_pqc = match
            if is_pqc:
                return 5
        # Classic heuristics
        if "MD5" in algo_name.upper():
            return 0
        if "SHA" in algo_name.upper() or "SHA256" in algo_name.upper():
            return 3
        if "128" in algo_name and "AES" in algo_name.upper():
            return 1
        if "256" in algo_name or "384" in algo_name or "512" in algo_name:
            return 3
        return 0
