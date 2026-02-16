#!/usr/bin/env python3
"""
Merge multiple CycloneDX 1.6 CBOM files into a single comprehensive CBOM.
Resolves conflicts (e.g., X.509 as certificate), deduplicates assets,
and consolidates evidence from all sources.
"""

import json
import uuid
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

# Normalize algorithm names for deduplication
NAME_ALIASES = {
    "SHA256": "SHA-256",
    "SHA-256": "SHA-256",
    "HMAC-SHA512": "HmacSHA512",
    "HmacSHA512": "HmacSHA512",
    "SHA512": "SHA-512",  # when used as hash
}


def normalize_name(name: str, category: str) -> str:
    """Normalize algorithm name for deduplication."""
    n = name.strip()
    if n in NAME_ALIASES:
        return NAME_ALIASES[n]
    if "SHA256" in n.upper() and "SHA-256" not in n:
        return "SHA-256"
    if "HMACSHA512" in n.upper() or "HMAC-SHA512" in n.upper():
        return "HmacSHA512"
    return n


def make_occurrence_key(occ: dict) -> str:
    """Create key for deduplicating occurrences."""
    loc = occ.get("location", "")
    line = occ.get("line")
    offset = occ.get("offset")
    return f"{loc}:{line}:{offset}"


def merge_occurrences(occurrences_list: list, source: str) -> list:
    """Merge and deduplicate occurrences, tagging with source."""
    seen = set()
    merged = []
    for occ in occurrences_list:
        k = make_occurrence_key(occ)
        if k in seen:
            continue
        seen.add(k)
        o = {k: v for k, v in occ.items() if v is not None}
        o["source"] = source
        merged.append(o)
    return merged


def build_asset_key(comp: dict) -> str:
    """Build canonical key for an asset (for deduplication)."""
    name = comp.get("name", "")
    cp = comp.get("cryptoProperties", {})
    at = cp.get("assetType", "algorithm")
    # X.509 is always certificate for deduplication
    if "X.509" in name.upper() or (cp.get("certificateProperties") and "X.509" in str(cp.get("certificateProperties", {}).get("format", ""))):
        return "certificate:X.509"
    ap = cp.get("algorithmProperties", cp.get("certificateProperties", cp.get("relatedCryptoMaterialProperties", {})))
    prim = ap.get("primitive", "") if isinstance(ap, dict) else ""
    rcm = cp.get("relatedCryptoMaterialProperties", {})
    rcm_type = rcm.get("type", "") if isinstance(rcm, dict) else ""
    if at == "related-crypto-material":
        return f"rcm:{rcm_type}:{name}"
    if "unknown" in name.lower() or "dynamic" in name.lower():
        return f"{at}:{name}:{id(comp)}"  # Keep unknowns separate by component id
    return f"{at}:{normalize_name(name, prim)}:{prim}"


def load_cbom(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def extract_components(cbom: dict, source: str) -> list:
    """Extract components with source tag."""
    comps = cbom.get("components", [])
    out = []
    for c in comps:
        c = c.copy()
        c["_source"] = source
        out.append(c)
    return out


def merge_assets(assets_by_key: dict) -> list:
    """Merge assets with same key; resolve conflicts."""
    merged_components = []
    for key, candidates in assets_by_key.items():
        # Prefer: LLM > SonarQube > CodeQL for conflict resolution
        ordered = sorted(candidates, key=lambda x: (0 if x["_source"] == "llm" else 1 if x["_source"] == "sonarqube" else 2))
        base = ordered[0].copy()
        del base["_source"]

        # Merge evidence from all
        all_occs = []
        for c in ordered:
            occs = c.get("evidence", {}).get("occurrences", [])
            all_occs.extend(merge_occurrences(occs, c["_source"]))

        if all_occs:
            base["evidence"] = {"occurrences": all_occs}

        # Conflict resolution for cryptoProperties
        cp = base.get("cryptoProperties", {})
        for c in ordered[1:]:
            ocp = c.get("cryptoProperties", {})
            if not cp.get("nistQuantumSecurityLevel") and ocp.get("nistQuantumSecurityLevel") is not None:
                cp["nistQuantumSecurityLevel"] = ocp["nistQuantumSecurityLevel"]
            if not cp.get("oid") and ocp.get("oid"):
                cp["oid"] = ocp["oid"]
            if ocp.get("assetType") == "certificate" and cp.get("assetType") != "certificate":
                cp["assetType"] = "certificate"
                if "certificateProperties" in ocp:
                    cp["certificateProperties"] = ocp["certificateProperties"]
                if "algorithmProperties" in cp:
                    del cp["algorithmProperties"]
            if ocp.get("certificateProperties") and not cp.get("certificateProperties"):
                cp["certificateProperties"] = ocp["certificateProperties"]

        base["cryptoProperties"] = cp
        base["bom-ref"] = "urn:uuid:" + str(uuid.uuid4())
        merged_components.append(base)

    return merged_components


def main():
    base = Path(__file__).parent
    gen = base / "generated-cboms"

    llm_path = gen / "llm_cbom.json"
    sonar_path = gen / "sonarqube_cbom.json"
    codeql_path = gen / "codeql_cbom.json"

    if not llm_path.exists() or not sonar_path.exists() or not codeql_path.exists():
        print("Missing CBOM files. Ensure llm_cbom.json, sonarqube_cbom.json, codeql_cbom.json exist in generated-cboms/")
        return 1

    llm = load_cbom(llm_path)
    sonar = load_cbom(sonar_path)
    codeql = load_cbom(codeql_path)

    # Collect application and libraries from LLM
    app_comp = None
    libraries = []
    for c in llm.get("components", []):
        if c.get("type") == "application":
            app_comp = c.copy()
        elif c.get("type") == "library":
            libraries.append(c.copy())

    # Collect crypto assets from all three
    assets_by_key = defaultdict(list)
    for comp in extract_components(llm, "llm"):
        if comp.get("type") == "cryptographic-asset":
            k = build_asset_key(comp)
            assets_by_key[k].append(comp)

    for comp in extract_components(sonar, "sonarqube"):
        if comp.get("type") == "cryptographic-asset":
            # Skip generic key@... if we have better
            name = comp.get("name", "")
            if name.startswith("key@") or name.startswith("secret-key@"):
                k = f"rcm:secret-key:{name}"
            else:
                k = build_asset_key(comp)
            assets_by_key[k].append(comp)

    for comp in extract_components(codeql, "codeql"):
        if comp.get("type") == "cryptographic-asset":
            k = build_asset_key(comp)
            assets_by_key[k].append(comp)

    # Merge crypto assets
    crypto_assets = merge_assets(assets_by_key)

    # Build final components list
    components = []
    bom_refs = []
    if app_comp:
        app_comp["bom-ref"] = "urn:uuid:" + str(uuid.uuid4())
        components.append(app_comp)
        bom_refs.append(app_comp["bom-ref"])

    for lib in libraries:
        lib["bom-ref"] = "urn:uuid:" + str(uuid.uuid4())
        components.append(lib)
        bom_refs.append(lib["bom-ref"])

    for asset in crypto_assets:
        components.append(asset)
        bom_refs.append(asset["bom-ref"])

    # Build merged BOM
    merged = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "lifecycles": [{"phase": "post-build"}],
            "tools": {
                "components": [
                    {"type": "library", "name": "CBOM Merger", "version": "1.0.0", "description": "Merges LLM, SonarQube, and CodeQL CBOMs"}
                ]
            },
            "component": app_comp,
            "manufacturer": {"name": "CBOM Merger"},
            "properties": [
                {"name": "cdx:cbom:mergedSources", "value": "llm,sonarqube,codeql"},
                {"name": "cdx:cbom:componentCount", "value": str(len(components))},
                {"name": "cdx:git:commit", "value": "f20f2994928fbae53541a2b821515427ee2679a2"},
            ],
        },
        "components": components,
        "dependencies": [
            {"ref": app_comp["bom-ref"], "dependsOn": bom_refs[1:]}  # App depends on all others
        ] if app_comp else [],
    }

    out_path = gen / "merged_cbom.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)

    print(f"Merged CBOM written to {out_path}")
    print(f"  Components: {len(components)} (1 app, {len(libraries)} libraries, {len(crypto_assets)} crypto assets)")
    return 0


if __name__ == "__main__":
    exit(main())
