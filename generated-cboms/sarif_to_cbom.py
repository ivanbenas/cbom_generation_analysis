#!/usr/bin/env python3
"""
Convert CodeQL crypto-results.sarif to CycloneDX 1.6 exhaustive CBOM.
Adheres strictly to CycloneDX 1.6 specification.
"""

import json
import re
import uuid
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path

from crypto_defs_loader import CryptographyDefs


def extract_algorithm_from_message(msg: str, rule_id: str) -> tuple[str | None, str | None]:
    """Extract algorithm name and category from SARIF message."""
    if not msg:
        return None, None

    # Pattern: "Cryptographic <category> algorithm: '<name>'"
    patterns = [
        (r"Cryptographic hash algorithm: '([^']+)'", "hash"),
        (r"Cryptographic mac algorithm: '([^']+)'", "mac"),
        (r"Cryptographic keystore algorithm: '([^']+)'", "keystore"),
        (r"Cryptographic certificate-factory algorithm: '([^']+)'", "certificate"),
        (r"Cryptographic secret-key-factory algorithm: '([^']+)'", "secret-key-factory"),
        (r"Cryptographic cipher algorithm: '([^']+)'", "cipher"),
        (r"Cryptographic key-generator algorithm: '([^']+)'", "key-generator"),
        (r"Cryptographic keypair-generator algorithm: '([^']+)'", "keypair-generator"),
        (r"Cryptographic signature algorithm: '([^']+)'", "signature"),
    ]

    for pattern, category in patterns:
        m = re.search(pattern, msg, re.IGNORECASE)
        if m:
            return m.group(1).strip(), category

    # Key management
    if "key-management" in rule_id:
        m = re.search(r"Key management operation: ([a-z\-]+)", msg)
        if m:
            return m.group(1), "key-management"
        return msg, "key-management"

    # Random generation
    if "random-generation" in rule_id:
        if "SecureRandom" in msg:
            return "SecureRandom", "random"
        if "Random" in msg:
            return "java.util.Random", "random-insecure"
        return msg, "random"

    # TLS configuration
    if "tls-configuration" in rule_id:
        m = re.search(r"TLS/SSL ([^:]+) configuration: '([^']*)'", msg)
        if m:
            return m.group(1).strip(), "tls-configuration"
        return "TLS/SSL", "tls-configuration"

    return None, None


def primitive_from_category(category: str) -> str:
    """Map category to CycloneDX primitive."""
    mapping = {
        "hash": "hash",
        "mac": "mac",
        "keystore": "key-management",
        "certificate": "certificate",
        "secret-key-factory": "key-derivation",
        "cipher": "block-cipher",
        "key-generator": "key-generation",
        "keypair-generator": "key-generation",
        "signature": "signature",
        "key-management": "key-management",
        "random": "random",
        "random-insecure": "random",
        "tls-configuration": "protocol",
    }
    return mapping.get(category, "other")


def get_oid(algorithm: str) -> str | None:
    """Get OID for algorithm from cryptography-defs.json (elliptic curves + fallbacks)."""
    return CryptographyDefs.get().get_oid(algorithm)


def parse_sarif(sarif_path: str) -> dict:
    """Parse SARIF file and return structured data."""
    with open(sarif_path, encoding="utf-8") as f:
        return json.load(f)


def build_cbom(sarif_data: dict) -> dict:
    """Build CycloneDX 1.6 CBOM from SARIF data."""
    run = sarif_data["runs"][0]
    tool = run.get("tool", {}).get("driver", {})
    results = run.get("results", [])

    # Group results by algorithm/category for deduplication
    assets: dict[str, dict] = {}  # key -> {name, category, occurrences, rule_id}

    for result in results:
        msg = result.get("message", {}).get("text", "")
        rule_id = result.get("ruleId", "")

        algo_name, category = extract_algorithm_from_message(msg, rule_id)
        if not algo_name:
            continue

        # Create unique key (handle dynamic/unknown)
        if "dynamic" in algo_name.lower() or "unknown" in algo_name.lower():
            key = f"{category}:{algo_name}:{result.get('partialFingerprints', {}).get('primaryLocationLineHash', uuid.uuid4().hex[:16])}"
        else:
            key = f"{category}:{algo_name}"

        if key not in assets:
            assets[key] = {
                "name": algo_name if algo_name not in ("dynamic/unknown", "dynamic") else f"{category}-unknown",
                "category": category,
                "occurrences": [],
                "rule_id": rule_id,
            }

        # Extract location
        for loc in result.get("locations", []):
            phys = loc.get("physicalLocation", {})
            artifact = phys.get("artifactLocation", {})
            region = phys.get("region", {})
            context_region = phys.get("contextRegion", {})

            occurrence = {
                "location": artifact.get("uri", ""),
                "line": region.get("startLine"),
                "endLine": region.get("endLine"),
                "offset": region.get("startColumn", 0),
                "endOffset": region.get("endColumn"),
                "message": msg,
            }

            if context_region and "snippet" in context_region:
                snippet = context_region["snippet"].get("text", "")
                if snippet and len(snippet) < 500:
                    occurrence["additionalContext"] = snippet.strip()
                else:
                    occurrence["additionalContext"] = msg
            else:
                occurrence["additionalContext"] = msg

            assets[key]["occurrences"].append(occurrence)

    # Build components
    components = []
    main_ref = "urn:uuid:" + str(uuid.uuid4())
    dep_refs = []

    for key, asset in assets.items():
        bom_ref = "urn:uuid:" + str(uuid.uuid4())
        dep_refs.append(bom_ref)

        name = asset["name"]
        category = asset["category"]
        occurrences = asset["occurrences"]

        # Build evidence
        evidence_occurrences = []
        for occ in occurrences:
            eo = {
                "location": occ["location"],
                "line": occ.get("line"),
            }
            if occ.get("offset") is not None:
                eo["offset"] = occ["offset"]
            if occ.get("additionalContext"):
                eo["additionalContext"] = occ["additionalContext"][:1000]
            if occ.get("endLine"):
                eo["endLine"] = occ["endLine"]
            if occ.get("endOffset") is not None:
                eo["endOffset"] = occ["endOffset"]
            evidence_occurrences.append(eo)

        component = {
            "type": "cryptographic-asset",
            "bom-ref": bom_ref,
            "name": name,
            "description": f"Cryptographic asset detected by CodeQL: {category}",
            "evidence": {
                "occurrences": evidence_occurrences,
            },
        }

        # Add cryptoProperties
        primitive = primitive_from_category(category)
        crypto_props = {"assetType": "algorithm"}
        # NIST quantum security level (PQC = 5)
        crypto_props["nistQuantumSecurityLevel"] = CryptographyDefs.get().nist_quantum_level(
            category, name
        )

        if category in ("hash", "mac", "cipher", "signature", "key-generator", "keypair-generator"):
            algo_props = {"primitive": primitive, "variant": name.upper()}
            # algorithmFamily from cryptography-defs when matched
            if family := CryptographyDefs.get().get_algorithm_family(name):
                algo_props["algorithmFamily"] = family
            # ellipticCurve when algo references a curve
            if curve := CryptographyDefs.get().get_elliptic_curve(name):
                algo_props["ellipticCurve"] = curve
            # parameterSetIdentifier: check 512/384 before generic SHA (fixes HmacSHA512->256 bug)
            if "SHA512" in name.upper() or "SHA-512" in name:
                algo_props["parameterSetIdentifier"] = "512"
            elif "SHA384" in name.upper() or "SHA-384" in name:
                algo_props["parameterSetIdentifier"] = "384"
            elif "SHA256" in name.upper() or "SHA-256" in name or "SHA" in name:
                algo_props["parameterSetIdentifier"] = "256"
            # Add cryptoFunctions where inferable
            if category == "hash":
                algo_props["cryptoFunctions"] = ["digest"]
            elif category == "mac":
                algo_props["cryptoFunctions"] = ["authenticate"]
            elif category in ("key-generator", "keypair-generator"):
                algo_props["cryptoFunctions"] = ["keygen"]
            crypto_props["algorithmProperties"] = algo_props
        elif category == "keystore":
            algo_props = {"primitive": "key-management", "variant": name}
            if family := CryptographyDefs.get().get_algorithm_family(name):
                algo_props["algorithmFamily"] = family
            crypto_props["algorithmProperties"] = algo_props
        elif category == "certificate":
            algo_props = {"primitive": "certificate", "variant": name}
            if family := CryptographyDefs.get().get_algorithm_family(name):
                algo_props["algorithmFamily"] = family
            crypto_props["algorithmProperties"] = algo_props
        elif category == "key-management":
            crypto_props["assetType"] = "related-crypto-material"
            crypto_props["relatedCryptoMaterialProperties"] = {"type": "key-management"}
        elif category in ("random", "random-insecure"):
            algo_props = {"primitive": "random", "variant": name}
            if family := CryptographyDefs.get().get_algorithm_family(name):
                algo_props["algorithmFamily"] = family
            crypto_props["algorithmProperties"] = algo_props
        elif category == "tls-configuration":
            algo_props = {"primitive": "protocol", "variant": name}
            if family := CryptographyDefs.get().get_algorithm_family(name):
                algo_props["algorithmFamily"] = family
            crypto_props["algorithmProperties"] = algo_props
        else:
            algo_props = {"primitive": primitive, "variant": name}
            if family := CryptographyDefs.get().get_algorithm_family(name):
                algo_props["algorithmFamily"] = family
            if curve := CryptographyDefs.get().get_elliptic_curve(name):
                algo_props["ellipticCurve"] = curve
            crypto_props["algorithmProperties"] = algo_props

        oid = get_oid(name)
        if oid:
            crypto_props["oid"] = oid

        component["cryptoProperties"] = crypto_props

        # Add properties for taxonomy
        component["properties"] = [
            {"name": "cdx:crypto:source", "value": "CodeQL"},
            {"name": "cdx:crypto:ruleId", "value": asset["rule_id"]},
            {"name": "cdx:crypto:category", "value": category},
            {"name": "cdx:crypto:occurrenceCount", "value": str(len(occurrences))},
        ]

        components.append(component)

    # Build main application component
    component_ref = "urn:uuid:" + str(uuid.uuid4())
    main_component = {
        "type": "application",
        "bom-ref": component_ref,
        "name": "Apache Kafka",
        "version": "trunk",
        "description": "Cryptographic Bill of Materials derived from CodeQL analysis",
    }

    # Metadata
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tool_name = tool.get("name", "CodeQL")
    tool_org = tool.get("organization", "GitHub")
    tool_version = tool.get("version") or tool.get("semanticVersion", "unknown")

    # External reference to source
    external_refs = [
        {
            "type": "other",
            "url": "file:///crypto-results.sarif",
            "comment": "Source SARIF file from CodeQL cryptographic analysis",
        }
    ]

    cbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "externalReferences": external_refs,
        "metadata": {
            "timestamp": timestamp,
            "lifecycles": [{"phase": "post-build"}],
            "tools": {
                "components": [
                    {
                        "type": "library",
                        "bom-ref": "urn:uuid:" + str(uuid.uuid4()),
                        "name": tool_name,
                        "version": tool_version,
                        "author": tool_org,
                        "description": "Static analysis tool that generated the crypto findings",
                    }
                ]
            },
            "component": main_component,
            "manufacturer": {
                "name": tool_org,
            },
            "properties": [
                {"name": "cdx:cbom:source", "value": "crypto-results.sarif"},
                {"name": "cdx:cbom:analysis:type", "value": "exhaustive"},
                {"name": "cdx:cbom:analysis:tool", "value": f"{tool_name} {tool_version}"},
                {"name": "cdx:cbom:componentCount", "value": str(len(components))},
            ],
        },
        "components": [main_component] + components,
        "dependencies": [
            {
                "ref": component_ref,
                "dependsOn": dep_refs,
            }
        ],
    }

    return cbom


def main():
    import sys

    sarif_path = sys.argv[1] if len(sys.argv) > 1 else "crypto-results.sarif"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "cbom-from-sarif.json"

    if not Path(sarif_path).exists():
        print(f"Error: {sarif_path} not found")
        sys.exit(1)

    print(f"Parsing {sarif_path}...")
    sarif_data = parse_sarif(sarif_path)
    print(f"Building CycloneDX 1.6 CBOM...")
    cbom = build_cbom(sarif_data)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cbom, f, indent=2, ensure_ascii=False)

    print(f"CBOM written to {output_path}")
    print(f"  - Components: {len(cbom['components'])}")
    print(f"  - Total cryptographic assets: {len(cbom['components']) - 1}")


if __name__ == "__main__":
    main()
