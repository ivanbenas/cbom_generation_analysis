#!/usr/bin/env python3
"""
CBOM Generator V2 - CycloneDX 1.6 Compliant
Generates exhaustive Cryptographic Bill of Materials from any codebase.
Addresses: serial number, cryptoProperties, assetType, nistQuantumSecurityLevel,
granular dependencies, OIDs, correct key typing (private/public/secret).
"""

import os
import json
import re
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
import hashlib
import uuid

from crypto_defs_loader import CryptographyDefs


class CBOMGeneratorV2:
    def __init__(self, source_path: str, project_name: Optional[str] = None):
        self.source_path = Path(source_path)
        self.project_name = project_name or self._detect_project_name()
        self.crypto_assets: Dict[str, dict] = {}  # key -> asset details
        self.crypto_libraries: Dict[str, dict] = {}
        self.dependency_edges: List[Tuple[str, str]] = []  # (from_ref, to_ref)
        self.bom_refs: Dict[str, str] = {}  # asset_key -> bom-ref (urn:uuid:...)

    def _detect_project_name(self) -> str:
        """Detect project name from path or git."""
        try:
            r = subprocess.run(
                ["git", "-C", str(self.source_path), "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode == 0 and r.stdout:
                url = r.stdout.strip()
                return Path(url).stem.replace(".git", "") or "unknown"
        except Exception:
            pass
        return self.source_path.name or "application"

    def _make_bom_ref(self, key: str) -> str:
        if key not in self.bom_refs:
            self.bom_refs[key] = "urn:uuid:" + str(uuid.uuid4())
        return self.bom_refs[key]

    def _get_oid(self, algo: str) -> Optional[str]:
        return CryptographyDefs.get().get_oid(algo)

    def _nist_quantum_level(self, category: str, algo: str) -> int:
        return CryptographyDefs.get().nist_quantum_level(category, algo)

    def _infer_key_type(self, api_type: str, context: str) -> str:
        """Infer key type from API and context. Returns: private-key, public-key, or secret-key."""
        ctx_lower = (context or "").lower()
        api_lower = api_type.lower()
        if "keypairgenerator" in api_lower or "privatekey" in ctx_lower or "getprivate" in ctx_lower:
            return "private-key"
        if "publickey" in ctx_lower or "getpublic" in ctx_lower:
            return "public-key"
        if "secretkey" in ctx_lower or "secretkeyfactory" in api_lower or "keygenerator" in api_lower:
            return "secret-key"
        if "keyfactory" in api_lower and "rsa" in ctx_lower:
            return "private-key"  # RSA KeyFactory often for private keys
        return "secret-key"  # default

    def _categorize_algorithm(self, algo: str) -> str:
        algo_lower = algo.lower()
        # PQC: ML-KEM (kem), ML-DSA/SLH-DSA (signature), Ed25519/Ed448 (signature)
        if any(x in algo_lower for x in ["ml-kem", "mlkem"]):
            return "kem"
        if any(x in algo_lower for x in ["ml-dsa", "mldsa", "slh-dsa", "slhdsa"]):
            return "signature"
        if any(x in algo_lower for x in ["ed25519", "ed448"]):
            return "signature"
        if any(x in algo_lower for x in ["hmac", "cmac", "gmac"]) and "mac" in algo_lower:
            return "mac"
        if any(x in algo_lower for x in ["aes", "des", "3des", "blowfish", "rc4", "chacha", "camellia"]):
            return "symmetric-encryption"
        if any(x in algo_lower for x in ["rsa", "ec", "ecdsa", "dsa", "dh", "ecdh", "x25519", "x448"]):
            return "asymmetric-encryption"
        if any(x in algo_lower for x in ["sha", "md5", "sha1", "sha2", "sha3", "sha256", "sha512", "blake"]):
            return "hash"
        if any(x in algo_lower for x in ["mac"]):
            return "mac"
        if any(x in algo_lower for x in ["tls", "ssl"]):
            return "protocol"
        if any(x in algo_lower for x in ["jks", "pkcs12", "pem"]):
            return "key-management"
        if "x.509" in algo_lower or "x509" in algo_lower:
            return "certificate"
        return "other"

    def _primitive_from_category(self, cat: str) -> str:
        m = {
            "hash": "hash",
            "mac": "mac",
            "symmetric-encryption": "block-cipher",
            "asymmetric-encryption": "pke",
            "kem": "kem",
            "signature": "signature",
            "key-management": "key-management",
            "certificate": "certificate",
            "protocol": "protocol",
            "other": "other",
        }
        return m.get(cat, "other")

    def _crypto_functions(self, api_type: str, category: str) -> List[str]:
        api = api_type.lower()
        if "messagedigest" in api:
            return ["digest"]
        if "mac" in api:
            return ["tag", "verify"]
        if "cipher" in api:
            return ["encrypt", "decrypt"]
        if "signature" in api:
            return ["sign", "verify"]
        if "keypairgenerator" in api or "keygenerator" in api:
            return ["keygen"]
        if "keyfactory" in api:
            return ["keygen"]
        if "keystore" in api:
            return ["store", "retrieve"]
        if "certificatefactory" in api:
            return ["parse"]
        return ["other"]

    def scan_java_scala(self):
        """Scan Java and Scala files for cryptographic usage."""
        patterns = {
            "Cipher": r'Cipher\.getInstance\(["\']([^"\']+)["\']',
            "MessageDigest": r'MessageDigest\.getInstance\(["\']([^"\']+)["\']',
            "KeyPairGenerator": r'KeyPairGenerator\.getInstance\(["\']([^"\']+)["\']',
            "Signature": r'Signature\.getInstance\(["\']([^"\']+)["\']',
            "KeyFactory": r'KeyFactory\.getInstance\(["\']([^"\']+)["\']',
            "KeyAgreement": r'KeyAgreement\.getInstance\(["\']([^"\']+)["\']',
            "Mac": r'Mac\.getInstance\(["\']([^"\']+)["\']',
            "SecureRandom": r'SecureRandom\.getInstance\(["\']([^"\']+)["\']',
            "KeyStore": r'KeyStore\.getInstance\(["\']([^"\']+)["\']',
            "CertificateFactory": r'CertificateFactory\.getInstance\(["\']([^"\']+)["\']',
            "SecretKeyFactory": r'SecretKeyFactory\.getInstance\(["\']([^"\']+)["\']',
        }

        for ext in ["*.java", "*.scala"]:
            for f in self.source_path.rglob(ext):
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    rel = str(f.relative_to(self.source_path))
                    for api_type, pattern in patterns.items():
                        for m in re.finditer(pattern, content, re.I):
                            algo = (m.group(1) or "").strip()
                            if not algo:
                                continue
                            line = content[: m.start()].count("\n") + 1
                            line_start = content.rfind("\n", 0, m.start()) + 1
                            offset = m.start() - line_start
                            # Get surrounding context for key type inference
                            ctx_start = max(0, m.start() - 200)
                            ctx_end = min(len(content), m.end() + 200)
                            context = content[ctx_start:ctx_end]
                            ctx = f"java.security.{api_type}#getInstance"
                            cat = self._categorize_algorithm(algo)
                            key = f"algo:{algo}:{api_type}"
                            asset_type = "certificate" if api_type == "CertificateFactory" else "algorithm"
                            if key not in self.crypto_assets:
                                self.crypto_assets[key] = {
                                    "name": algo,
                                    "api_type": api_type,
                                    "category": cat,
                                    "asset_type": asset_type,
                                    "usages": [],
                                    "depends_on": [],
                                }
                            self.crypto_assets[key]["usages"].append({
                                "location": rel,
                                "line": line,
                                "offset": offset,
                                "additionalContext": ctx,
                            })
                            # Granular dependencies: Signature depends on hash algorithm
                            if api_type == "Signature" and "SHA" in algo:
                                for hk in ["algo:SHA-256:MessageDigest", "algo:SHA-384:MessageDigest", "algo:SHA-512:MessageDigest"]:
                                    if hk in self.crypto_assets and hk not in self.crypto_assets[key]["depends_on"]:
                                        self.crypto_assets[key]["depends_on"].append(hk)
                                        break
                            # KeyPairGenerator/KeyFactory for RSA/DSA/EC -> produces key pair (private-key)
                            if api_type in ("KeyPairGenerator", "KeyFactory") and any(x in algo.upper() for x in ["RSA", "DSA", "EC", "ECDSA"]):
                                key_type = self._infer_key_type(api_type, context)
                                km_key = f"key:{algo}:{api_type}:{line}"
                                if km_key not in self.crypto_assets:
                                    self.crypto_assets[km_key] = {
                                        "name": f"{algo} key",
                                        "api_type": api_type,
                                        "category": cat,
                                        "asset_type": "related-crypto-material",
                                        "key_type": key_type,
                                        "usages": [{"location": rel, "line": line, "offset": offset, "additionalContext": ctx}],
                                        "depends_on": [key],
                                    }
                            # SecretKeyFactory, KeyGenerator -> secret-key
                            if api_type in ("SecretKeyFactory",) or (api_type == "KeyAgreement"):
                                km_key = f"key:secret:{algo}:{rel}:{line}"
                                if km_key not in self.crypto_assets:
                                    self.crypto_assets[km_key] = {
                                        "name": f"Secret key ({algo})",
                                        "api_type": api_type,
                                        "category": cat,
                                        "asset_type": "related-crypto-material",
                                        "key_type": "secret-key",
                                        "usages": [{"location": rel, "line": line, "offset": offset, "additionalContext": ctx}],
                                        "depends_on": [key],
                                    }
                except Exception:
                    continue

    def scan_gradle(self):
        """Scan Gradle build files for crypto-related dependencies."""
        deps_file = self.source_path / "gradle" / "dependencies.gradle"
        dep_map = {}
        if deps_file.exists():
            try:
                c = deps_file.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'(\w+):\s*["\']([^"\']+)["\']', c):
                    k, v = m.group(1), m.group(2)
                    if ":" in v:
                        dep_map[k] = v
            except Exception:
                pass

        def add_lib(g: str, a: str, v: Optional[str], gf: Path):
            lib_id = f"{g}:{a}"
            if lib_id not in self.crypto_libraries:
                kw = ["crypto", "ssl", "tls", "bouncycastle", "bcprov", "bcpkix", "jose", "jwt", "oauth", "security", "auth", "apacheds"]
                if any(k in g.lower() or k in a.lower() for k in kw):
                    self.crypto_libraries[lib_id] = {"group": g, "name": a, "version": v}

        for gf in list(self.source_path.rglob("build.gradle*")) + list(self.source_path.rglob("**/dependencies.gradle")):
            try:
                c = gf.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'(?:implementation|api|compile|runtime)[\s(]+["\']([^"\']+)["\']', c):
                    dep = m.group(1)
                    if ":" not in dep:
                        continue
                    parts = dep.split(":")
                    if len(parts) >= 2:
                        g, a, v = parts[0], parts[1], parts[2] if len(parts) > 2 else None
                        if v and v.startswith("$"):
                            vk = v.replace("$versions.", "").replace("$", "")
                            v = self._resolve_version(deps_file, vk)
                        add_lib(g, a, v, gf)
                for m in re.finditer(r'dependencies\.(\w+)', c):
                    k = m.group(1)
                    if k in dep_map:
                        v = dep_map[k]
                        parts = v.split(":")
                        if len(parts) >= 2:
                            g, a = parts[0], parts[1]
                            ver = parts[2] if len(parts) > 2 else None
                            if ver and str(ver).startswith("$"):
                                ver = self._resolve_version(deps_file, ver.replace("$versions.", "").replace("$", ""))
                            add_lib(g, a, ver, gf)
                for m in re.finditer(r'libs\.(\w+)', c):
                    k = m.group(1)
                    if k in dep_map:
                        v = dep_map[k]
                        parts = v.split(":")
                        if len(parts) >= 2:
                            g, a = parts[0], parts[1]
                            ver = parts[2] if len(parts) > 2 else None
                            if ver and str(ver).startswith("$"):
                                ver = self._resolve_version(deps_file, ver.replace("$versions.", "").replace("$", ""))
                            add_lib(g, a, ver, gf)
            except Exception:
                continue

    def _resolve_version(self, deps_file: Path, key: str) -> Optional[str]:
        try:
            c = deps_file.read_text(encoding="utf-8", errors="ignore")
            m = re.search(rf'{re.escape(key)}:\s*["\']([^"\']+)["\']', c)
            return m.group(1) if m else None
        except Exception:
            return None

    def scan_maven(self):
        """Scan Maven pom.xml for crypto dependencies."""
        for pom in self.source_path.rglob("pom.xml"):
            try:
                c = pom.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]*)</version>)?", c):
                    g, a, v = m.group(1), m.group(2), m.group(3) or None
                    lib_id = f"{g}:{a}"
                    if lib_id not in self.crypto_libraries:
                        kw = ["crypto", "ssl", "tls", "bouncycastle", "bcprov", "jose", "jwt", "security"]
                        if any(k in g.lower() or k in a.lower() for k in kw):
                            self.crypto_libraries[lib_id] = {"group": g, "name": a, "version": v}
            except Exception:
                continue

    def get_git_info(self) -> Dict:
        try:
            r = subprocess.run(["git", "-C", str(self.source_path), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
            commit = r.stdout.strip() if r.returncode == 0 else None
            r = subprocess.run(["git", "-C", str(self.source_path), "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, timeout=10)
            branch = r.stdout.strip() if r.returncode == 0 else None
            r = subprocess.run(["git", "-C", str(self.source_path), "log", "-1", "--format=%ai"], capture_output=True, text=True, timeout=10)
            last = r.stdout.strip() if r.returncode == 0 else None
            return {"commit": commit, "branch": branch, "last_commit": last}
        except Exception:
            return {"commit": None, "branch": None, "last_commit": None}

    def _build_crypto_properties(self, asset: dict) -> dict:
        """Build standard cryptoProperties object."""
        name = asset["name"]
        cat = asset["category"]
        api = asset["api_type"]
        asset_type = asset.get("asset_type", "algorithm")

        if asset_type == "related-crypto-material":
            key_type = asset.get("key_type", "secret-key")
            return {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {"type": key_type},
                "nistQuantumSecurityLevel": self._nist_quantum_level(cat, name),
            }

        if asset_type == "certificate" or (cat == "certificate" and "X.509" in name.upper()):
            return {
                "assetType": "certificate",
                "certificateProperties": {"format": name},
                "oid": self._get_oid(name),
                "nistQuantumSecurityLevel": 0,
            }

        prim = self._primitive_from_category(cat)
        algo_props = {
            "primitive": prim,
            "variant": name.upper(),
            "cryptoFunctions": self._crypto_functions(api, cat),
        }
        if "512" in name or "SHA512" in name.upper():
            algo_props["parameterSetIdentifier"] = "512"
        elif "384" in name:
            algo_props["parameterSetIdentifier"] = "384"
        elif "SHA" in name or "256" in name:
            algo_props["parameterSetIdentifier"] = "256"
        elif "RSA" in name.upper() or "DSA" in name.upper():
            algo_props["parameterSetIdentifier"] = "2048"

        # algorithmFamily from cryptography-defs when matched
        cd = CryptographyDefs.get()
        if family := cd.get_algorithm_family(name):
            algo_props["algorithmFamily"] = family
        # ellipticCurve when algo references a curve (e.g. ECDH-secp256r1, ECDSA-P256)
        if curve := cd.get_elliptic_curve(name):
            algo_props["ellipticCurve"] = curve

        cp = {
            "assetType": "algorithm",
            "algorithmProperties": algo_props,
            "nistQuantumSecurityLevel": self._nist_quantum_level(cat, name),
        }
        oid = self._get_oid(name)
        if oid:
            cp["oid"] = oid
        return cp

    def generate_cbom(self) -> dict:
        """Generate CycloneDX 1.6 CBOM with all required/optional fields."""
        git = self.get_git_info()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Pre-assign bom-refs so dependencies can resolve
        for key in list(self.crypto_assets.keys()) + [f"lib:{x}" for x in self.crypto_libraries]:
            self._make_bom_ref(key)

        main_ref = "urn:uuid:" + str(uuid.uuid4())
        components = []
        dependencies = []
        dep_map: Dict[str, List[str]] = defaultdict(list)

        # Main application component
        main_comp = {
            "type": "application",
            "bom-ref": main_ref,
            "name": self.project_name,
            "version": "trunk",
            "description": f"Cryptographic Bill of Materials for {self.project_name}",
        }
        components.append(main_comp)
        main_deps = []

        # Library components
        for lib_id, lib in sorted(self.crypto_libraries.items()):
            ref = self._make_bom_ref(f"lib:{lib_id}")
            main_deps.append(ref)
            components.append({
                "type": "library",
                "bom-ref": ref,
                "group": lib["group"],
                "name": lib["name"],
                "version": lib.get("version"),
                "description": "Cryptographic library dependency",
            })

        # Cryptographic asset components with cryptoProperties
        for key, asset in sorted(self.crypto_assets.items()):
            ref = self._make_bom_ref(key)
            main_deps.append(ref)

            occurrences = [
                {
                    "location": u["location"],
                    "line": u["line"],
                    "offset": u.get("offset", 0),
                    "additionalContext": u.get("additionalContext", ""),
                }
                for u in asset["usages"]
            ]

            comp = {
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": asset["name"],
                "description": f"{asset['category']} algorithm via {asset['api_type']}",
                "evidence": {"occurrences": occurrences},
                "cryptoProperties": self._build_crypto_properties(asset),
            }
            components.append(comp)

            for dep_key in asset.get("depends_on", []):
                if dep_key in self.bom_refs:
                    dep_map[ref].append(self.bom_refs[dep_key])

        # Granular dependencies
        dependencies.append({"ref": main_ref, "dependsOn": main_deps})
        for ref, deps in dep_map.items():
            if deps:
                dependencies.append({"ref": ref, "dependsOn": deps})

        cbom = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "lifecycles": [{"phase": "post-build"}],
                "tools": {
                    "components": [
                        {
                            "type": "library",
                            "bom-ref": "urn:uuid:" + str(uuid.uuid4()),
                            "name": "CBOM Generator V2",
                            "version": "2.0.0",
                            "description": "CycloneDX 1.6 exhaustive CBOM generator",
                        }
                    ]
                },
                "component": main_comp,
                "manufacturer": {"name": "CBOM Generator"},
                "properties": [
                    {"name": "cdx:git:commit", "value": git.get("commit", "unknown")},
                    {"name": "cdx:git:branch", "value": git.get("branch", "unknown")},
                    {"name": "cdx:cbom:analysis:type", "value": "exhaustive"},
                    {"name": "cdx:cbom:componentCount", "value": str(len(components))},
                ],
            },
            "components": components,
            "dependencies": dependencies,
        }
        return cbom

    def scan_all(self):
        """Run all applicable scans."""
        self.scan_java_scala()
        self.scan_gradle()
        self.scan_maven()
        print(f"  Algorithms: {len(self.crypto_assets)}")
        print(f"  Libraries: {len(self.crypto_libraries)}")


def main():
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    out = sys.argv[2] if len(sys.argv) > 2 else "llm_cbom.json"
    name = sys.argv[3] if len(sys.argv) > 3 else None

    if not os.path.exists(path):
        print(f"Error: {path} not found")
        sys.exit(1)

    print(f"CBOM V2: Analyzing {path}")
    gen = CBOMGeneratorV2(path, name)
    gen.scan_all()
    cbom = gen.generate_cbom()

    with open(out, "w", encoding="utf-8") as f:
        json.dump(cbom, f, indent=2, ensure_ascii=False)

    print(f"Written: {out}")
    print(f"  Serial: {cbom['serialNumber']}")
    print(f"  Components: {len(cbom['components'])}")
    print(f"  Dependencies: {len(cbom['dependencies'])}")


if __name__ == "__main__":
    main()
