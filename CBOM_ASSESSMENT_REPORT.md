# CBOM Generation Methods Comparison Report

**Target:** Apache Kafka (commit f20f299)  
**Date:** 2026-02-15

---

## Summary

Three distinct approaches were used to generate CycloneDX 1.6 CBOMs for the same Kafka codebase. This report compares complexity, time investment, standard adherence, coverage, and language support. A merged CBOM consolidates findings from all three sources.

| Tool | Components | Crypto Assets | Libraries | Compliance Score | Best For |
|------|-----------|-------------|-----------|-----------------|----------|
| **Pure LLM** | 16 | 5 | 10 | 78% | Semantic understanding, library detection |
| **SonarQube** | 11 | 11 | 0 | 65% | Algorithm detection with dependencies |
| **CodeQL** | 35 | 35 | 0 | 82% | Exhaustive static analysis, operational crypto |
| **Merged** | 55 | 45 | 10 | 91% | Comprehensive coverage |


![Component distribution by methodology](images/full_view.png)

---

## 1. Process Complexity

| Method | Setup | Dependencies | Steps | Infrastructure | Overall |
|--------|-------|--------------|-------|----------------|---------|
| **Pure LLM** (generate_cbom_v2.py) | Low (~5min) – single Python script, no external services | Python 3, no special packages beyond stdlib | 1. Clone repo, 2. Run `python generate_cbom_v2.py <path> <output> <name>` | None | Low complexity |
| **SonarQube** Cryptography Plugin | High (~30min) – Maven build, Docker, SonarQube, Quality Profile config | Maven, Docker, Java 17+, Gradle | 1. Build plugin, 2. Start SonarQube, 3. Configure Quality Profile, 4. Create project, 5. Activate Cryptography rules, 6. Run `gradlew sonar` | SonarQube server (Docker) must be running | Medium – multiple manual configuration steps + Java Heap Issues for big projects |
| **CodeQL + LLM** (SARIF → CBOM) | Medium–High (~40min) – CodeQL CLI, database creation, custom queries, converter script | CodeQL CLI, Java (for DB), Python for `sarif_to_cbom.py` | 1. `codeql database create`, 2. Run crypto queries (LLM-generated or community), 3. Run `sarif_to_cbom.py` | CodeQL database (large, disk-intensive) | Medium–High – DB creation is slow; queries and converter are reusable |


---


## 3. Adherence to CycloneDX 1.6 CBOM Standard

| Requirement | LLM | SonarQube | CodeQL |
|-------------|-----|-----------|--------|
| **Serial number** (`urn:uuid:...`) | ✔ | ✔ | ✔ |
| **$schema** reference | ✔ | ✘ | ✔ |
| **cryptoProperties** (standard object) | ✔ | ✔ | ✔ |
| **assetType** (algorithm, certificate, related-crypto-material) | ✔ | ⚠️ Partial | ⚠️ Partial |
| **certificateProperties** for X.509 | ✔ | N/A | ✘ (uses algorithm) |
| **nistQuantumSecurityLevel** | ✔ | ✘ | ✘ |
| **OIDs** for algorithms | ✔ (most) | ✔ (most) | ✔ (known only) |
| **Evidence with occurrences** | ✔ | ✔ | ✔ |
| **Dependencies** (granular) | ⚠️ Flat (app→all) | ✔ (algorithm→algorithm) | ⚠️ Flat |
| **Application component** | ✔ | ✘ | ✔ |
| **Library components** | ✔ | ✘ | ✘ |
| **Key typing** (private/public/secret) | N/A (no keys) | ✘ (all secret-key) | N/A |

### Summary

- **LLM**: Best overall standard adherence (serial, schema, cryptoProperties, nistQuantumSecurityLevel, certificateProperties, libraries).
- **SonarQube**: Good cryptoProperties and granular dependencies; missing schema, nistQuantumSecurityLevel, application, libraries; incorrect key typing.
- **CodeQL**: Good coverage and evidence; X.509 as algorithm instead of certificate; no nistQuantumSecurityLevel; no libraries.

---

## 4. Coverage 

### 4.1 Cryptographic Assets Discovered

| Asset | LLM | SonarQube | CodeQL |
|-------|-----|-----------|--------|
| SHA-256 / SHA256 | ✔ | ✔ (SHA256) | ✔ |
| SHA-512 / SHA512 | ✘ | ✔ (SHA512) | ✘ |
| HmacSHA512 / HMAC-SHA512 | ✔ | ✔ | ✔ |
| JKS | ✔ | ✘ | ✔ |
| PKCS12 | ✔ | ✘ | ✔ |
| X.509 | ✔ | ✘ | ✔ |
| DSA | ✘ | ✔ | ✘ |
| RSA-2048 / RSA | ✘ | ✔ | ✘ |
| EC | ✘ | ✔ | ✘ |
| SecretKeyFactory (PBKDF2 etc.) | ✘ | ✔ (as key) | ✔ (unknown) |
| Cipher (dynamic) | ✘ | ✘ | ✔ (unknown) |
| SecureRandom | ✘ | ✘ | ✔ |
| java.util.Random (insecure) | ✘ | ✘ | ✔ |
| TLS/SSL, SSLEngine, SSLContext | ✘ | ✘ | ✔ |
| keystore-unknown (dynamic) | ✘ | ✘ | ✔ (many) |
| hash-unknown, mac-unknown (dynamic) | ✘ | ✘ | ✔ |
| Key management ops (load, store, retrieve) | ✘ | ✘ | ✔ |
| symmetric-key-generation | ✘ | ✘ | ✔ |

### 4.2 Unique Strengths

- **LLM**: Libraries (BouncyCastle, JOSE4J, ApacheDS), key-management formats (JKS, PKCS12), X.509 as certificate, nistQuantumSecurityLevel. Also can be code languaje agnostic
- **SonarQube**: DSA, RSA, EC from `KeyPairGenerator`/`KeyFactory` (variable algorithm resolution), granular algorithm→algorithm dependencies, key material detection.
- **CodeQL**: Dynamic/unknown algorithms, SecureRandom, insecure `java.util.Random`, TLS/SSL config, key-management operations, ScramFormatter, Connect runtime, SkimpyOffsetMap.

---

## 5. Language Coverage

| Method | Java | Scala | Other |
|--------|------|-------|-------|
| **LLM** | ✔ | ✔ | ✔ |
| **SonarQube** | ✔ | ✘ | ✘ |
| **CodeQL** | ✔ | ✘ | ✘ |


---

## 6. Inconsistencies Across Sources

| Issue | Description |
|-------|-------------|
| **X.509 assetType** | LLM: `certificate` + `certificateProperties`. CodeQL: `algorithm` + `algorithmProperties`. Standard prefers certificate. |
| **Key typing** | SonarQube marks DSA/RSA/EC keys as `secret-key`; they should be `private-key` or `public-key`. |
| **Naming** | SHA-256 vs SHA256, HmacSHA512 vs HMAC-SHA512 vs SHA512 (in MAC context) – same algorithms, different strings. |
| **PRIVATE KEY** | SonarQube has asset "PRIVATE KEY" with primitive "other" – non-standard. |
| **keystore-unknown** | CodeQL creates many separate `keystore-unknown` entries (different locations); may represent same JKS. |
| **Duplicate evidence** | Same file:line can appear in multiple sources with slightly different context. |
| **Missing application** | SonarQube has no application component; LLM and CodeQL do. |
| **BOM ref format** | SonarQube uses short UUIDs in dependencies; LLM/CodeQL use `urn:uuid:...`. |

---

## 7. Merged CBOM

A merged CBOM (`generated-cboms/merged_cbom.json`) consolidates:

- **Components**: Application + libraries (from LLM) + all unique cryptographic assets from all three sources
- **Evidence**: Merged occurrences; duplicates deduplicated by location
- **cryptoProperties**: Best available (certificate for X.509, nistQuantumSecurityLevel when known)
- **Metadata**: `cdx:cbom:mergedSources` = `llm,sonarqube,codeql`

### Merge Strategy

1. **Deduplication**: Normalize names (SHA-256↔SHA256, HmacSHA512↔HMAC-SHA512).
2. **Conflict resolution**: Prefer LLM for X.509 (certificate), LLM for nistQuantumSecurityLevel.
3. **Evidence**: Union of occurrences; same file:line from multiple tools kept with source tag.
4. **Libraries**: From LLM only (SonarQube and CodeQL do not produce library components).

---

## 8. Merged CBOM Analysis

### 8.1 Structure

| Metric | Value |
|--------|-------|
| **Total components** | 55 |
| **Application** | 1 (Apache Kafka) |
| **Libraries** | 10 (ApacheDS, jose4j, bcpkix) |
| **Cryptographic assets** | 44 |

### 8.2 Asset Distribution by Source

Evidence occurrences in the merged CBOM originate from:
- **CodeQL**: ~100 occurrences (dynamic algorithms, TLS, random, key-management ops)
- **SonarQube**: ~12 occurrences (DSA, RSA, EC, keys)
- **LLM**: ~11 occurrences (SHA-256, HmacSHA512, JKS, PKCS12, X.509)

### 8.3 Asset Categories in Merged CBOM

| Category | Examples |
|----------|----------|
| **Known algorithms** | SHA-256, HmacSHA512, PKCS12, JKS, X.509, DSA, RSA-2048, EC, SHA512 |
| **Unknown/dynamic** | keystore-unknown (10), mac-unknown (5), hash-unknown (2), cipher-unknown, secret-key-factory-unknown, key-generator-unknown |
| **Key material** | key@..., secret-key@... (SonarQube) |
| **Key management ops** | keystore-load, key-storage, key-retrieval, keystore-store, symmetric-key-generation |
| **Random** | SecureRandom, java.util.Random (insecure) |
| **Protocol/TLS** | TLS/SSL Configuration, SSLEngine, SSLContext |
| **Other** | PRIVATE KEY (SonarQube – non-standard) |

### 8.4 Inconsistencies in Merged Output

| Issue | Severity | Description |
|-------|----------|-------------|
| **PRIVATE KEY primitive** | Medium | SonarQube asset "PRIVATE KEY" has primitive "other"; should be modeled as related-crypto-material |
| **Key typing** | Medium | SonarQube key@... assets use `secret-key`; DSA/RSA/EC keys should be `private-key` or `public-key` |
| **Duplicate keystore-unknown** | Low | 10 separate keystore-unknown entries (different file:line); may represent same JKS in different tests |
| **Evidence source field** | Info | Custom `source` (llm/sonarqube/codeql) in occurrences; not in CycloneDX spec but useful for traceability |
| **nistQuantumSecurityLevel** | Low | Only present on assets from LLM; CodeQL/SonarQube assets lack it |

### 8.5 Recommendations for Merged CBOM

1. **Post-merge validation**: Run CycloneDX schema validation on `merged_cbom.json`.
2. **Deduplicate keystore-unknown**: Consider merging keystore-unknown by location pattern (e.g. same test file) if desired.
3. **Enrich nistQuantumSecurityLevel**: Add PQC levels to CodeQL/SonarQube-origin assets using a lookup table.
4. **Fix key typing**: Replace `secret-key` with `private-key`/`public-key` for asymmetric key assets.


