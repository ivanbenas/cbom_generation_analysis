# CBOM Generation Methods Comparison Report

**Target:** Apache Kafka (commit f20f299)  
**Date:** 2026-02-15

---

## Summary

Three distinct approaches were used to generate CycloneDX 1.6 CBOMs for the same Kafka codebase. This report compares complexity, time investment, standard adherence, coverage, and language support. A merged CBOM consolidates findings from all three sources.

---

## 1. Method Overview

| Method | Tool(s) | Output File | Primary Input |
|--------|---------|-------------|---------------|
| **1. Pure LLM** | `generate_cbom_v2.py` (regex + Gradle parsing) | `generated-cboms/llm_cbom.json` | Source code (Java, Scala) |
| **2. SonarQube Cryptography** | Sonar Cryptography Plugin (IBM) | `generated-cboms/sonarqube_cbom.json` | Java AST via SonarQube |
| **3. CodeQL + LLM** | CodeQL DB + custom crypto queries + `sarif_to_cbom.py` | `generated-cboms/codeql_cbom.json` | SARIF from CodeQL analysis |

---

## 2. Complexity to Get the Result

### 2.1 Pure LLM (generate_cbom_v2.py)

| Aspect | Assessment |
|--------|------------|
| **Setup** | Low – single Python script, no external services |
| **Dependencies** | Python 3, no special packages beyond stdlib |
| **Steps** | 1. Clone repo, 2. Run `python generate_cbom_v2.py <path> <output> <name>` |
| **Infrastructure** | None |
| **Overall** | **Low complexity** – run and done |

### 2.2 SonarQube Cryptography Plugin

| Aspect | Assessment |
|--------|------------|
| **Setup** | High – Maven build, Docker, SonarQube, Quality Profile config |
| **Dependencies** | Maven, Docker, Java 17+, Gradle |
| **Steps** | 1. Build plugin, 2. Start SonarQube, 3. Configure Quality Profile, 4. Create project, 5. Activate Cryptography rules, 6. Run `gradlew sonar`|
| **Infrastructure** | SonarQube server (Docker) must be running |
| **Overall** | **Medium complexity** – multiple manual configuration steps + Java Heap Issues for big projects |

### 2.3 CodeQL + LLM (SARIF → CBOM)

| Aspect | Assessment |
|--------|------------|
| **Setup** | Medium–High – CodeQL CLI, database creation, custom queries, converter script |
| **Dependencies** | CodeQL CLI, Java (for DB), Python for `sarif_to_cbom.py` |
| **Steps** | 1. `codeql database create`, 2. Run crypto queries (LLM-generated or community), 3. Run `sarif_to_cbom.py` |
| **Infrastructure** | CodeQL database (large, disk-intensive) |
| **Overall** | **Medium–High complexity** – DB creation is slow; queries and converter are reusable |

![Setup difficulty by methodology](suppot_docs/methodology-difficulty.png)

*Figure 1: Relative setup difficulty of each methodology (1=Low, 4=High)*

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

![Standard adherence comparison](suppot_docs/standard-adherence.png)

*Figure 2: CycloneDX CBOM standard adherence by methodology*

---

## 4. Time Investment

| Method | Typical Time | Notes |
|--------|--------------|-------|
| **Pure LLM** | &lt; 1 min | Single script run |
| **SonarQube Cryptography** | 8–21 min | Build + scan + analysis |
| **CodeQL + LLM** | 12–40 min | DB creation + queries + conversion |

![Time investment by methodology](suppot_docs/time-investment.png)

*Figure 3: Approximate time investment (minutes) to produce a CBOM*

---

## 5. Coverage by Dimension

### 5.1 Cryptographic Assets Discovered

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

### 5.2 Unique Strengths

- **LLM**: Libraries (BouncyCastle, JOSE4J, ApacheDS), key-management formats (JKS, PKCS12), X.509 as certificate, nistQuantumSecurityLevel. Also can be code languaje agnostic
- **SonarQube**: DSA, RSA, EC from `KeyPairGenerator`/`KeyFactory` (variable algorithm resolution), granular algorithm→algorithm dependencies, key material detection.
- **CodeQL**: Dynamic/unknown algorithms, SecureRandom, insecure `java.util.Random`, TLS/SSL config, key-management operations, ScramFormatter, Connect runtime, SkimpyOffsetMap.

![Component distribution by methodology](suppot_docs/coverage-component-distribution.png)

*Figure 4: Distribution of discovered components (Crypto Assets, Libraries, Applications) per methodology*

---

## 6. Language Coverage

| Method | Java | Scala | Other |
|--------|------|-------|-------|
| **LLM** | ✔ | ✔ | ✔ |
| **SonarQube** | ✔ | ✘ | ✘ |
| **CodeQL** | ✔ | ✘ | ✘ |


---

## 7. Inconsistencies Across Sources

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

## 8. Merged CBOM

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

## 9. Recommendations

| Goal | Recommendation |
|-----|----------------|
| **Fastest result** | Use LLM (`generate_cbom_v2.py`) |
| **Best standard compliance** | Use LLM; optionally augment with SonarQube for algorithm dependencies |
| **Maximum coverage** | Merge all three; CodeQL adds dynamic/unknown, TLS, insecure random |
| **Scala support** | LLM only; extend SonarQube/CodeQL for Scala if needed |

---

## 10. Files Reference

| File | Description |
|------|-------------|
| `generated-cboms/llm_cbom.json` | Pure LLM/regex CBOM |
| `generated-cboms/sonarqube_cbom.json` | SonarQube Cryptography plugin output |
| `generated-cboms/codeql_cbom.json` | CodeQL SARIF → CBOM |
| `generated-cboms/merged_cbom.json` | Merged CBOM from all three |
| `merge_cboms.py` | Script to produce merged CBOM |

---

## 11. Merged CBOM Analysis

### 11.1 Structure

| Metric | Value |
|--------|-------|
| **Total components** | 55 |
| **Application** | 1 (Apache Kafka) |
| **Libraries** | 10 (ApacheDS, jose4j, bcpkix) |
| **Cryptographic assets** | 44 |

### 11.2 Asset Distribution by Source

Evidence occurrences in the merged CBOM originate from:
- **CodeQL**: ~100 occurrences (dynamic algorithms, TLS, random, key-management ops)
- **SonarQube**: ~12 occurrences (DSA, RSA, EC, keys)
- **LLM**: ~11 occurrences (SHA-256, HmacSHA512, JKS, PKCS12, X.509)

### 11.3 Asset Categories in Merged CBOM

| Category | Examples |
|----------|----------|
| **Known algorithms** | SHA-256, HmacSHA512, PKCS12, JKS, X.509, DSA, RSA-2048, EC, SHA512 |
| **Unknown/dynamic** | keystore-unknown (10), mac-unknown (5), hash-unknown (2), cipher-unknown, secret-key-factory-unknown, key-generator-unknown |
| **Key material** | key@..., secret-key@... (SonarQube) |
| **Key management ops** | keystore-load, key-storage, key-retrieval, keystore-store, symmetric-key-generation |
| **Random** | SecureRandom, java.util.Random (insecure) |
| **Protocol/TLS** | TLS/SSL Configuration, SSLEngine, SSLContext |
| **Other** | PRIVATE KEY (SonarQube – non-standard) |

### 11.4 Inconsistencies in Merged Output

| Issue | Severity | Description |
|-------|----------|-------------|
| **PRIVATE KEY primitive** | Medium | SonarQube asset "PRIVATE KEY" has primitive "other"; should be modeled as related-crypto-material |
| **Key typing** | Medium | SonarQube key@... assets use `secret-key`; DSA/RSA/EC keys should be `private-key` or `public-key` |
| **Duplicate keystore-unknown** | Low | 10 separate keystore-unknown entries (different file:line); may represent same JKS in different tests |
| **Evidence source field** | Info | Custom `source` (llm/sonarqube/codeql) in occurrences; not in CycloneDX spec but useful for traceability |
| **nistQuantumSecurityLevel** | Low | Only present on assets from LLM; CodeQL/SonarQube assets lack it |

### 11.5 Recommendations for Merged CBOM

1. **Post-merge validation**: Run CycloneDX schema validation on `merged_cbom.json`.
2. **Deduplicate keystore-unknown**: Consider merging keystore-unknown by location pattern (e.g. same test file) if desired.
3. **Enrich nistQuantumSecurityLevel**: Add PQC levels to CodeQL/SonarQube-origin assets using a lookup table.
4. **Fix key typing**: Replace `secret-key` with `private-key`/`public-key` for asymmetric key assets.


### Lessons Learnt 

1. There is no tool that gives you the "perfect CBOM"
2. LLMs are a must tool for CI/CD CBOM analysis
2. CodeQL and sonarqube are good tools with sound capabilities, but do not give you the complete picture and have limitations on top of the known languaje limitations
3. This kind of benchmarks can help us understand the big picture of the CBOM paradigm and advance in the fastest path (to me LLM repository scanning)
4. All this analysis are static and require further methods to include them in the pipelines for continuous integration. (i.e Rejecting pull request if cryptography is not compliant with policies.)

### Next steps I will follow.
1. Apply the methodology to other Java and Python codes to check the results and try to get stronger conclusions.
2. Explore the LLM stand alone capability and its integration in SecDevOps.
