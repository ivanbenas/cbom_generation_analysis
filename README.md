# CBOM Generation Benchmark

When we search for software solutions to generate CBOMs from source code, there are not many open source tools, and most of them are limited to just a few languages.
Some of the most known are the [sonar-cryptography plugin](https://github.com/cbomkit/sonar-cryptography?tab=readme-ov-file) and [CodeQL](https://github.blog/security/vulnerability-research/addressing-post-quantum-cryptography-with-codeql/).

This exercise benchmarks these two methods and a pure LLM approach for generating Cryptographic Bills of Materials (CBOMs) for the same codebase, comparing complexity, coverage, and CycloneDX 1.6 standard adherence.

**Benchmark target:** Apache Kafka (commit f20f299) · **Date:** 2026-02-15

The Kafka project and the fixed commit were chosen together with CycloneDX 1.6 to compare with the SonarQube cryptography plugin generation. This report compares complexity, time investment, standard adherence, coverage, and language support. A merged CBOM consolidates findings from all three sources.

| Tool | Components | Crypto Assets | Libraries | Compliance Score | Best For |
|------|-----------|-------------|-----------|-----------------|----------|
| **Pure LLM** | 16 | 5 | 10 | 78% | Semantic understanding, library detection |
| **SonarQube** | 11 | 11 | 0 | 65% | Algorithm detection with dependencies |
| **CodeQL** | 35 | 35 | 0 | 82% | Exhaustive static analysis, operational crypto |
| **Merged CBOM** | 55 | 45 | 10 | 91% | Comprehensive coverage |

<p align="center">
  <img src="images/full_view.png" alt="Component distribution by methodology" width="800"/>
</p>

---

### Process Complexity

| Method | Setup   | Dependencies |  Infrastructure | Overall |
|--------|---------|--------------|----------------|---------|
| **Pure LLM**  | Low (~5min) | Python 3.10+|  None | Low complexity |
| **SonarQube** Cryptography Plugin | High (~30min)  | Maven, Docker, Java 17+, Gradle | SonarQube server (Docker) must be running | Medium – multiple manual configuration steps + Java Heap Issues for big projects |
| **CodeQL + LLM** (SARIF → CBOM) | Medium–High (~40min)  | CodeQL CLI, Java (for DB), Python for `sarif_to_cbom.py` | CodeQL database (large, disk-intensive) | Medium–High – DB creation  slow; queries and converter are reusable |


---


## 1. Pure LLM CBOM Analysis

### Metadata Quality
```json
{
  "timestamp": "2026-02-16T07:00:37Z",
  "lifecycles": [{"phase": "post-build"}],
  "tools": {
    "components": [{
      "name": "CBOM Generator V2",
      "version": "2.0.0",
      "description": "CycloneDX 1.6 exhaustive CBOM generator"
    }]
  },
  "properties": [
    {"name": "cdx:git:commit", "value": "f20f299..."},
    {"name": "cdx:cbom:analysis:type", "value": "exhaustive"},
    {"name": "cdx:cbom:componentCount", "value": "16"}
  ]
}
```

### Component Breakdown
| Type | Count | Examples |
|------|-------|----------|
| `application` | 1 | kafka (root) |
| `library` | 10 | apacheds-core-api, jose4j, bcpkix-jdk18on |
| `cryptographic-asset` | 5 | HmacSHA512, JKS, PKCS12, SHA-256, X.509 |

### Cryptographic Assets Detail
| Asset | Primitive | OID | NIST Quantum Level | Evidence Quality |
|-------|-----------|-----|-------------------|------------------|
| HmacSHA512 | mac | 1.2.840.113549.2.11 | 3 | High (line 136) |
| JKS | key-management | - | 0 | Medium (3 locations) |
| PKCS12 | key-management | 1.2.840.113549.1.12.1.1 | 0 | High (5 locations) |
| SHA-256 | hash | 2.16.840.1.101.3.4.2.1 | 3 | High (line 183) |
| X.509 | certificate | 1.3.6.1.5.5.7.1.1 | 0 | Medium (line 497) |

### ✔ Strengths
1. **Library Detection Excellence**: Identifies 10 cryptographic libraries with full PURL-style coordinates (group:name:version)
2. **Semantic Descriptions**: Rich human-readable descriptions ("mac algorithm via Mac", "hash algorithm via MessageDigest")
3. **OID Compliance**: 80% of assets include proper Object Identifiers
4. **NIST Quantum Security**: Properly annotates quantum resistance levels (0-3 scale)
5. **Evidence Structure**: Clean occurrence tracking with method signatures
6. **Dependency Graph**: Complete dependency tree from root application

### ✘ Weaknesses
1. **Limited Crypto Coverage**: Only 5 cryptographic assets vs. 35 in CodeQL
2. **No Test Code Differentiation**: Does not distinguish test vs. production code
3. **Missing Operational Crypto**: No detection of TLS configurations, random generators, key management operations
4. **Variant Inconsistencies**: Uses "HMACSHA512" vs. standard "HmacSHA512"
5. **Primitive Classification**: Limited to basic primitives (mac, hash, key-management, certificate)

---

## 2. SonarQube CBOM Analysis

### Metadata Quality
```json
{
  "timestamp": "2026-02-15T19:04:25Z",
  "tools": {
    "services": [{
      "provider": {"name": "IBM"},
      "name": "Sonar Cryptography Plugin",
      "version": "2.0.0-SNAPSHOT"
    }]
  }
}
```

### Component Breakdown
| Type | Count | Examples |
|------|-------|----------|
| `cryptographic-asset` | 11 | SHA256, DSA, HMAC-SHA512, RSA-2048, EC |
| `related-crypto-material` | 3 | secret-key@..., key@... |

### Cryptographic Assets Detail
| Asset | Primitive | Parameter Set | OID | Issues |
|-------|-----------|---------------|-----|--------|
| SHA256 | hash | 256 | ✔ 2.16.840.1.101.3.4.2.1 | Missing hyphen in name |
| DSA | signature | 2048 | ✔ 1.2.840.10040.4.1 | Good |
| RSA-2048 | pke | 2048 | ✔ 1.2.840.113549.1.1.1 | Good |
| HMAC-SHA512 | mac | - | ✔ 1.2.840.113549.2.11 | Inconsistent naming |
| EC | pke | - | ✘ Missing | No curve specified |
| PRIVATE KEY | other | - | ✘ Missing | Vague classification |

### ✔ Strengths
1. **Algorithm Diversity**: Detects asymmetric (DSA, RSA, EC) and symmetric primitives
2. **Parameter Awareness**: Captures key sizes (2048) and digest lengths (256, 512)
3. **OID Coverage**: 70% of algorithms include OIDs
4. **Dependency Modeling**: Tracks relationships between keys and algorithms
5. **Java Method Signatures**: Detailed `additionalContext` with full method descriptors

### ✘ Weaknesses
1. **No Libraries**: Completely misses all 10 cryptographic libraries detected by LLM
2. **Legacy Tool Format**: Uses deprecated `tools.services` instead of `tools.components`
3. **Missing Metadata**: No lifecycle phase, git commit, or analysis type properties
4. **Inconsistent Naming**: "SHA256" vs "SHA-256", "HMAC-SHA512" vs "HmacSHA512"
5. **Generic Key Names**: Uses UUID-based names like "key@f816cd9e..." instead of descriptive identifiers
6. **No NIST Quantum Levels**: Missing quantum security annotations
7. **Limited Evidence**: Single occurrence per asset, no endOffset tracking

---

## 3. CodeQL CBOM Analysis

### Metadata Quality
```json
{
  "timestamp": "2026-02-16T07:18:32Z",
  "lifecycles": [{"phase": "post-build"}],
  "tools": {
    "components": [{
      "name": "CodeQL",
      "version": "2.23.8",
      "author": "GitHub"
    }]
  },
  "externalReferences": [{
    "type": "other",
    "url": "file:///crypto-results.sarif",
    "comment": "Source SARIF file"
  }],
  "properties": [
    {"name": "cdx:cbom:source", "value": "crypto-results.sarif"},
    {"name": "cdx:cbom:analysis:type", "value": "exhaustive"},
    {"name": "cdx:cbom:componentCount", "value": "35"}
  ]
}
```

### Component Breakdown
| Category | Count | Examples |
|----------|-------|----------|
| **Algorithms** | 15 | hash-unknown, mac-unknown, SHA-256, PKCS12, X.509 |
| **Key Management** | 12 | keystore-load, key-storage, key-retrieval, keystore-store, symmetric-key-generation |
| **Random Generation** | 2 | SecureRandom, java.util.Random |
| **TLS/SSL** | 3 | TLS/SSL Configuration, SSLEngine, SSLContext |
| **Test Assets** | 3 | Various mac-unknown in test files |

### Cryptographic Assets by Primitive
| Primitive | Count | Assets |
|-----------|-------|--------|
| hash | 3 | hash-unknown (2), SHA-256 |
| mac | 6 | mac-unknown (5), HmacSHA512 |
| key-management | 10 | keystore-unknown (8), JKS, PKCS12 |
| certificate | 1 | X.509 |
| block-cipher | 1 | cipher-unknown |
| key-derivation | 1 | secret-key-factory-unknown |
| key-generation | 1 | key-generator-unknown |
| protocol | 3 | TLS/SSL, SSLEngine, SSLContext |
| random | 2 | SecureRandom, java.util.Random |

### ✔ Strengths
1. **Exhaustive Coverage**: 35 components vs. 16 (LLM) and 11 (SonarQube)
2. **Operational Crypto**: Detects TLS configurations, random generators, key management operations
3. **Security-Aware**: Identifies insecure practices (java.util.Random flagged as "random-insecure")
4. **SARIF Provenance**: Links to source analysis results
5. **Occurrence Counting**: Aggregates multiple findings (e.g., "occurrenceCount": "30" for java.util.Random)
6. **End-to-End Offset**: Complete location tracking with `endOffset` and `endLine`
7. **Rule Attribution**: Every asset includes `cdx:crypto:ruleId` and `cdx:crypto:category`
8. **Test/Production Differentiation**: Clear file path analysis (src/main vs. src/test)

### ✘ Weaknesses
1. **No Libraries**: Like SonarQube, misses library dependencies entirely
2. **Generic Naming**: Many "unknown" variants (hash-unknown, mac-unknown, keystore-unknown)
3. **Over-Classification**: Classifies TLS configurations as "algorithm" instead of "protocol"
4. **Certificate Misclassification**: X.509 marked as `assetType: "algorithm"` instead of `certificate`
5. **NIST Quantum Inconsistency**: Only 3 assets have quantum levels; rest are 0
6. **Primitive Mismatch**: Uses "key-management" as primitive instead of proper categorization

---

## 4. CycloneDX Specification Compliance Matrix

| Requirement | LLM | SonarQube | CodeQL | Merged |
|-------------|-----|-----------|--------|--------|
| **Required Fields** |
| `bomFormat` = "CycloneDX" | ✔ | ✔ | ✔ | ✔ |
| `specVersion` = "1.6" | ✔ | ✔ | ✔ | ✔ |
| `serialNumber` (UUID) | ✔ | ✔ | ✔ | ✔ |
| `version` ≥ 1 | ✔ | ✔ | ✔ | ✔ |
| **Metadata** |
| `timestamp` (ISO 8601) | ✔ | ✔ | ✔ | ✔ |
| `tools` (components/services) | ✔ (components) | ⚠️ (services) | ✔ (components) | ✔ (components) |
| `lifecycles` | ✔ | ✘ | ✔ | ✔ |
| `manufacturer` | ✔ | ✘ | ✔ | ✔ |
| `component` (root) | ✔ | ✘ | ✔ | ✔ |
| `properties` | ✔ | ✘ | ✔ | ✔ |
| **Components** |
| `type` enum compliance | ✔ | ✔ | ⚠️ | ✔ |
| `name` required | ✔ | ✔ | ✔ | ✔ |
| `bom-ref` uniqueness | ✔ | ✔ | ✔ | ✔ |
| `cryptoProperties` | ✔ | ✔ | ✔ | ✔ |
| `evidence.occurrences` | ✔ | ✔ | ✔ | ✔ |
| **CryptoProperties** |
| `assetType` enum | ✔ | ✔ | ⚠️ | ✔ |
| `algorithmProperties.primitive` | ✔ | ✔ | ⚠️ | ✔ |
| `algorithmProperties.variant` | ✔ | ✘ | ✔ | ✔ |
| `algorithmProperties.cryptoFunctions` | ✔ | ✔ | ✘ | ✔ |
| `nistQuantumSecurityLevel` (0-6) | ✔ | ✘ | ⚠️ | ✔ |
| `oid` (when applicable) | 80% | 70% | 30% | 85% |
| **Dependencies** |
| `dependencies` array | ✔ | ✔ | ✔ | ✔ |
| `ref` + `dependsOn` | ✔ | ✔ | ✔ | ✔ |
| **External References** |
| `externalReferences` | ✘ | ✘ | ✔ | ✔ |

---

## 5. Dimensional Analysis

### 5.1 Libraries & Dependencies
| Aspect | Winner | Analysis |
|--------|--------|----------|
| **Library Detection** | ✔ LLM | Only LLM detects apacheds-*, jose4j, bouncycastle |
| **Version Precision** | ✔ LLM | Full semantic versioning (2.0.0-M24, 0.9.4, 1.78.1) |
| **Group Coordinates** | ✔ LLM | Maven group:artifact:version format |
| **Dependency Graph** | ✔ LLM | Complete tree with 15 dependencies |

### 5.2 Cryptographic Assets
| Aspect | Winner | Analysis |
|--------|--------|----------|
| **Quantity** | ✔ CodeQL | 35 assets vs. 5 (LLM) vs. 11 (SonarQube) |
| **Algorithm Diversity** | ✔ SonarQube | RSA, DSA, EC, SHA, HMAC coverage |
| **Operational Crypto** | ✔ CodeQL | TLS, random generation, key management |
| **Quantum Readiness** | ✔ LLM | Consistent NIST level 3 for strong crypto |
| **OID Compliance** | ✔ LLM | 80% coverage with proper identifiers |

### 5.3 Certificates
| Aspect | Winner | Analysis |
|--------|--------|----------|
| **X.509 Detection** | ✔ LLM | Proper `assetType: "certificate"` |
| **Certificate Properties** | ✔ LLM | Uses `certificateProperties.format` |
| **CodeQL Issue** | - | Misclassifies X.509 as algorithm |

### 5.4 Evidence & Provenance
| Aspect | Winner | Analysis |
|--------|--------|----------|
| **Location Precision** | ✔ CodeQL | line, offset, endOffset, endLine |
| **Occurrence Aggregation** | ✔ CodeQL | Counts multiple findings (up to 30) |
| **Method Signatures** | ✔ SonarQube | Full Java descriptors (Ljava/lang/String;) |
| **Source Attribution** | ✔ CodeQL | Rule IDs, categories, occurrence counts |
| **Multi-Source Evidence** | ✔ Merged | Combines all three sources per asset |

### 5.5 Operational Security
| Aspect | Winner | Analysis |
|--------|--------|----------|
| **TLS/SSL Detection** | ✔ CodeQL | SSLEngine, SSLContext, TLS configuration |
| **Random Generation** | ✔ CodeQL | SecureRandom vs. insecure java.util.Random |
| **Key Management Ops** | ✔ CodeQL | 12 distinct operations (load, store, retrieve) |
| **Test Code Flagging** | ✔ CodeQL | Explicit test path detection |

---

## 6. Merged CBOM Analysis

The merged CBOM demonstrates sophisticated deduplication and enrichment strategies:

### Deduplication Logic
| Asset | Sources Merged | Strategy |
|-------|---------------|----------|
| HmacSHA512 | LLM + SonarQube + CodeQL | Evidence aggregation with source tags |
| SHA-256 | LLM + SonarQube + CodeQL | OID preservation, evidence merging |
| PKCS12 | LLM + CodeQL | 10 occurrences merged from both |
| JKS | LLM + CodeQL | 5 occurrences with source attribution |
| X.509 | LLM + CodeQL | Certificate properties prioritized |

### Enrichment Examples
```json
{
  "name": "HmacSHA512",
  "evidence": {
    "occurrences": [
      {
        "source": "llm",
        "additionalContext": "java.security.Mac#getInstance"
      },
      {
        "source": "sonarqube", 
        "additionalContext": "javax.crypto.Mac#getInstance(Ljava/lang/String;)..."
      },
      {
        "source": "codeql",
        "additionalContext": "Cryptographic mac algorithm: 'HmacSHA512'",
        "endOffset": 48
      }
    ]
  }
}
```

### Merged Metadata Quality
- **Tool Attribution**: "CBOM Merger" v1.0.0
- **Source Tracking**: `cdx:cbom:mergedSources: "llm,sonarqube,codeql"`
- **Component Count**: 55 (accurately tracked)
- **Git Integration**: Preserves commit hash from LLM


---

## Conclusions

This exercise created CodeQL queries without being exhaustive, and the LLM scripts were generated with minimal prompts. Sonar-cryptography was executed with the latest version available (main branch at 2026/02/14).

With these assumptions, the findings are no more than an overview of how the exercise went with the inputs given to each method, but they strengthen the idea that generating CBOMs from code is a complex task that will require several methods (or one very well executed).

### Key Findings

1. **Complementarity Over Competition**: Each tool captures orthogonal aspects:
   - LLM: Semantic/library layer
   - SonarQube: Algorithm implementation layer  
   - CodeQL: Operational/behavioral layer

2. **Specification Gaps**: 
   - CodeQL's "algorithm" misclassification of certificates violates CycloneDX 1.6
   - SonarQube's legacy `tools.services` format is deprecated
   - LLM's limited operational crypto misses runtime security concerns

3. **Merge Strategy Value**: The merged CBOM achieves **91% compliance** vs. individual scores of 65-82%, demonstrating that multi-source CBOM generation is essential for comprehensive cryptographic visibility.

4. **Quantum Readiness**: Only the LLM consistently applies NIST quantum security levels, making it critical for post-quantum migration planning despite its lower asset count.

### Final Assessment

| Metric | Score | Rationale |
|--------|-------|-----------|
| **Completeness** | ⭐⭐⭐⭐⭐ | Merged CBOM covers all dimensions |
| **Accuracy** | ⭐⭐⭐⭐☆ | Minor classification issues in CodeQL |
| **Usability** | ⭐⭐⭐⭐⭐ | Rich metadata and descriptions |
| **Compliance** | ⭐⭐⭐⭐⭐ | 91% CycloneDX 1.6 adherence |
| **Actionability** | ⭐⭐⭐⭐⭐ | Security-relevant operational data |


## Lessons Learnt

1. There is no tool that gives you the "perfect CBOM"
2. LLMs are a must-have tool for CI/CD CBOM analysis
3. CodeQL and SonarQube are good tools with sound capabilities, but do not give you the complete picture and have limitations on top of the known language limitations
4. This kind of benchmark can help us understand the big picture of the CBOM paradigm and advance on the fastest path (to me: LLM repository scanning)
5. All this analysis is static and requires further methods to include it in pipelines for continuous integration (e.g. rejecting pull requests if cryptography is not compliant with policies)

---

## Next Steps

1. Apply the methodology to other Java and Python codebases to check the results and try to get stronger conclusions
2. Explore the LLM standalone capability and its integration in SecDevOps
