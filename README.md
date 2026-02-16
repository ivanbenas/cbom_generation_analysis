# CBOM Generation Benchmark

This project benchmarks **three methods** of generating Cryptographic Bills of Materials (CBOMs) for the same codebase, comparing complexity, coverage, and CycloneDX 1.6 standard adherence.

**Benchmark target:** Apache Kafka (commit f20f299). The `kafka-f20f299` directory should contain the Kafka source, or use any Java/Scala project path for Method 1.
This commit was chosen along with CycloneDX 1.6 to compare also with the CBOMKit CBOM generated for Kafka.


## Overview

The benchmark evaluates three distinct approaches to produce CycloneDX 1.6 CBOMs:

| Method | Tool(s) | Primary Input | Output |
|--------|---------|---------------|--------|
| **1. Pure LLM (regex)** | `generate_cbom_v2.py` | Source code (Java, Scala) | `llm_cbom.json` |
| **2. SonarQube Cryptography** | Sonar Cryptography Plugin (IBM) | Java AST via SonarQube | `sonarqube_cbom.json` |
| **3. CodeQL + SARIF converter** | CodeQL + `sarif_to_cbom.py` | SARIF from CodeQL analysis | `codeql_cbom.json` |

A **merged CBOM** (`merged_cbom.json`) consolidates findings from all three sources. See [CBOM_COMPARISON_REPORT.md](CBOM_COMPARISON_REPORT.md) for a detailed comparison.

---

## Requirements

### Common (all methods)

- **Python 3.10+** – for `generate_cbom_v2.py`, `sarif_to_cbom.py`, `merge_cboms.py`
- **Git** – for cloning repositories

### Method 1: Pure LLM

- Python 3.10+ (stdlib only; no extra packages)

### Method 2: SonarQube Cryptography

- **Maven** – to build the sonar-cryptography plugin
- **Docker** – to run SonarQube
- **Java 17+** – for Kafka and SonarQube
- **Gradle** – Kafka uses Gradle (wrapper included)

### Method 3: CodeQL + SARIF

- **CodeQL CLI** – [download](https://github.com/github/codeql-cli-binaries/releases)
- **Java** – for CodeQL database creation
- **Python 3.10+** – for `sarif_to_cbom.py`

---

## How to Execute

### Method 1: Pure LLM (fastest, &lt; 1 min)

```bash
python3 generate_cbom_v2.py <source_path> <output.json> [project_name]
```

**Example:**
```bash
python3 generate_cbom_v2.py ./kafka-f20f299 llm_cbom.json "Apache Kafka"
```

**Output:** `llm_cbom.json` – CycloneDX 1.6 CBOM with algorithms, libraries, evidence, OIDs, `nistQuantumSecurityLevel`, `algorithmFamily`, `ellipticCurve`.

---

### Method 2: SonarQube Cryptography (~10 min)
Clone the repository sonar-cryptography and use the docker contained to ensure that you do not have problems with dependencies.

**Steps:**
1. Build plugin: `cd sonar-cryptography && mvn clean package -DskipTests`
2. Start SonarQube: `UID=${UID} docker compose up -d`
3. Configure Quality Profile (activate "Cryptography Inventory")
4. Create project and run scan:
   ```bash
   cd kafka-f20f299
   ./gradlew sonar -Dsonar.projectKey=kafka -Dsonar.host.url=http://localhost:9000 \
     -Dsonar.token=YOUR_TOKEN -Dsonar.cryptoScanner.cbom=cbom_sonar
   ```
*You will need java21 and increase the Java Heap Space in `gradle.properties`.*
   ```bash
   # Reduce heap size if builds are smaller
   org.gradle.jvmargs=-Xmx2g -XX:MaxMetaspaceSize=256m -XX:+UseParallelGC

   # Or for larger Kafka projects, balance memory
   # org.gradle.jvmargs=-Xmx4g -XX:MaxMetaspaceSize=512m -XX:+HeapDumpOnOutOfMemoryError

   # Enable daemon for caching (trades memory for speed)
   org.gradle.daemon=true
   org.gradle.daemon.idletimeout=60000  # Kill idle daemon faster (1 min)

   # Disable if memory is critical
   # org.gradle.daemon=false
   ```

*Also add to the `build.gradle`:*
   ```bash
   sonar {
      properties {
         property("sonar.scanner.javaOpts", "-Xmx4g -XX:MaxMetaspaceSize=512m")
      }}
   ```
      



### Method 3: CodeQL + SARIF converter (12–40 min)

**Step 1 – Create CodeQL database:**
```bash
codeql database create kafka-db --language=java --source-root=kafka-f20f299
```

**Step 2 – Run CodeQL cryptographic queries:**
```bash
codeql database analyze kafka-db \
  --format=sarif-latest \
  --output=crypto-results.sarif \
  codeql/cryptographyc-queries/*.ql
```

*For richer crypto coverage, use custom or community CodeQL crypto queries (e.g. algorithm-usage, key-management) that produce SARIF.*

**Step 3 – Convert SARIF to CBOM:**
```bash
python3 sarif_to_cbom.py crypto-results.sarif cbom-from-sarif.json
```

**Output:** `cbom-from-sarif.json` – copy to `generated-cboms/codeql_cbom.json`.

---

### Merge all three CBOMs

```bash
python3 merge_cboms.py
```

**Output:** `generated-cboms/merged_cbom.json` – consolidated CBOM with deduplicated components and merged evidence.

---

## Outputs

| File | Method | Description |
|------|--------|-------------|
| `generated-cboms/llm_cbom.json` | 1. Pure LLM | Regex + Gradle parsing; algorithms, libraries |
| `generated-cboms/sonarqube_cbom.json` | 2. SonarQube | Java AST; granular algorithm dependencies |
| `generated-cboms/codeql_cbom.json` | 3. CodeQL | SARIF → CBOM; dynamic/unknown algorithms, TLS, random |
| `generated-cboms/merged_cbom.json` | Merge | Combined findings from all three |

---

## Project Structure

```
SBOM_CBOM_DB/
├── generate_cbom_v2.py      # Method 1: Pure LLM/regex CBOM generator
├── sarif_to_cbom.py        # Method 3: SARIF → CBOM converter
├── merge_cboms.py          # Merge script for all three CBOMs
├── crypto_defs_loader.py   # Loads specification/schema/cryptography-defs.json
├── specification/          # CycloneDX schema and cryptography-defs.json
├── sonar-cryptography/     # Method 2: SonarQube Cryptography plugin
├── generated-cboms/        # Output directory for all CBOMs
├── CBOM_COMPARISON_REPORT.md
└── CBOM_SUMMARY.md
```

---

## Cryptography Definitions

All generators use `specification/schema/cryptography-defs.json` for:

- **OIDs** – elliptic curve and algorithm OIDs
- **algorithmFamily** – e.g. SHA-2, HMAC, ECDH
- **ellipticCurve** – canonical curve references (e.g. `secg/secp256r1`)
- **nistQuantumSecurityLevel** – PQC algorithms (ML-DSA, ML-KEM, etc.) → level 5

---

## Validation

Validate CBOMs against CycloneDX 1.6 schema:

```bash
cyclonedx validate --input-file generated-cboms/llm_cbom.json
```

---

## Benchmark Summary

| Method | Setup | Time | Best for |
|--------|-------|------|----------|
| **LLM** | Low | &lt; 1 min | Fastest result, best standard compliance |
| **SonarQube** | High | 8–21 min | Algorithm dependencies, key material |
| **CodeQL** | Medium–High | 12–40 min | Dynamic algorithms, TLS, insecure random |
| **Merge** | — | — | Maximum coverage |

See [CBOM_COMPARISON_REPORT.md](CBOM_COMPARISON_REPORT.md) for full analysis.


## Lessons Learnt 

1. There is no tool that gives you the "perfect CBOM"
2. LLMs are a must tool for CI/CD CBOM analysis
2. CodeQL and sonarqube are good tools with sound capabilities, but do not give you the complete picture and have limitations on top of the known languaje limitations
3. This kind of benchmarks can help us understand the big picture of the CBOM paradigm and advance in the fastest path (to me LLM repository scanning)
4. All this analysis are static and require further methods to include them in the pipelines for continuous integration. (i.e Rejecting pull request if cryptography is not compliant with policies.)

## Next steps.
1. Apply the methodology to other Java and Python codes to check the results and try to get stronger conclusions.
2. Explore the LLM stand alone capability and its integration in SecDevOps.
