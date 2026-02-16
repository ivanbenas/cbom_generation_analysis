
## Playback Requirements
Some of the details to be able to reproduce my results are in here. If  you have any issue to execute them just let me know.
I use  Linux manjaroX 6.12.68-1

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