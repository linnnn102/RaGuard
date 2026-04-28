## MCP server
### 1. Start the target app
python targets/test_target2.py

### 2. Run the MCP pipeline via client.py
python src/client.py targets/test_target2.py


## Fuzzy test pipeline
### Step 1 — run the vulnerability scanner
python src/vuln_scanner.py targets/test_target2.py

### Step 2 — generate fuzz.sh from the report
python src/generate_fuzz_script.py --report results/reports/vuln_report.json \
    --target-url http://host.docker.internal:5055/user/FUZZ

### Step 3 — build the container (once)
docker build -t vuln-fuzzer .

### Step 4 — run fuzzing when ready
mkdir -p results/fuzz
docker run --rm \
    -v $(pwd)/results/scripts/fuzz.sh:/fuzz/fuzz.sh \
    -v $(pwd)/results/fuzz:/results \
    --add-host=host.docker.internal:host-gateway \
    vuln-fuzzer bash /fuzz/fuzz.sh

### Step 5 — parse results
python src/parse_fuzz_results.py