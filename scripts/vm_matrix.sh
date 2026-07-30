#!/usr/bin/env bash
# End-to-end VM runtime test matrix: runs each test case unobfuscated (baseline)
# then through --runtime with multiple seeds, comparing stdout.
set -u
cd /workspace

# Each test case is: <name>|<lua file>
TESTS=(
  "hello|examples/hello.lua"
  "vm_features|examples/vm_features.lua"
  "min_for|examples/min_for.lua"
  "min_if|examples/min_if.lua"
  "min_concat|examples/min_concat.lua"
)

SEEDS=(1 2 3 42 100 1234 9999)
PASS=0
FAIL=0
FAILED_CASES=()

for entry in "${TESTS[@]}"; do
  name="${entry%%|*}"
  file="${entry#*|}"
  if [ ! -f "$file" ]; then
    echo "[skip] $name: file $file missing"
    continue
  fi
  # Baseline (unobfuscated) run
  baseline=$(luau "$file" 2>&1)
  baseline_rc=$?
  if [ $baseline_rc -ne 0 ]; then
    echo "[skip] $name: baseline failed (rc=$baseline_rc)"
    continue
  fi
  for seed in "${SEEDS[@]}"; do
    out_lua="/tmp/vmtest_${name}_s${seed}.lua"
    if ! node dist/cli/obfuscate.js -i "$file" -o "$out_lua" --runtime --seed "$seed" 2>/tmp/vmtest_err.txt; then
      echo "[FAIL] $name seed=$seed obfuscate-error"
      FAIL=$((FAIL + 1))
      FAILED_CASES+=("$name/s$seed/obf")
      cat /tmp/vmtest_err.txt
      continue
    fi
    actual=$(luau "$out_lua" 2>&1)
    if [ "$actual" == "$baseline" ]; then
      PASS=$((PASS + 1))
      echo "[ok]   $name seed=$seed"
    else
      FAIL=$((FAIL + 1))
      FAILED_CASES+=("$name/s$seed")
      echo "[FAIL] $name seed=$seed"
      echo "--- baseline ---"
      echo "$baseline"
      echo "--- actual ---"
      echo "$actual"
      echo "---"
    fi
  done
done

echo "=========================================="
echo "PASS=$PASS FAIL=$FAIL"
if [ $FAIL -gt 0 ]; then
  echo "Failed cases:"
  for c in "${FAILED_CASES[@]}"; do echo "  - $c"; done
  exit 1
fi
echo "ALL PASS"
