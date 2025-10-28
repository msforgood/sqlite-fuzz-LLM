# Quick Start Guide

## 5-Minute Demo

Get started with the advanced SQLite3 fuzzer in just 5 minutes!

### 1. Build Everything

```bash
# From the root directory
make all
```

### 2. Run Basic Test

```bash
# Test the advanced fuzzer
./advanced_fuzzer_standalone tests/testcases/sql/basic.sql

# Test with different modes
./advanced_fuzzer_standalone tests/testcases/binary/schema.bin
./advanced_fuzzer_standalone tests/testcases/binary/functions.bin
```

### 3. Run Performance Comparison

```bash
# Compare baseline vs advanced fuzzer
make analysis
```

### 4. View Results

```bash
# Check the generated reports
cat analysis/results/reports/coverage_analysis.txt
cat analysis/results/reports/performance_summary.md
```

## What You Should See

- Advanced fuzzer runs successfully on test cases
- Coverage analysis shows improvement over baseline
- Multiple fuzzing modes demonstrate different test scenarios

## Next Steps

- Check out `examples/advanced_usage/` for more complex scenarios
- Read `docs/ARCHITECTURE.md` for technical details
- Explore `analysis/tools/` for custom analysis scripts