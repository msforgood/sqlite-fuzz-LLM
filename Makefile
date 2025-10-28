# Advanced SQLite3 Fuzzer - Competition Submission
# Main Makefile for building all components

.PHONY: all clean baseline ours_wo_spec ours_w_spec advanced coverage analysis examples help

# Default target
all: baseline ours_wo_spec

# Build baseline fuzzers
baseline:
	@echo "Building baseline fuzzers..."
	@cd build/scripts && ./build_baseline.sh

# Build ours_wo_spec fuzzer (version 1)
ours_wo_spec:
	@echo "Building ours_wo_spec fuzzer (version 1)..."
	@cd build/scripts && ./build_ours_wo_spec.sh

# Build ours_w_spec fuzzer (version 2) 
ours_w_spec:
	@echo "Building ours_w_spec fuzzer (version 2)..."
	@cd build/scripts && ./build_ours_w_spec.sh

# Legacy alias for ours_wo_spec
advanced: ours_wo_spec

# Build with coverage instrumentation
coverage:
	@echo "Building with coverage instrumentation..."
	@cd build/scripts && ./build_coverage.sh

# Run performance analysis
analysis: coverage
	@echo "Running performance analysis..."
	@cd analysis/scripts && ./run_comparison.sh

# Generate reports
reports: analysis
	@echo "Generating analysis reports..."
	@cd analysis/scripts && ./generate_reports.sh

# Build examples
examples:
	@echo "Preparing examples..."
	@cd examples/quickstart && chmod +x *.sh
	@cd examples/advanced_usage && chmod +x *.sh
	@cd examples/competition_demo && chmod +x *.sh

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bld/ coverage_build/ gcov_build/
	@rm -rf coverage_results/ gcov_results/
	@rm -f analysis/results/coverage/*
	@rm -f analysis/results/performance/*
	@rm -f analysis/results/reports/*
	@rm -f fuzzers/advanced/advanced_fuzzer_*
	@rm -f build/dependencies/original_fuzzer_*

# Install dependencies (if needed)
deps:
	@echo "Installing dependencies..."
	@which gcc >/dev/null || (echo "Please install gcc" && exit 1)
	@which python3 >/dev/null || (echo "Please install python3" && exit 1)

# Help target
help:
	@echo "Available targets:"
	@echo "  all           - Build baseline and ours_wo_spec fuzzers"
	@echo "  baseline      - Build only baseline fuzzers"
	@echo "  ours_wo_spec  - Build ours_wo_spec fuzzer (version 1)"
	@echo "  ours_w_spec   - Build ours_w_spec fuzzer (version 2)"
	@echo "  advanced      - Alias for ours_wo_spec (legacy)"
	@echo "  coverage  - Build with coverage instrumentation"
	@echo "  analysis  - Run performance comparison analysis"
	@echo "  reports   - Generate analysis reports"
	@echo "  examples  - Prepare example scripts"
	@echo "  clean     - Clean build artifacts"
	@echo "  deps      - Check dependencies"
	@echo "  help      - Show this help message"