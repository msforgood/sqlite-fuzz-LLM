# Advanced SQLite3 Fuzzer - Competition Submission
# Main Makefile for building all components

.PHONY: all clean baseline advanced coverage analysis examples help

# Default target
all: baseline advanced

# Build baseline fuzzers
baseline:
	@echo "Building baseline fuzzers..."
	@cd build/scripts && ./build_baseline.sh

# Build advanced fuzzer
advanced:
	@echo "Building advanced fuzzer..."
	@cd build/scripts && ./build_advanced.sh

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
	@echo "  all       - Build baseline and advanced fuzzers"
	@echo "  baseline  - Build only baseline fuzzers"
	@echo "  advanced  - Build only advanced fuzzer"
	@echo "  coverage  - Build with coverage instrumentation"
	@echo "  analysis  - Run performance comparison analysis"
	@echo "  reports   - Generate analysis reports"
	@echo "  examples  - Prepare example scripts"
	@echo "  clean     - Clean build artifacts"
	@echo "  deps      - Check dependencies"
	@echo "  help      - Show this help message"