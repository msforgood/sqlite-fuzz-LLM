#!/usr/bin/env python3
"""
Advanced SQLite3 Fuzzer Coverage Analysis
Analyzes gcov output to compare function coverage between original and advanced fuzzers
"""

import re
import sys
from collections import defaultdict

def parse_gcov_file(filename):
    """Parse a gcov file and extract function coverage information"""
    functions = {}
    covered_lines = 0
    total_lines = 0
    
    try:
        with open(filename, 'r') as f:
            current_function = None
            for line_num, line in enumerate(f, 1):
                # Skip header lines
                if line.startswith('-:') and ('Source:' in line or 'Graph:' in line or 'Data:' in line):
                    continue
                    
                # Count total lines (excluding metadata)
                if ':' in line and not line.startswith('-:'):
                    total_lines += 1
                    
                # Check if line is covered (starts with number)
                if re.match(r'^\s*[1-9]\d*:', line):
                    covered_lines += 1
                
                # Look for function definitions
                # Pattern: number:line_number:function_type function_name(
                if re.match(r'^\s*[1-9]\d*:\s*\d+:\s*(?:static\s+)?(?:SQLITE_\w+\s+)?(?:int|void|char|sqlite3|u\d+|double|float)\s+\w+\s*\(', line):
                    # Extract function name
                    match = re.search(r'(?:static\s+)?(?:SQLITE_\w+\s+)?(?:int|void|char|sqlite3|u\d+|double|float)\s+(\w+)\s*\(', line.split(':', 2)[2])
                    if match:
                        func_name = match.group(1)
                        # Get execution count
                        exec_count = int(line.split(':')[0].strip())
                        functions[func_name] = exec_count
                        current_function = func_name
                        
    except FileNotFoundError:
        print(f"File not found: {filename}")
        return {}, 0, 0
    except Exception as e:
        print(f"Error parsing {filename}: {e}")
        return {}, 0, 0
    
    return functions, covered_lines, total_lines

def analyze_coverage():
    """Main analysis function"""
    print("=== Advanced SQLite3 Fuzzer Coverage Analysis ===\n")
    
    # Parse coverage files
    orig_funcs, orig_covered, orig_total = parse_gcov_file('gcov_results/original/sqlite3.c.gcov')
    adv_funcs, adv_covered, adv_total = parse_gcov_file('gcov_results/advanced/sqlite3.c.gcov')
    
    if not orig_funcs and not adv_funcs:
        print("No function data found. Coverage files may not exist or be in wrong format.")
        return
    
    # Calculate coverage percentages
    orig_percentage = (orig_covered / orig_total * 100) if orig_total > 0 else 0
    adv_percentage = (adv_covered / adv_total * 100) if adv_total > 0 else 0
    
    print("=== Line Coverage Summary ===")
    print(f"Original Fuzzer: {orig_covered:,}/{orig_total:,} lines ({orig_percentage:.2f}%)")
    print(f"Advanced Fuzzer: {adv_covered:,}/{adv_total:,} lines ({adv_percentage:.2f}%)")
    print(f"Improvement: +{adv_covered - orig_covered:,} lines (+{adv_percentage - orig_percentage:.2f}%)\n")
    
    # Function analysis
    orig_called_funcs = {f: count for f, count in orig_funcs.items() if count > 0}
    adv_called_funcs = {f: count for f, count in adv_funcs.items() if count > 0}
    
    only_advanced = set(adv_called_funcs.keys()) - set(orig_called_funcs.keys())
    only_original = set(orig_called_funcs.keys()) - set(adv_called_funcs.keys())
    common_funcs = set(orig_called_funcs.keys()) & set(adv_called_funcs.keys())
    
    print("=== Function Coverage Summary ===")
    print(f"Functions called by original fuzzer: {len(orig_called_funcs)}")
    print(f"Functions called by advanced fuzzer: {len(adv_called_funcs)}")
    print(f"Common functions: {len(common_funcs)}")
    print(f"Functions only called by advanced fuzzer: {len(only_advanced)}")
    print(f"Functions only called by original fuzzer: {len(only_original)}\n")
    
    # New functions hit by advanced fuzzer
    if only_advanced:
        print("=== New Functions Hit by Advanced Fuzzer ===")
        for i, func in enumerate(sorted(only_advanced)[:20], 1):
            call_count = adv_called_funcs[func]
            print(f"{i:2d}. {func:<30} (called {call_count:,} times)")
        if len(only_advanced) > 20:
            print(f"    ... and {len(only_advanced) - 20} more functions")
        print()
    
    # Functions with increased call frequency
    increased_calls = []
    for func in common_funcs:
        orig_count = orig_called_funcs[func]
        adv_count = adv_called_funcs[func]
        if adv_count > orig_count:
            increased_calls.append((func, orig_count, adv_count, adv_count - orig_count))
    
    if increased_calls:
        print("=== Functions with Increased Call Frequency ===")
        increased_calls.sort(key=lambda x: x[3], reverse=True)  # Sort by increase amount
        for i, (func, orig_count, adv_count, increase) in enumerate(increased_calls[:15], 1):
            print(f"{i:2d}. {func:<30} {orig_count:,} -> {adv_count:,} (+{increase:,})")
        if len(increased_calls) > 15:
            print(f"    ... and {len(increased_calls) - 15} more functions")
        print()
    
    # Most frequently called functions in advanced fuzzer
    print("=== Most Frequently Called Functions (Advanced Fuzzer) ===")
    top_functions = sorted(adv_called_funcs.items(), key=lambda x: x[1], reverse=True)[:15]
    for i, (func, count) in enumerate(top_functions, 1):
        orig_count = orig_called_funcs.get(func, 0)
        status = " (NEW)" if func in only_advanced else f" (was {orig_count:,})" if orig_count != count else ""
        print(f"{i:2d}. {func:<30} {count:,} calls{status}")
    print()
    
    # Functions that help with specific SQLite features
    feature_functions = {
        'JSON': [f for f in adv_called_funcs if 'json' in f.lower()],
        'FTS': [f for f in adv_called_funcs if 'fts' in f.lower()],
        'RTREE': [f for f in adv_called_funcs if 'rtree' in f.lower()],
        'Window': [f for f in adv_called_funcs if 'window' in f.lower()],
        'Parse': [f for f in adv_called_funcs if 'parse' in f.lower() or 'Parse' in f],
        'VDBE': [f for f in adv_called_funcs if 'vdbe' in f.lower() or 'Vdbe' in f],
        'B-Tree': [f for f in adv_called_funcs if 'btree' in f.lower() or 'Btree' in f],
        'Memory': [f for f in adv_called_funcs if 'malloc' in f.lower() or 'memory' in f.lower() or 'Malloc' in f]
    }
    
    print("=== SQLite Feature Coverage ===")
    for feature, funcs in feature_functions.items():
        if funcs:
            new_funcs = [f for f in funcs if f in only_advanced]
            print(f"{feature:<8}: {len(funcs):2d} functions ({len(new_funcs)} new)")
    print()
    
    # Save detailed results
    with open('coverage_analysis_report.txt', 'w') as f:
        f.write("=== SQLite3 Fuzzer Coverage Analysis Report ===\n\n")
        f.write(f"Generated for comparison between original and advanced fuzzers\n\n")
        
        f.write("=== Line Coverage ===\n")
        f.write(f"Original Fuzzer: {orig_covered:,}/{orig_total:,} lines ({orig_percentage:.2f}%)\n")
        f.write(f"Advanced Fuzzer: {adv_covered:,}/{adv_total:,} lines ({adv_percentage:.2f}%)\n")
        f.write(f"Improvement: +{adv_covered - orig_covered:,} lines (+{adv_percentage - orig_percentage:.2f}%)\n\n")
        
        f.write("=== Function Coverage ===\n")
        f.write(f"Functions called by original fuzzer: {len(orig_called_funcs)}\n")
        f.write(f"Functions called by advanced fuzzer: {len(adv_called_funcs)}\n")
        f.write(f"New functions hit by advanced fuzzer: {len(only_advanced)}\n\n")
        
        f.write("=== New Functions (Advanced Fuzzer Only) ===\n")
        for func in sorted(only_advanced):
            f.write(f"{func}: {adv_called_funcs[func]:,} calls\n")
        f.write("\n")
        
        f.write("=== Functions with Increased Call Frequency ===\n")
        for func, orig_count, adv_count, increase in increased_calls:
            f.write(f"{func}: {orig_count:,} -> {adv_count:,} (+{increase:,})\n")
    
    print("Detailed report saved to: coverage_analysis_report.txt")

if __name__ == "__main__":
    analyze_coverage()