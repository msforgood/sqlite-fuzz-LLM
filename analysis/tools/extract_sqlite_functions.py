#!/usr/bin/env python3
"""
SQLite3 Function Extraction and Analysis Tool
Extracts all functions from SQLite3 source code and categorizes them for fuzzing
"""

import os
import re
import csv
from typing import List, Dict, Tuple
from collections import defaultdict

def extract_functions_from_file(filepath: str) -> List[Dict]:
    """Extract function definitions from a single C file"""
    functions = []
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # 함수 정의 패턴들 (매크로와 구조체 제외)
        patterns = [
            # static 함수: static return_type function_name(
            r'^static\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\s*\*)*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            # 일반 함수: return_type function_name( (매크로 #define 제외)
            r'^(?!#define)([a-zA-Z_][a-zA-Z0-9_]*(?:\s*\*)*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            # void 함수
            r'^(void)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # 주석, 전처리기 지시문, 매크로 정의 제외
            if (line.startswith('//') or line.startswith('/*') or line.startswith('#') or
                line.startswith('SQLITE_') or line.startswith('typedef') or
                line.startswith('struct') or line.startswith('enum') or
                line.startswith('union') or '{' in line.split('(')[0]):
                continue
                
            for pattern in patterns:
                match = re.match(pattern, line)
                if match:
                    return_type = match.group(1).strip()
                    func_name = match.group(2).strip()
                    
                    # 유효한 함수명인지 확인 (매크로나 상수 제외)
                    if (func_name and not func_name.isdigit() and 
                        not func_name.isupper() and  # 상수명 제외
                        not func_name.startswith('SQLITE_') and  # SQLite 상수 제외
                        len(func_name) > 1 and  # 단일 문자 제외
                        not return_type.isupper()):  # 리턴 타입이 상수가 아닌지 확인
                        
                        functions.append({
                            'file': os.path.basename(filepath),
                            'line_number': line_num,
                            'function_name': func_name,
                            'return_type': return_type,
                            'is_static': 'static' in line.lower(),
                            'is_public_api': func_name.startswith('sqlite3'),
                            'full_signature': line
                        })
                    break
                    
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
    
    return functions

def categorize_function(func_info: Dict) -> Dict:
    """Categorize function based on name patterns and file location"""
    func_name = func_info['function_name'].lower()
    file_name = func_info['file'].lower()
    
    # 카테고리 분류
    category = "Other"
    subcategory = "Unknown"
    fuzzing_priority = "Low"
    complexity = "Medium"
    
    # 파일 기반 카테고리
    file_categories = {
        'btree.c': ('B-Tree', 'Index Management'),
        'vdbe.c': ('VDBE', 'Virtual Machine'),
        'vdbeapi.c': ('VDBE', 'API Interface'),
        'vdbeaux.c': ('VDBE', 'Auxiliary Functions'),
        'vdbemem.c': ('VDBE', 'Memory Operations'),
        'parse.y': ('Parser', 'SQL Parsing'),
        'build.c': ('Parser', 'SQL Building'),
        'expr.c': ('Parser', 'Expression Evaluation'),
        'select.c': ('Query', 'SELECT Processing'),
        'insert.c': ('Query', 'INSERT Processing'),
        'update.c': ('Query', 'UPDATE Processing'),
        'delete.c': ('Query', 'DELETE Processing'),
        'where.c': ('Query', 'WHERE Clause'),
        'malloc.c': ('Memory', 'Memory Management'),
        'mem0.c': ('Memory', 'Memory Interface'),
        'pager.c': ('Storage', 'Page Management'),
        'btmutex.c': ('Concurrency', 'Mutex Operations'),
        'os.c': ('OS', 'Operating System Interface'),
        'json.c': ('Extension', 'JSON Functions'),
        'fts3.c': ('Extension', 'Full-Text Search'),
        'rtree.c': ('Extension', 'R-Tree Index'),
        'auth.c': ('Security', 'Authorization'),
        'backup.c': ('Utility', 'Database Backup'),
        'analyze.c': ('Optimization', 'Statistics Analysis'),
        'pragma.c': ('Configuration', 'PRAGMA Commands'),
        'trigger.c': ('Feature', 'Trigger Processing'),
        'vacuum.c': ('Maintenance', 'Database Maintenance'),
        'wal.c': ('Storage', 'Write-Ahead Logging'),
    }
    
    if file_name in file_categories:
        category, subcategory = file_categories[file_name]
    
    # 함수명 기반 세부 분류
    if func_name.startswith('sqlite3'):
        # Public API 함수들
        if 'exec' in func_name:
            subcategory = "SQL Execution"
            fuzzing_priority = "Critical"
        elif 'prepare' in func_name:
            subcategory = "Statement Preparation" 
            fuzzing_priority = "Critical"
        elif 'step' in func_name:
            subcategory = "Statement Execution"
            fuzzing_priority = "Critical"
        elif 'bind' in func_name:
            subcategory = "Parameter Binding"
            fuzzing_priority = "High"
        elif 'column' in func_name:
            subcategory = "Result Retrieval"
            fuzzing_priority = "High"
        elif 'open' in func_name or 'close' in func_name:
            subcategory = "Database Connection"
            fuzzing_priority = "High"
    
    # 내부 함수 중요도 분석
    critical_patterns = [
        'parse', 'exec', 'malloc', 'free', 'btree', 'vdbe', 'page', 'lock', 
        'commit', 'rollback', 'backup', 'recover', 'corrupt', 'verify'
    ]
    
    high_patterns = [
        'insert', 'update', 'delete', 'select', 'where', 'join', 'index',
        'trigger', 'view', 'vacuum', 'analyze', 'pragma', 'auth'
    ]
    
    for pattern in critical_patterns:
        if pattern in func_name:
            fuzzing_priority = "Critical"
            complexity = "High"
            break
    else:
        for pattern in high_patterns:
            if pattern in func_name:
                fuzzing_priority = "High"
                break
    
    # 복잡도 추정 (함수명 길이와 패턴 기반)
    if len(func_name) > 20 or 'complex' in func_name or 'recursive' in func_name:
        complexity = "High"
    elif len(func_name) > 15:
        complexity = "Medium"
    else:
        complexity = "Low"
    
    return {
        **func_info,
        'category': category,
        'subcategory': subcategory,
        'fuzzing_priority': fuzzing_priority,
        'complexity': complexity,
        'description': f"{subcategory} function in {category} subsystem"
    }

def main():
    """Main function to extract and analyze SQLite3 functions"""
    
    # SQLite3 소스 디렉토리
    src_dir = "./build/dependencies/sqlite3-source/src"
    
    if not os.path.exists(src_dir):
        print(f"Source directory not found: {src_dir}")
        return
    
    all_functions = []
    
    # 모든 C 파일에서 함수 추출
    print("Extracting functions from SQLite3 source files...")
    for filename in os.listdir(src_dir):
        if filename.endswith('.c'):
            filepath = os.path.join(src_dir, filename)
            functions = extract_functions_from_file(filepath)
            all_functions.extend(functions)
            print(f"  {filename}: {len(functions)} functions")
    
    print(f"\nTotal functions extracted: {len(all_functions)}")
    
    # 함수 카테고리화
    print("Categorizing functions...")
    categorized_functions = []
    for func in all_functions:
        categorized_func = categorize_function(func)
        categorized_functions.append(categorized_func)
    
    # 통계 출력
    categories = defaultdict(int)
    priorities = defaultdict(int)
    public_apis = 0
    
    for func in categorized_functions:
        categories[func['category']] += 1
        priorities[func['fuzzing_priority']] += 1
        if func['is_public_api']:
            public_apis += 1
    
    print(f"\n=== Function Analysis Summary ===")
    print(f"Total functions: {len(categorized_functions)}")
    print(f"Public API functions: {public_apis}")
    print(f"\nBy Category:")
    for cat, count in sorted(categories.items()):
        print(f"  {cat}: {count}")
    print(f"\nBy Fuzzing Priority:")
    for priority, count in sorted(priorities.items()):
        print(f"  {priority}: {count}")
    
    # CSV 파일 생성
    output_file = "./analysis/results/sqlite3_functions.csv"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    print(f"\nWriting results to {output_file}...")
    
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'function_name', 'file', 'line_number', 'return_type',
            'category', 'subcategory', 'fuzzing_priority', 'complexity',
            'is_public_api', 'is_static', 'description', 'full_signature'
        ]
        
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        # 중요도와 카테고리별로 정렬
        priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_functions = sorted(categorized_functions, 
                                key=lambda x: (priority_order.get(x['fuzzing_priority'], 4),
                                             x['category'],
                                             x['function_name']))
        
        for func in sorted_functions:
            writer.writerow(func)
    
    print("Function extraction and analysis complete!")
    print(f"Results saved to: {output_file}")
    
    # 고우선순위 함수들 미리보기
    print(f"\n=== Top 20 Critical Functions for Fuzzing ===")
    critical_functions = [f for f in sorted_functions if f['fuzzing_priority'] == 'Critical'][:20]
    for i, func in enumerate(critical_functions, 1):
        print(f"{i:2d}. {func['function_name']:<30} ({func['category']}/{func['subcategory']})")

if __name__ == "__main__":
    main()