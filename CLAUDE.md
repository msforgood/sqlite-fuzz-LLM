# ROLE

당신은 SQLite3 v3.51.0에 대해 실제로 동작하는 고도화된 퍼징 하니스를 작성하는 전문가다.
- SQLite3 내부 구조 (B-Tree, VDBE, Parser, Storage) 완전 이해
- 4,260개 추출 함수 중 Critical/High 우선순위 함수 타겟팅
- OSS-Fuzz 기준 대비 커버리지 극대화 목표

# RULE

## 파일 관리
- 절대 파일을 삭제하지 않는다 (DO NOT DELETE any file)
- 기존 baseline 퍼저는 수정 금지 (`fuzzers/baseline/` 보존)
- 분석 결과 파일 덮어쓰기 금지 (`analysis/results/` 보존)

## SQLite3 특화 제약사항
- SQLite3 amalgamation (`sqlite3.c`) 수정 금지
- 원본 소스코드 (`build/dependencies/sqlite3-source/`) 수정 금지
- Public API 호출 시 반드시 초기화 순서 준수 (`sqlite3_initialize()` → `sqlite3_open()` 등)
- 메모리 누수 방지를 위한 리소스 정리 필수 (`sqlite3_close()`, `sqlite3_finalize()` 등)

# GOAL

타겟 함수에 대해, 검증 규칙을 통과하며 호출되는 퍼징 하니스를 완성한다.

# 핵심 단계(반드시 수행)

## 1) 타겟 함수 확인

### SQLite3 소스코드 구조 (v3.51.0)
```
build/dependencies/
├── sqlite3.c                # 기존 amalgamation (9.0MB) 
├── sqlite3.h                # 기존 헤더 (656KB)
└── sqlite3-source/          # 완전한 개별 소스코드
    ├── src/                 # 125개 개별 소스 파일 (205,059줄)
    │   ├── btree.c          # B-Tree 관리 (235개 함수)
    │   ├── vdbe*.c          # 가상머신 (383개 함수)
    │   ├── expr.c           # 표현식 처리 (177개 함수)  
    │   ├── select.c         # SELECT 처리 (97개 함수)
    │   └── ...              # 기타 핵심 모듈들
    ├── test/                # 2,000+ 공식 테스트 스위트
    └── README_INTEGRATION.md # 퍼저 개발 가이드
```

### 함수 선정 프로세스
1. **우선순위 기반 선정**: `./analysis/results/sqlite3_functions.csv` 참조
   - Critical 우선순위 함수: 960개 (22.5%)
   - High 우선순위 함수: 486개 (11.4%)
   - 카테고리별 중요도: B-Tree > VDBE > Parser > Storage

2. **함수 분석 단계**:
   ```bash
   # CSV에서 미퍼징 Critical 함수 확인
   grep "Critical" analysis/results/sqlite3_functions.csv | head -20
   
   # 소스코드에서 함수 정의 위치 확인
   grep -n "function_name" build/dependencies/sqlite3-source/src/*.c
   ```

3. **Function Code (FC) 매핑**:
   - SQLite3 내부 함수: 파일명 + 함수명 기반 유니크 ID
   - Public API: sqlite3_ 접두사 기반 표준 매핑
   - 매핑 근거를 `./fuzzers/ours_w_spec/spec/{함수명}_spec.json`에 기록

## 2) 구조체 확인

### SQLite3 핵심 구조체 분석
```bash
# 주요 구조체 정의 확인 (sqlite3.h)
grep -A 20 "typedef struct" build/dependencies/sqlite3.h

# 내부 구조체 확인 (개별 소스)
grep -A 10 "struct.*{" build/dependencies/sqlite3-source/src/*.h
```

**주요 구조체 타입**:
- **sqlite3**: 데이터베이스 연결 객체
- **sqlite3_stmt**: 준비된 SQL 문
- **Btree/BtCursor**: B-Tree 구조체 (btreeInt.h)
- **Vdbe**: 가상 데이터베이스 엔진 (vdbeInt.h)
- **Parse**: SQL 파서 상태 (sqliteInt.h)
- **MemPage**: 메모리 페이지 구조 (btreeInt.h)

### 구조체 필드 매핑 규칙
- **패딩**: 64비트 시스템 기준 8바이트 정렬
- **타입 크기**: int(4), char*(8), sqlite3_int64(8)
- **플래그 필드**: 비트마스크 형태로 압축 저장
- **가변 길이**: 문자열은 null-terminated

## 3) SQLite3 검증 조건 확인

### 필수 검증 패턴
1. **초기화 상태 검증**:
   ```c
   assert( sqlite3_initialize()==SQLITE_OK );
   assert( db!=NULL );
   ```

2. **메모리 정렬 검증**:
   ```c
   assert( (uptr)pPtr%8==0 );  // 8바이트 정렬
   assert( nByte>=0 && nByte<0x7ffffff0 );
   ```

3. **페이지 경계 검증**:
   ```c
   assert( pgno>=1 && pgno<=btreePagecount(pBt) );
   assert( pPage->pgno==pgno );
   ```

4. **SQL 구문 검증**:
   ```c
   assert( zSql!=NULL );
   assert( sqlite3_strnicmp(zSql, "SELECT", 6)==0 );
   ```

### 오류 처리 패턴
- **반환값**: SQLITE_OK(0) vs 오류코드 (SQLITE_ERROR 등)
- **널 포인터**: 모든 포인터 매개변수 NULL 체크 필수
- **범위 검사**: 배열 인덱스, 페이지 번호, 문자열 길이
- **리소스 정리**: sqlite3_close(), sqlite3_finalize() 호출 확인

## 4) SQLite3 Spec 문서화

### 스펙 파일 생성: `./fuzzers/ours_w_spec/spec/{함수명}_spec.json`

**SQLite3 함수 스펙 템플릿**:
```json
{
  "target": { 
    "function": "sqlite3BtreeInsert",
    "fc": "btree_001",
    "category": "B-Tree",
    "file": "btree.c",
    "line": 8934
  },
  "struct_spec": {
    "btree_cursor": {
      "pBtree": "Btree*",
      "pKeyInfo": "KeyInfo*", 
      "pgnoRoot": "Pgno",
      "wrFlag": "u8"
    },
    "btree_payload": {
      "pKey": "void*",
      "nKey": "i64",
      "pData": "void*", 
      "nData": "int"
    }
  },
  "validation_spec": {
    "memory_align": 8,
    "page_size": [512, 65536],
    "key_size": {"min": 0, "max": 2147483647},
    "data_size": {"min": 0, "max": 1000000000},
    "btree_state": ["CURSOR_VALID", "CURSOR_INVALID"],
    "write_permission": "required"
  },
  "fc_mapping": {
    "source": "btree.c:8934",
    "rationale": "sqlite3BtreeInsert - Critical B-Tree insertion function",
    "api_level": "internal"
  },
  "constraints": {
    "max_input_size": 8192,
    "min_input_size": 32,
    "endianness": "LE",
    "sqlite_version": "3.51.0",
    "requires_initialization": true
  },
  "notes": {
    "preconditions": [
      "sqlite3_initialize() called",
      "Valid Btree object created",
      "Cursor positioned correctly"
    ],
    "side_effects": [
      "Database pages modified",
      "B-Tree structure may rebalance",
      "Memory allocation may occur"
    ],
    "error_conditions": [
      "SQLITE_CORRUPT: Database corruption",
      "SQLITE_FULL: Database full", 
      "SQLITE_NOMEM: Out of memory"
    ]
  }
}
```

### 카테고리별 특화 템플릿
- **B-Tree 함수**: 페이지 관리, 커서 상태, 트랜잭션 필요
- **VDBE 함수**: 프로그램 카운터, 스택 상태, 레지스터 관리  
- **Parser 함수**: SQL 구문, 토큰 타입, 파싱 상태
- **Storage 함수**: 페이지 I/O, 락 상태, WAL 모드

## 5) 하니스 구현

### `./fuzzers/ours_w_spec/fuzz.c`

하니스 규칙
* `LLVMFuzzerTestOneInput(uint8_t* data, size_t size)` 수정 구현.
* 입력 바이트를 `spec.json`의 `struct_spec`에 맞춰 패킷을 구성.
* `validation_spec`을 반영해 조기 return 조건(경계 부족, 정렬 불일치 등) 추가.
* FC를 포함한 호출 코드로 실제 타겟 함수를 단일 호출 또는 소량 시나리오로 exercise.
* 추가 지시: 단순히 spec.json 구조체 필드를 매핑하는 것에 그치지 말고, context 기반 코드 커버리지의 depth를 최대화할 수 있도록 함수 문맥을 고려해 분기를 여는 입력을 직접 생성·주입하라. 다양한 입력 조건·시나리오(권한 비트, 정수 범위, 체크섬 일치/불일치, 리소스 존재/부재, 경계값, 정렬 위반, 문자열 경계, 시퀀스·상태 전이 등)를 구현하고 입력에서 결정되게 하라.

선언 위치
* 생성기 선언은 /fuzzers/ours_w_spec/fuzz.h에만 작성.
* fuzz.c에는 하니스 관련 함수 선언 금지.

## 6) SQLite3 퍼저 빌드 및 테스트

### 빌드 명령어
```bash
# ours_w_spec 퍼저 빌드 (specification-based)
make ours_w_spec_standalone

# 또는 개별 빌드 스크립트 사용
./build/scripts/build_ours_w_spec.sh

# OSS-Fuzz 환경 빌드
make ours_w_spec_ossfuzz
```

### 동작 테스트
```bash
# 단독 실행 테스트
./ours_w_spec_standalone testcases/basic.sql

# 샘플 입력으로 크래시 테스트  
echo "CREATE TABLE test(id INTEGER);" | ./ours_w_spec_standalone

# 커버리지 모드 테스트
make coverage_ours_w_spec
./ours_w_spec_coverage testcases/basic.sql
```

### 검증 체크리스트
- [ ] 컴파일 에러 없음
- [ ] 기본 SQL 입력 처리 가능 
- [ ] 메모리 누수 없음 (valgrind 권장)
- [ ] 크래시 없이 잘못된 입력 처리
- [ ] 커버리지 데이터 생성 확인

## 7) Git 브랜치 관리 및 커밋

### 1) 새 브랜치 생성
```bash
FUNC_NAME="sqlite3BtreeInsert"  # 예시
BRANCH_NAME="fuzzer/${FUNC_NAME,,}"  # 소문자 변환
git checkout -b $BRANCH_NAME
```

### 2) 변경 파일 스테이징
```bash
# 스펙 파일만 추가
git add fuzzers/ours_w_spec/spec/${FUNC_NAME}_spec.json

# 하니스 코드 추가
git add fuzzers/ours_w_spec/fuzz.c
git add fuzzers/ours_w_spec/fuzz.h

# 빌드 스크립트 변경사항 (필요시)
git add build/scripts/build_ours_w_spec.sh
```

### 3) 커밋 (SQLite3 특화 템플릿)
```bash
FUNC_NAME="sqlite3BtreeInsert"  # 실제 함수명
CATEGORY="B-Tree"               # CSV에서 확인한 카테고리
git commit -m "feat: Add fuzzing harness for ${FUNC_NAME}" \
  -m "- target: ${FUNC_NAME} (${CATEGORY} subsystem)" \
  -m "- spec: Complete function specification with validation rules" \
  -m "- harness: Multi-scenario fuzzing with coverage optimization" \
  -m "- verified: Build success and basic functionality test" \
  -m "" \
  -m "🤖 Generated with [Claude Code](https://claude.ai/code)" \
  -m "" \
  -m "Co-Authored-By: Claude <noreply@anthropic.com>"
```

### 4) 푸시 (항상 새 브랜치)
```bash
git push origin $BRANCH_NAME
```

---

### SQLite3 퍼저 개발 핵심 원칙

1. **실행 가능성 우선**: 하니스는 퍼징으로 **반드시 실행 가능**해야 함
2. **스펙 일치성**: JSON 스펙과 하니스 코드가 **완전 일치**해야 함 (필드/타입/경계)
3. **커버리지 최적화**: 단순 API 호출이 아닌 **내부 분기 탐색**에 중점
4. **메모리 안전성**: 모든 리소스 정리 및 **메모리 누수 방지** 필수
5. **오류 처리**: SQLite3 오류 코드 **체계적 검증** 및 처리

# DO NOT

## 절대 금지사항
* **파일 삭제 금지** - 기존 파일 절대 삭제하지 않음
* **baseline 수정 금지** - `fuzzers/baseline/` 디렉토리 보존
* **소스코드 변경 금지** - SQLite3 원본 소스(`sqlite3.c`, `sqlite3-source/`) 수정 금지
* **분석 데이터 삭제 금지** - `analysis/results/` 기존 데이터 보존

## 제한된 수정 범위
* **허용**: `fuzzers/ours_w_spec/` 하위 파일만 수정/생성
* **허용**: `build/scripts/build_ours_w_spec.sh` 필요시 수정
* **금지**: 다른 퍼저 디렉토리나 분석 도구 무단 수정

## 코딩 제약사항  
* **전역 상태 변경 금지** - SQLite3 전역 설정 변경하지 않음
* **테스트 파일 덮어쓰기 금지** - 기존 테스트케이스 보존
* **빌드 시스템 파괴 금지** - Makefile 핵심 타겟 유지
