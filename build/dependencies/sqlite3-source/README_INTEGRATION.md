# SQLite3 소스코드 통합 가이드

## 개요

이 디렉토리는 SQLite3 공식 소스코드 (v3.51.0)를 포함하며, 고도화된 퍼저 개발을 위한 상세 분석 및 참조용으로 사용됩니다.

## 디렉토리 구조

```
sqlite3-source/
├── src/                    # SQLite3 핵심 소스코드 (125개 파일, 205,059줄)
├── test/                   # SQLite3 공식 테스트 스위트
├── VERSION                 # 버전 정보 (3.51.0)
└── README.md              # SQLite3 공식 README
```

## 주요 소스 파일 분석

### 핵심 엔진 파일
- **`btree.c`** (403,240줄): B-Tree 인덱스 관리
- **`vdbe.c`** (4,800+줄): Virtual Database Engine
- **`build.c`** (195,668줄): SQL 파싱 및 빌드
- **`select.c`**: SELECT 문 처리
- **`expr.c`**: 표현식 평가

### 퍼저 개발에 중요한 영역
1. **파서 계층**: `parse.y`, `tokenize.c`, `expr.c`
2. **VDBE 계층**: `vdbe*.c` 파일들
3. **B-Tree 계층**: `btree.c`, `btreeInt.h`
4. **메모리 관리**: `malloc.c`, `mem*.c`
5. **확장 기능**: `json.c`, `fts*.c`

## 퍼저 개발 활용법

### 1. 커버리지 분석
```bash
# 특정 소스 파일의 함수 목록 추출
grep -n "^[a-zA-Z_][a-zA-Z0-9_]* *(" src/btree.c | head -20

# 복잡한 함수 식별 (행 수 기준)
wc -l src/*.c | sort -nr | head -10
```

### 2. 함수 호출 관계 분석
```bash
# 특정 함수가 호출하는 다른 함수들
grep -n "sqlite3" src/vdbe.c | grep "(" | head -10

# 함수 정의 vs 호출 분석
grep -c "^sqlite3" src/*.c
```

### 3. 에러 처리 패턴
```bash
# 에러 코드 사용 패턴
grep -n "SQLITE_" src/*.h | grep "#define" | head -20

# 에러 처리 코드 패턴
grep -n "return SQLITE_" src/*.c | wc -l
```

## 테스트 케이스 분석

### 공식 테스트 구조
- **총 테스트 파일**: 2,000+ 개
- **커버리지 범위**: 모든 주요 SQLite3 기능
- **퍼저 참조 파일**: `test/fuzz*.c`, `test/ossfuzz.c`

### 퍼저 개발에 유용한 테스트
1. **`test/ossfuzz.c`**: OSS-Fuzz 기준 구현
2. **`test/fuzz*.test`**: 퍼징 테스트 케이스
3. **`test/malform*.test`**: 잘못된 입력 처리
4. **`test/corrupt*.test`**: 데이터베이스 손상 시나리오

## 고도화 퍼저 개발 방향

### 1. 소스코드 기반 타겟팅
- 복잡도가 높은 함수 우선 타겟팅
- 에러 처리 경로 체계적 테스트
- 메모리 할당/해제 패턴 분석

### 2. 함수별 특화 테스트
```c
// 예: B-Tree 함수 특화 퍼징
// btree.c의 주요 함수들:
// - sqlite3BtreeInsert()
// - sqlite3BtreeDelete() 
// - sqlite3BtreeMovetoUnpacked()
```

### 3. 확장 기능 커버리지
- JSON 함수 (`json.c`)
- FTS (Full-Text Search) 
- R-Tree 인덱스
- 가상 테이블

## 빌드 스크립트 통합

현재 퍼저 빌드 스크립트는 amalgamation 파일 (`sqlite3.c`)을 사용하지만, 필요시 개별 소스 파일을 직접 빌드할 수 있습니다:

```bash
# 개별 파일 빌드 예제
gcc -c src/btree.c -I. -DSQLITE_ENABLE_DEBUG=1
gcc -c src/vdbe.c -I. -DSQLITE_ENABLE_DEBUG=1
```

이를 통해 특정 모듈에 대한 상세한 디버깅 및 분석이 가능합니다.