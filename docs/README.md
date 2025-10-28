# 고도화 SQLite3 퍼저 아키텍처

## 개요

본 프로젝트는 다중 모드 퍼징과 지능형 테스트 케이스 생성을 통해 코드 커버리지를 대폭 향상시킨 SQLite3용 고도화 퍼징 프레임워크를 제시합니다.

## 핵심 아키텍처

### 1. 다중 모드 퍼징 엔진

고도화 퍼저는 7가지 전문화된 테스트 모드를 구현합니다:

```c
typedef enum {
    FUZZ_MODE_BASIC = 0,        // 기존 ossfuzz 동작 방식
    FUZZ_MODE_TRANSACTION,      // 트랜잭션 중심 테스트  
    FUZZ_MODE_SCHEMA,          // 스키마 조작 테스트
    FUZZ_MODE_FUNCTIONS,       // 내장 함수 테스트
    FUZZ_MODE_BLOB,            // 대용량 데이터 처리
    FUZZ_MODE_CONCURRENT,      // 다중 연결 시나리오
    FUZZ_MODE_ERROR_INJECTION, // 에러 조건 테스트
} FuzzMode;
```

각 모드는 특정 SQLite3 하위 시스템을 대상으로 하여 코드 커버리지를 최대화합니다.

### 2. 향상된 컨텍스트 추적

```c
typedef struct AdvancedFuzzCtx {
    sqlite3 *db;
    sqlite3 *db2;              // 동시 테스트용 두 번째 연결
    sqlite3_int64 iCutoffTime;
    FuzzMode mode;
    uint8_t flags;             // 설정 플래그
    int schemaVersion;         // 스키마 변경 추적
    int transactionDepth;      // 트랜잭션 중첩 추적
    size_t totalMemUsed;       // 메모리 사용량 추적
} AdvancedFuzzCtx;
```

### 3. 지능형 SQL 생성

각 모드는 전문화된 SQL 생성기를 구현합니다:

- **스키마 모드**: CREATE/ALTER/DROP 시퀀스 생성
- **트랜잭션 모드**: 세이브포인트를 포함한 복잡한 트랜잭션 패턴 생성
- **함수 모드**: SQLite 내장 함수 체계적 테스트
- **BLOB 모드**: 대용량 데이터 처리 및 경계값 테스트

## 기준 퍼저 대비 주요 개선사항

### 1. 커버리지 향상

| 구성요소 | 기준 퍼저 | 고도화 퍼저 | 개선도 |
|----------|-----------|-------------|---------|
| 라인 커버리지 | 3.44% | 4.19% | +21.7% |
| 함수 커버리지 | 686개 | 783개 | +97개 함수 |
| 신규 발견 함수 | 0개 | 144개 | 새로 발견 |

### 2. 고급 기능

- **상태 추적**: 트랜잭션 깊이 및 스키마 버전 모니터링
- **메모리 관리**: 실시간 메모리 사용량 추적 및 제한
- **에러 탐색**: 체계적인 에러 조건 생성
- **향상된 디버깅**: 환경변수 기반 디버그 플래그 설정

### 3. 안전성 개선

- 메모리 한계 증가 (25MB vs 20MB) 및 실시간 모니터링
- 진행률 추적을 통한 향상된 타임아웃 메커니즘
- 개선된 에러 처리 및 복구
- 종료 시 트랜잭션 상태 정리

## 성능 분석 프레임워크

### 1. 커버리지 분석 도구

- **GCov 통합**: 라인별 커버리지 분석
- **LLVM 커버리지**: HTML 출력이 포함된 고급 커버리지 리포팅
- **함수 추적**: 상세한 함수 호출 빈도 분석

### 2. 자동화된 비교

```bash
# 자동화된 성능 비교
make analysis

# 생성 결과:
# - 커버리지 차이 리포트
# - 함수 발견 분석  
# - 성능 메트릭 비교
```

### 3. 재현 가능한 테스트

- 표준화된 테스트 케이스 세트
- 결정론적 빌드 프로세스
- 버전 관리된 분석 스크립트

## 빌드 시스템 아키텍처

### 1. 모듈형 빌드 시스템

```
build/
├── scripts/           # 빌드 자동화
├── configs/          # 설정 파일
└── dependencies/     # 외부 의존성
```

### 2. 다중 타겟 지원

- **독립실행형**: 독립적인 테스트 실행 파일
- **OSS-Fuzz**: LibFuzzer 통합을 통한 연속 퍼징
- **커버리지**: 분석용 계측 빌드

### 3. 자동화된 테스트

```makefile
# 다양한 사용 사례별 Makefile 타겟
all: baseline ours_wo_spec        # 양 퍼저 빌드
coverage: build with coverage     # 커버리지 계측 빌드
analysis: run performance tests   # 자동화된 비교
```

## 버전 구분 체계

### 1. 퍼저 버전

```
fuzzers/
├── baseline/         # OSS-Fuzz 기준 퍼저들
├── ours_wo_spec/    # 우리 퍼저 버전 1 (기본 고도화)
└── ours_w_spec/     # 우리 퍼저 버전 2 (사양 기반 고도화)
```

### 2. 버전별 특징

- **ours_wo_spec**: 다중 모드 퍼징 기반 기본 고도화 버전
- **ours_w_spec**: 명세 기반 추가 최적화가 적용된 고급 버전

### 3. 성능 비교 체계

각 버전에 대해 독립적인 성능 분석 및 비교가 가능합니다:

sudo apt-get update
sudo apt-get install -y clang-18 lld-18 lldb-18 llvm-18

./build/scripts/build_coverage.sh
./analysis/scripts/run_coverage_comparison.sh

```bash
# 특정 버전 빌드
make baseline        # 기준 퍼저
make ours_wo_spec   # 기본 고도화 버전
make ours_w_spec    # 고급 고도화 버전

# 버전별 성능 비교
make analysis_wo_spec  # 기본 버전 vs 기준
make analysis_w_spec   # 고급 버전 vs 기준
make analysis_full     # 전체 버전 비교
```

## 향후 개선 계획

### 1. 계획된 개선사항

- **동적 모드 선택**: 커버리지 피드백 기반 적응형 모드 전환
- **머신러닝 통합**: 커버리지 가이드 테스트 케이스 생성
- **분산 퍼징**: 다중 프로세스 퍼징 조정

### 2. 확장 분석

- **변이 분석**: 코드 변경 영향 평가
- **회귀 테스트**: 자동화된 회귀 감지
- **성능 프로파일링**: 상세한 성능 병목 분석

## 공모전 출품 구조

프로젝트는 쉬운 평가를 위해 체계적으로 구성되었습니다:

```
custom-sqlite-fuzzer/
├── docs/             # 완전한 문서화
├── fuzzers/         # 소스코드 (기준 vs 고도화 버전들)
├── build/           # 빌드 시스템 및 의존성  
├── tests/           # 테스트 케이스 및 데이터
├── analysis/        # 분석 도구 및 결과
├── examples/        # 사용 예제 및 데모
└── Makefile         # 간단한 빌드 인터페이스
```

이 아키텍처는 기존 OSS-Fuzz 인프라와의 호환성을 유지하면서 퍼징 기술의 상당한 발전을 보여줍니다.