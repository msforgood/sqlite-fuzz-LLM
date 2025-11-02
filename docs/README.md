# 🔬 ALFHA: LLM을 활용한 지능형 퍼징 하니스 생성 기술

> **AI가 스스로 보안을 탐색하고 개선하는 차세대 퍼징 플랫폼**

ALFHA(Automated LLM-based Fuzzing and Harness Agent)는 LLM을 활용해 퍼징 하니스를 자동 생성하고, 코드 구조와 제약조건을 고려하여 보안 테스트 효율을 극대화하는 AI 주도 하니스 생성 기술입니다.

## 🎯 한 줄 요약

**SQLite3을 대상으로 LLM이 스스로 퍼징 하니스를 생성하고 개선하여 기존 OSS-Fuzz 대비 함수 커버리지 2.1배, 브랜치 커버리지 2.6배 향상을 달성한 지능형 퍼징 자동화 프레임워크**

## 🎬 데모 영상

[▶️ Watch the Demo](https://github.com/msforgood/ALFHA/assets/demo.mp4)
[![Watch the demo](https://img.youtube.com/vi/7dXUTrWKGFQ/maxresdefault.jpg)](https://www.youtube.com/watch?v=7dXUTrWKGFQ)


ALFHA가 SQLite3 함수를 자동으로 분석하고, 스펙을 생성하며, 실행 가능한 퍼징 하니스를 자동으로 개발하는 전체 과정을 시연합니다.

## 📊 성능 비교

### 커버리지 성능 비교표

| 구분 | Baseline (OSS-Fuzz) | Plain LLM | **ALFHA (Ours)** | 개선도 |
|------|---------------------|-----------|-------------------|--------|
| **함수 커버리지** | 18.25% (656개) | 29.10% (1,046개) | **38.03% (1,367개)** | **+2.1배** |
| **라인 커버리지** | 12.92% (13,577줄) | 21.62% (22,715줄) | **33.37% (35,059줄)** | **+2.6배** |
| **브랜치 커버리지** | 9.96% (4,716개) | 15.52% (7,349개) | **25.94% (12,288개)** | **+2.6배** |
| **실행 처리량** | 21,532 exec/sec | 2,717 exec/sec | **113,195 exec/sec** | **+5.3배** |

### 핵심 성과

- ✅ **함수 커버리지**: Baseline 대비 약 **2.1배**, Plain LLM 대비 약 **1.3배** 향상
- ✅ **라인 커버리지**: Plain LLM 대비 **11.75%p** 향상으로 더 넓은 코드 경로 탐색
- ✅ **브랜치 커버리지**: 조건 분기 탐색에서 **2.6배** 이상 향상으로 rare branch 탐색 효과 입증
- ✅ **실행 효율**: 초당 처리량 **5배** 이상 개선으로 퍼징 성능 극대화

## 🏗️ 아키텍처

### 전체 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                         ALFHA Framework                     │
├─────────────────────────────────────────────────────────────┤
│  MCP (Model Context Protocol) 기반 확장 가능 구조           │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐      │
│  │ 정적 분석   │  │ 스펙 명세화  │  │ 하니스 생성     │      │
│  │ 모듈        │→ │ 모듈         │→ │ 모듈            │      │
│  └─────────────┘  └──────────────┘  └─────────────────┘      │
│                                           ↓                 │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐      │
│  │ 성능 개선   │← │ 실행 결과    │← │ 퍼징 실행       │      │
│  │ 피드백      │  │ 분석         │  │ 모듈            │      │
│  └─────────────┘  └──────────────┘  └─────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### 핵심 기술 요소

#### 1. **MCP 아키텍처**
- **입력**: 소스/헤더/바이너리 정적분석
- **처리**: 명세·하니스 생성 
- **출력**: 퍼징 실행 로그 취합 
- **피드백**: LLM 기반 성능 개선 루프

#### 2. **Self-Heuristic 프롬프팅**
- LLM이 코드 의미를 단계적으로 추론
- 신뢰성 높은 스펙 명세 자동 생성
- 함수 시그니처·메모리 접근 조건 학습

#### 3. **Coverage Feedback Loop**
- 퍼징 결과 커버리지 자동 분석
- LLM이 하니스를 재보정
- 사람 개입 없는 지속적 최적화

## 🔄 워크플로우

### 3단계 자동화 워크플로우

```
┌─────────────┐    ┌─────────────────────────────┐    ┌─────────────┐
│   1단계     │    │          2단계              │    │   3단계     │
│  환경 구축   │ →  │  LLM 작업 지시 및 자동 검증  │ →  │  결과 확인   │
└─────────────┘    └─────────────────────────────┘    └─────────────┘
      ↓                         ↓                           ↓
 타겟 함수              스펙 명세화 & 하니스 생성        퍼징 실행 &
리스트 작성                   자동화                  성능 분석
```

#### **1단계: 환경 구축**
- 타겟 함수 리스트화 (4,260개 SQLite3 함수 중 Critical/High 우선순위)
- 핵심 프롬프트 상세 기입 (ROLE/RULE/GOAL/DO NOT)
- 실행 가능한 환경 구성

#### **2단계: LLM 작업 지시 및 자동 실행 검증**
- 구조체/검증 조건 분석
- 함수 스펙 명세화 (`spec.json` 생성)
- 하니스 생성 (`harness.c` 생성)
- 빌드/실행 가능 여부 셀프 검증

#### **3단계: 결과 확인**
- 퍼저 실행 및 커버리지 시각화 리포트 자동 생성
- 타겟 함수 리스트 업데이트
- Git 커밋 자동화

### 함수 스펙 명세 예시

```json
{
  "target": {
    "function": "sqlite3BtreeInsert",
    "fc": "btree_001",
    "category": "B-Tree",
    "file": "btree.c",
    "line": 9370
  },
  "struct_spec": {
    "btree_insert_packet": {
      "keySize": "i64",
      "dataSize": "u32",
      "flags": "u8",
      "seekResult": "u8",
      "keyData": "u8[32]",
      "valueData": "u8[64]"
    }
  },
  "validation_spec": {
    "memory_align": 8,
    "key_size": {"min": 0, "max": 2147483647},
    "data_size": {"min": 0, "max": 1000000000},
    "flags": [0, 1, 2, 4, 8]
  }
}
```

## 🚀 시작하기

### 필요 환경

- **OS**: Ubuntu 24.04.2 LTS (권장)
- **컴파일러**: clang-18, LLVM-18
- **Fuzzer**: libFuzzer
- **Sanitizers**: ASAN, UBSAN, LSAN
- **LLM**: Claude Sonnet 4.5 (MCP 서버 연동)

### 설치 및 빌드

```bash
# 1. 저장소 클론
git clone https://github.com/msforgood/ALFHA.git
cd ALFHA

# 2. 의존성 설치
sudo apt-get update
sudo apt-get install -y clang-18 lld-18 lldb-18 llvm-18

# 3. 퍼저 빌드 & 실행 & 커버리지 시각화 자동 생성
./build/build_baseline.sh     # Baseline 퍼저 빌드
./build/build_plain.sh        # Plain LLM 퍼저 빌드
./build/build_alfha.sh        # Alfha 퍼저 빌드

# 4. 커버리지 분석 빌드
# 퍼저 빌드 및 실행 완료 시 커버리지 시각화 자료 생성됨
# txt, html 파일 확인 가능
```


## 📁 프로젝트 구조

```
ALFHA/
├── 📋 docs/                    # 문서 및 연구 자료
│   ├── README.md              # 상세 아키텍처 문서
│   └── [ALFHA] LLM을 활용한 지능형 퍼징 하니스 생성 기술.pdf
├── 🔧 build/                   # 빌드 시스템
│   ├── scripts/               # 빌드 자동화 스크립트
│   ├── configs/               # 설정 파일
│   └── dependencies/          # SQLite3 소스코드
│       ├── sqlite3.c          # Amalgamation (9.0MB)
│       ├── sqlite3.h          # 헤더 파일 (656KB)
│       └── sqlite3-source/    # 개별 소스 (125개 파일, 205,059줄)
├── 🎯 fuzzers/                 # 퍼저 구현체들
│   ├── baseline/              # OSS-Fuzz 기준 퍼저
│   ├── plain/                 # 기본 LLM 퍼저
│   └── alfha/                 # ALFHA 퍼저 (MCP + Self-heuristic)
│       ├── fuzz.c             # 메인 퍼저 코드
│       ├── spec/              # 함수 스펙 명세서들
│       └── *_harness.c        # 함수별 하니스 파일들
├── 📊 analysis/                # 분석 도구 및 결과
│   ├── results/               # 성능 분석 결과
│   │   └── sqlite3_functions.csv # 4,260개 함수 분석 데이터
│   └── tools/                 # 분석 도구들
├── 🎲 corpus/                  # 퍼징 코퍼스
│   ├── alfha/                 # ALFHA 생성 코퍼스
│   └── baseline/              # 기준 코퍼스
├── 🏆 artifacts/               # 퍼징 결과물
│   ├── alfha/                 # ALFHA 발견 크래시/리크
│   ├── baseline/              # 기준 퍼저 결과
│   └── plain/                 # Plain LLM 결과
├── 🧪 tests/                   # 테스트 케이스
│   └── testcases/             # 다양한 SQL 테스트 케이스
└── 📋 Makefile                 # 통합 빌드 시스템
```

## 🎯 기술적 차별성

| 구분 | 기존 접근 | ALFHA | 효과 |
|------|-----------|-------|------|
| **아키텍처** | LLM 수동 입력 중심 | MCP 기반 자동 확장 구조 | 구조적 분석 자동화 |
| **코드 문맥 전달** | 사용자 수동 입력 | 정적분석 + JSON 체계화 | 정확한 컨텍스트 제공 |
| **명세 처리** | 외부 생성/수동 작성 | Self-heuristic 자동 생성 | 사용자 개입 최소화 |
| **피드백 루프** | 단순 1회 생성 | Iterative 성능 개선 | 커버리지 지속 향상 |
| **사용 편의성** | 코드별 설정 필요 | 1-command 수준 단순화 | 하니스 생성 자동화 |

## 🔬 연구 배경

### AI for Security 시대의 도래

- **DARPA AIxCC**: 미국 국방부 주최 AI 기반 사이버보안 경진대회 (상금 270억원)
- **후원사**: OpenAI, Anthropic, Google, Microsoft, Cisco, AWS
- **패러다임 전환**: 사람 중심 → AI 중심 자율형 보안 분석

### LLM의 보안 분야 기술적 진보

- **IRIS (2025, ICLR)**: LLM이 CodeQL 대비 203.7% 향상된 취약점 검출
- **CoT Prompting (2024, arXiv)**: 취약점 식별에서 553.3% 높은 F1 정확도
- **CKGFuzzer (2025, ICSE)**: LLM 기반 하니스가 기존 대비 평균 8.73% 커버리지 향상

## 🏅 연구 성과

### 정량적 성과

- ✅ **함수 커버리지**: 38.03% (Baseline 18.25% 대비 **+2.1배**)
- ✅ **브랜치 커버리지**: 25.94% (Baseline 9.96% 대비 **+2.6배**)
- ✅ **실행 처리량**: 113,195 exec/sec (**5.3배** 향상)
- ✅ **새로운 에러 코드 탐색**: READONLY, TOOBIG, MISMATCH, RANGE, WARNING

### 정성적 성과

- 🎯 **자동화 달성**: 사람 개입 없는 완전 자동 하니스 생성
- 🔄 **확장성 확보**: MCP 구조로 다양한 타겟 프로그램 적용 가능
- 📊 **검증 가능성**: 스펙 명세서와 실행 로그로 결과 검증
- 🚀 **실용성 입증**: 실제 SQLite3에서 rare branch 탐색 성공

## 🔮 향후 발전 계획

### 기술적 확장

- **다중 모델 협력**: 코드 이해·테스트 생성·결과 해석 분리형 MCP
- **강화학습 적용**: Coverage gradient 기반 하니스 최적화
- **하니스 QA 모듈**: 생성 하니스의 안정성·재현성 자동 검증

### 적용 영역 확장

- **시스템 소프트웨어**: 커널, 네트워크 스택, IoT 펌웨어
- **NASA cFS**: 우주항공 시스템 검증
- **산업 표준**: MISRA-C, ISO 26262 준수 코드 검증

## 🤝 기여 방법

### 버그 리포트

이슈 발견 시 [GitHub Issues](https://github.com/msforgood/ALFHA/issues)에서 다음 정보와 함께 리포트해주세요:

- 실행 환경 (OS, 컴파일러 버전)
- 재현 단계
- 예상 결과 vs 실제 결과
- 관련 로그 파일

## 📜 라이선스

본 프로젝트는 [MIT License](LICENSE) 하에 배포됩니다.

## 🧑‍💻 연구진

**Kyung Hee University PWNLAB**
김민서, 장대희

2025 AI 기반 취약점 발굴 시스템 공모전 출품작

---

<div align="center">

**🤖 Generated with Claude Code & Human Intelligence**

*ALFHA는 AI와 보안이 상호 진화하는 미래를 위한 첫걸음입니다.*

</div>