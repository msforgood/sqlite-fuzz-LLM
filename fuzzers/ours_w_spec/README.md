# SQLite3 Fuzzer Version 2 (ours_w_spec)

## 개요

`ours_w_spec`는 명세 기반 추가 최적화가 적용된 고급 SQLite3 퍼저입니다. `ours_wo_spec` (버전 1) 기반으로 SQLite3 명세서 분석을 통한 추가 개선사항이 적용되었습니다.

## 주요 개선사항 (vs ours_wo_spec)

### 1. 명세 기반 테스트 케이스 생성
- SQLite3 공식 문서 기반 SQL 구문 생성
- SQL-92/SQL-99 표준 준수 테스트
- 복잡한 쿼리 패턴 체계적 생성

### 2. 향상된 에러 시나리오
- 명세서의 에지 케이스 및 제약사항 테스트
- 타입 변환 경계값 테스트
- 메모리 및 리소스 한계 테스트

### 3. 고급 SQL 구문 지원
- 복잡한 조인 패턴
- 서브쿼리 및 CTE (Common Table Expression)
- 윈도우 함수 및 집계 함수 조합

## 빌드 및 실행

```bash
# 빌드
make ours_w_spec

# 실행
./ours_w_spec_standalone tests/testcases/sql/basic.sql
```

## 성능 비교

| 메트릭 | ours_wo_spec | ours_w_spec | 개선도 |
|--------|--------------|-------------|---------|
| 커버리지 | TBD | TBD | TBD |
| 신규 함수 | TBD | TBD | TBD |

## 개발 상태

🚧 **현재 개발 중** - 명세 기반 최적화 구현 예정

다음 구현 예정 기능:
- [ ] SQL 명세 기반 구문 생성기
- [ ] 고급 에러 시나리오 테스트
- [ ] 성능 벤치마크 및 비교