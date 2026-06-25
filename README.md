# 사이버보안 WE-Meet — AI 기반 공격탐지 에이전트

> 네트워크 침입 탐지(NIDS) + 보안로그 분석.
> 충남대 하기 계절학기 산학협력(WE-Meet) 팀 과제. 데이터셋 **CSE-CIC-IDS2018**.

---

## 한 줄 요약

네트워크 통신기록으로 **정상/공격을 분류**하고, 각 경보에 **위험점수·근거(SHAP)·자연어 설명**을 붙여 분석가가 우선 처리하게 돕는 시스템. 핵심은 "정확도 자랑"이 아니라 **"어디까지 믿을 수 있는지 정직하게 측정"** 한 것.

## 우리 프로젝트의 핵심 스토리 (이거 하나만 보면 됨)

1. **함정 발견** — 하루치 데이터로 학습/평가하니 F1 = **1.000(100%)** 이 나왔다. 그런데 모델 중요도의 **99%를 단일 피처(`Fwd Seg Size Min`)** 가 차지 = 공격 행위가 아니라 데이터 생성 특성을 외운 **지름길(shortcut) 허상**이었다.
2. **정직한 평가로 전환** — 무작위 분할 대신 **날짜 교차(과거로 학습 → 미래의 새 공격 탐지)** 로 바꾸자, 미관측 공격 탐지율이 **0에 가깝게** 떨어졌다. 무작위 분할의 고성능은 환상.
3. **원인 규명** — "모델/표현이 부족해서"가 아니라, 그날 안에선 100% 구분되는데(target-day oracle: Bot 0.996) **과거 규칙이 미래의 다른 공격으로 안 넘어가는 전이(분포 변화)** 문제임을 입증.
4. **개선** — 시간맥락(temporal) 피처(목적지 포트별 시간창 집계·반복 규칙성·연결 실패율)를 추가해 미관측 공격 탐지율을 끌어올림:

   | 공격군 | 기존 | +시간맥락 | 비고 |
   |---|---|---|---|
   | Bot(봇넷) | 0.009 | **0.49** | 큰 상승 |
   | DoS | 0.51 | **0.62** | |
   | DDoS | 0.38 | **0.50** | |
   | BruteForce | 0.74 | **0.98** | 첫 공격일(cold-start) |
   | Web(XSS/SQLi) | 0.02 | 0 | 구조적 한계(payload 없음·flow 희소) |

   *(오탐 약 15~18건/10만 flow 기준. 수치는 탐색 결과로, 재현 검증 중. 실제 지표 원본은 `output/metrics_*.json` 참고.)*
   *(공격군마다 최적 시간창이 달라: Bot=장기창 포함, DoS/BruteForce=단기창이 더 나음.)*
5. **결론** — 단일 ML로 모든 공격을 다 잡는 건 단일 데이터셋에서 불가능(학계 공통). 그래서 현업은 **다층 방어(SIEM+NDR+EDR)** 를 쓴다. 우리 기여 = **① 정직한 평가 방법 ② 시간맥락으로 미관측 탐지 개선 ③ 단일 ML 한계의 실증**.

## 시스템 파이프라인

```
데이터 → 전처리 → RF/XGBoost 이진분류 → 0~100 위험점수(conformal) → SHAP 근거 → LLM 설명 → Streamlit 대시보드
```
- **탐지·점수·우선순위는 ML이 결정. LLM은 판정을 못 바꾸고 설명만 한다** (재현성·프롬프트 인젝션 방지).

## 폴더 구조

| 폴더 | 내용 | git 포함 |
|---|---|---|
| `src/` | 전체 코드(학습·평가·위험점수·SHAP·설명·대시보드·시간맥락) | ✅ |
| `docs/` | 조사노트·설계·결과보고서 초안·참고문헌 | ✅ |
| `progress.md` | 진행 일지(시간순 전체 기록) | ✅ |
| `sources/` | 원본 데이터(6.8GB) — 용량/공개 이유로 제외, S3에서 받음 | ❌ |
| `paper/` | 교수님 제공 논문 PDF(저작권) | ❌ |
| `output/metrics_*.json` | 단계별 평가 지표(수치 검증용) | ✅ |
| `output/`(그 외) | 모델·PPT·보고서·SHAP 그림 등 대용량/개인정보 | ❌ |

> 데이터·산출물 바이너리는 용량·개인정보·저작권 때문에 git에서 제외. **제출용 최종 파일(PPT·hwpx·docx)은 팀에 별도 공유**.

## 코드 한눈에 (src/, 전체 28개)

| 파일 | 역할 |
|---|---|
| **핵심 ML 파이프라인** | |
| `train_baseline.py` | v0.1 베이스라인(여기서 100% 함정 발견) |
| `eval_honest.py` / `eval_allfolds.py` | 날짜교차 정직 평가(전 공격군 9 fold) |
| `temporal_cache.py` / `temporal_cache2.py` | **시간맥락 피처 생성**(원본 Timestamp → 포트별 시간창 집계) |
| `temporal_eval.py` / `temporal2_eval.py` / `temporal.py` | **시간맥락 평가(핵심 개선)** |
| `temporal_operational.py` | 시간맥락 운영 임계값 검증 |
| `conformal_triage.py` / `calibrate_triage.py` / `threshold_policy.py` | 위험점수·분포무관 오탐 제어·운영 임계값 |
| **분석·검증** | |
| `diagnose.py` / `verify_limit.py` | 병목이 "표현"이 아니라 "전이"임을 규명 |
| `explain.py` / `llm_explainer.py` | SHAP 근거 + 자연어 5섹션 설명 |
| **추가 실험(개선 시도)** | |
| `multiclass.py` | 6클래스 다중분류 |
| `domain_general.py` | 도메인 일반화(날짜불변 피처+OR) |
| `deepsad.py` / `novelty.py` | 반지도 이상탐지·novelty(둘 다 unseen엔 실패) |
| **산출물 생성** | |
| `app.py` / `build_demo.py` | Streamlit 대시보드 + 샘플 데이터 |
| `build_deck.py` | 멘토 소개용 PPT 생성 |
| `build_report_hwpx.py` / `fill_report.py` / `build_log_hwpx.py` / `build_docx.py` | 결과보고서·수행일지 문서 생성 |
| **보조** | |
| `log_analysis.py` | 보안로그(Windows 이벤트) 분석 보조 |

## 데이터 준비 & 실행

```bash
pip install -r requirements.txt
```

**1) 데이터 받기** (repo엔 용량 때문에 없음):
- 정제판(권장, ~690MB): Kaggle `dhoogla/csecicids2018` 10일치 parquet → `sources/cicids2018/` 에 저장
- 원본(시간정보 포함): AWS 공개버킷 `s3://cse-cic-ids2018/` (인증 불필요)

**2) 실행 순서**:
```bash
python src/eval_honest.py          # v0.2 날짜교차 정직 평가  → output/metrics_v02.json
python src/conformal_triage.py     # v0.4b 위험점수·오탐 제어 → output/metrics_v04b.json
python src/temporal_cache.py       # 시간맥락 피처 생성(★ 원본 Timestamp 필요)
python src/temporal_eval.py        # 시간맥락 평가          → output/metrics_temporal.json
python src/explain.py              # SHAP 근거
python src/build_demo.py           # 대시보드용 샘플 생성
python -m streamlit run src/app.py # 대시보드
```

> ⚠️ **재현 한계(정직하게):** Kaggle 정제판은 **Timestamp·IP가 제거**되어 있어 시간맥락 피처(`temporal_*`)를 **그대로 재현할 수 없다.** temporal 결과를 재현하려면 원본 CSV(AWS S3, Timestamp 포함)가 필요하다. 이 때문에 핵심 수치는 `output/metrics_*.json`에 **스냅샷으로 동봉**해 두었다(코드 실행 없이 수치 확인 가능).

## 데이터 출처

CSE-CIC-IDS2018 (CSE + Canadian Institute for Cybersecurity, 2018).
⚠️ 원본 라벨에 알려진 오류 있음(Infiltration·웹 브루트포스) + 공개 정제판은 IP/Timestamp 제거됨 → 한계는 `docs/`에 명시. 참고문헌 전체는 `docs/references.md`.

---
*팀: 컴퓨터융합학부 2인. 자세한 진행은 `progress.md`, 설계 근거는 `docs/` 참고.*
