# 사이버보안 WE-Meet — 실행계획 (개발 마일스톤)

> 작성 2026-06-23 · **2026-06-23 GPT-5.5 Pro 리뷰 검증 후 반영본**. 전제: **주제 최종확정 전**(잠정). 상세 근거는 [`2026-06-23-wemeet-ai-ids-research.md`](2026-06-23-wemeet-ai-ids-research.md). 진행 현황은 루트 `progress.md`.

## 0. 전제 · 현재 상태
- **잠정 주제(제목 수정):** AI 기반 **네트워크 침입 탐지·triage** — *"보안로그 분석"은 제외*. 현재 데이터(CSE-CIC-IDS2018)는 **네트워크 flow**(CICFlowMeter)이지 시스템/엔드포인트 로그가 아니므로, 실제 로그를 추가하지 않는 한 제목·서술에서 "로그 분석"·"실시간"은 빼고 **"flow 종료/timeout 후 탐지"**로 정의.
  - 권장 제목(영): *Shortcut-Aware, Calibrated Network Intrusion Triage: Day-Disjoint Evaluation with SHAP-Grounded LLM Explanations*
- **데이터셋:** CSE-CIC-IDS2018 — **Improved(교정판) 한 종류로 통일** 사용 권장(원본 라벨오류 多).
- **팀:** 팀장(데이터·모델·평가·문서) · 팀원(에이전트 구조·시각화·통합테스트). 2인.
- **현재:** v0.1 완료. RF/XGBoost F1=1.0 — 단 **피처 `Fwd Seg Size Min` 하나가 99.2%** = 단일 지름길 artifact, 일반화 불가. 파이프라인 동작은 확인.

## 1. 핵심 설계 (요약)
`데이터 → 전처리 → RF/XGBoost 이진분류 → 위험점수(보정확률) → SHAP 근거 → LLM 자연어 설명 → Streamlit`
- **원칙: 탐지·점수·우선순위는 ML이 결정, LLM은 변경 불가(설명만).**
- **차별점(재정의):** 알고리즘/에이전트 novelty가 아니라 **① shortcut-aware 날짜교차 평가 ② 비권한 LLM 경계(immutable JSON 설명만) ③ 보정확률 기반 analyst triage**. (상세 §6)

## 2. 개발 마일스톤
각 단계 = 목표 / 작업 / **완료기준** / 산출물 / 담당. **우선순위 v0.2 > v0.4 > v0.3 > v0.6 > v0.5.**

| 단계 | 목표 | 핵심 작업 | 완료기준 | 산출물 | 담당 |
|---|---|---|---|---|---|
| **v0.0** ⭐신규 | 데이터·실험 동결 | Improved 데이터 manifest(파일명·SHA-256·행수·라벨수), `Attempted` 처리규칙, 제거 피처 목록, **최종 테스트 날짜 잠금**, 시드·라이브러리 버전 | manifest 1장 + 첫 날짜분리 결과 1회 생성 | `manifest.md`, config | 팀장 |
| **v0.1** ✅ | 베이스라인 | 1일치 로드·청소·RF/XGB·평가 | 파이프라인 end-to-end 동작 | `train_baseline.py`, `metrics_v01.json` | 팀장 |
| **v0.2** | **정직한 평가**(최우선) | 다중 공격일자 결합 + **F0/F1/F2 피처셋 ablation** + **날짜 교차(LeaveOneGroupOut by capture_day)** + RF/XGB 비교(여기서만) → **최종 모델·피처셋 하나 확정**. **SMOTE 금지**(train만 class_weight/scale_pos_weight) | 학습/테스트 날짜 완전 분리, 일자별 AP·F1·Recall·FP/10만·Brier 재현 | `eval_honest.py`, `metrics_v02.json`, 분석노트 | 팀장 |
| **v0.3** | SHAP 근거 | 최종 모델 1개의 global/local SHAP, top-1 집중도 | 공격 20건·오탐 20건 local 설명 + 전역 중요도 | `explain.py`, plots | 팀장 |
| **v0.4** | **위험점수**(재설계) | **sigmoid 보정(grouped OOF) → `R₀=round(100×보정확률)`**. SHAP은 점수에 더하지 않고 **근거 + "근거품질"(단일피처 집중도) 별도 축**으로. P1~P3 임계는 검증데이터 최악날짜 기준 | 보정 전후 reliability·Brier·ECE 비교, 임계값 검증데이터로만 결정 | `risk_score.py`, calibration curve | 팀장 |
| **v0.5** | LLM 설명 | immutable JSON(label·risk·threshold 변경불가) → LLM 5섹션 설명, JSON검증 실패시 템플릿, IP 마스킹 | LLM이 수치·판정 못 바꿈 + 폴백 동작 | `llm_explainer.py` | 팀원 |
| **v0.6** | Streamlit | 저장 모델·고정 샘플 재생, 결과·근거·성능 3화면 이내 | 로컬 실행, 동일 입력 동일 출력 | `app.py` | 팀원 |
| ~~v0.7~~ | ~~에이전트+MITRE~~ | **삭제 — 4주 범위 밖.** 발표자료 "향후 과제"로만 | — | — | — |

## 3. 정직한 평가 프로토콜 (보고서 신뢰도의 핵심 = 우리 최대 기여)
- **단일일자/무작위분할 고정확도는 상한일 뿐 배포성능 아님** — v0.1에서 직접 확인.
- **피처셋 3종 ablation:** `F0`(직접누수·상수·중복만 제거) / `F1`(F0 − `Fwd Seg Size Min`·`Init Fwd/Bwd Win Byts`) / `F2 Robust`(F1 − `Src/Dst Port`·`Protocol`). **헤드라인 = F2**, F0=나이브 상한, F1=원인분석.
- **날짜 교차 fold:** 같은 공격군 전이(예: Web 2/22→2/23)와 **unseen-family 스트레스**(예: Bot 3/2)를 **구분**. Infiltration(2/28·3/1)은 라벨 불확실 → 부록만.
- **SMOTE 금지**(분할 전 SMOTE=누수). train에만 class_weight/scale_pos_weight. 보정은 자연분포 OOF로.
- **`Attempted` 처리:** flow 특징만으론 benign과 구분 불가 → **이진 타깃에서 공격(1)으로 두지 않음**(=비공격 취급). ⚠️ 단 이는 *우리 모델링 선택*이며, 교정판 저자는 `Attempted`를 별도 라벨로 **유지**한다(병합 권고 아님 — 인용 주의).
- **누수 감사 절차:** ① 피처 provenance 표 ② single-feature 날짜분리 검사(AP>0.9 경고) ③ 피처로 capture_day 예측되나 검사 ④ 일자별 중요도 안정성(top-1 집중도). `Dst Port` 단독으로 IDS 데이터셋 70~100% 분리됨(D'hooge, DIMVA 2022) → 포트는 주 모델 제거, 포함모델은 "service-aware baseline"로 별도 표기.
- **지표(일자별 + 일자 macro):** AP · 공격 P/R/F1 · Balanced Acc · FPR · **FP/100,000 Benign** · Brier · log-loss · ECE · 공격군별 Recall · top-1 SHAP 집중도. (accuracy 단독·pooled F1 단독 금지)

## 4. 일정·멘토링·산출물 (compact)
- **운영:** 6.22~7.17 (0~3주차). 팀 계획서 제출 완료.
- **4주 배치:** 0주차 평가기반 고정(v0.0)+골격 / 1주차 v0.2(모델·피처셋 확정) / 2주차 v0.3~v0.4 / 3주차 v0.5~v0.6+문서(마지막 2~3일 모델 동결, 보고서·일지·통합테스트만).
- **멘토링 3회 필수**(누락=이수불가): ~6.26 / ~7.3 / ~7.10. 회차 당일 일지+증빙(사진·날짜 일치). **일지에 "발견(F1=1.0이나 단일피처 99.2%)→판단(평가설계 수정)→검증" 의사결정 서사 남기기.**
- **제출:** 일지 1·2·3차 + 결과보고서 **~7.10**, 이수 **~7.17**. 보고서=논문 아님(배경/목표·수행·문제해결/활용·기대효과/소감/활동사진).

## 5. 리스크 · 미확정
- **미확정:** 주제 최종확정 · 팀원 가용시간 · 멘토 기업 배정 · 개발환경 · 제출 채널 · Improved 데이터 정확 버전/해시.
- **리스크:** ① 6/29~7/3 팀장 전체 불가(1주차+2차 멘토링 충돌) ② 2인 과부하 → 지연 시 제거 순서 **v0.7(이미삭제)→LLM설명→XGB비교** (RF+보정+SHAP+날짜분리+Streamlit는 사수) ③ 라벨오류·교정라벨 순환성(Web BF는 `Tot Fwd Pkts>20`로 재라벨 → `Tot Fwd Pkts/Byts` 제거 민감도 실험 1회).

## 6. 차별점 (novelty — 정직 버전)
알고리즘/에이전트 최초성은 **주장하지 않음**(IDS-Agent·LogRESP-Agent가 더 강한 에이전트). 우리 기여는 **시스템·평가**:
1. **Shortcut-aware evaluation** — 오류 알려진 벤치마크에서 무작위분할 과대평가를 드러내고, 교정라벨·날짜분리·artifact ablation으로 일반화를 재측정. (최대 기여)
2. **비권한 LLM 경계** — LLM은 ML·보정이 만든 immutable JSON을 설명만, 판정·점수 변경 불가(재현성·인젝션·환각 위험 의도적 제한).
3. **Calibrated analyst triage** — 정확도뿐 아니라 보정확률·FPR 기반 우선순위·SHAP 근거품질을 분석가용 화면으로 통합.
- ~~"SHAP+확률 융합 위험점수"~~ → **폐기.** SHAP은 모델 출력의 분해라 보정확률에 더하면 이중계산(GPT 검증 확인). 위험점수는 보정확률, SHAP은 근거/품질로 분리.

---
### 검증 메모 (2026-06-23 GPT 리뷰 대비)
- ✅ 채택: SHAP 비융합·R₀=보정확률, no-SMOTE, 날짜교차, F0/F1/F2, 메타데이터 contaminant(Dst Port, D'hooge 2022 실재확인), "보안로그/실시간" 제목 수정, v0.0 동결, novelty 하향.
- ⚠️ 주의(검증서 교정): `Attempted→Benign`은 *우리 선택*이지 저자 권고 아님(교정판은 별도 유지). IDS-Agent OpenReview ID는 `uuCcK4cmlH`(GPT가 틀린 ID 인용). 메타-risk 융합공식(σ[β…])은 범위 밖 → 단순 R₀ + 근거품질 별도축만.
