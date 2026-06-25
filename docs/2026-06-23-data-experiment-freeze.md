# v0.0 — 데이터·실험 동결 (manifest)

> 2026-06-23 동결. 변경 시 이력 추가. 관련: [`2026-06-23-wemeet-plan.md`](2026-06-23-wemeet-plan.md).

## 데이터 출처
- **dhoogla/csecicids2018** (Kaggle), CICFlowMeter parquet, **정제판(cleaned)**. 라이선스 CC-BY-NC-SA-4.0. 다운로드 2026-06-23 → `sources/cicids2018/`.
- ⚠️ **cleaned이지 relabeled(교정 라벨) 아님** — 라벨은 원본 CIC 그대로(`Attempted` 카테고리 없음). 라벨오류(특히 Infiltration·Web BF) 한계는 보고서에 명시. 라벨 교정 비교가 필요하면 Engelen/ernie55ernie 별도 확보(후속).
- ✅ dhoogla가 **`Dst Port`·`Timestamp`·`Flow ID`·IP를 이미 제거** → 메타데이터 누수 일부 사전 차단됨. (스키마가 `Protocol`부터 시작)

## 파일 인벤토리 (10일, 78컬럼 = 77피처 + Label, 총 6,659,532행)
| 일자(요일) | 파일 prefix | 행수 | 공격 라벨(건수) | sha256(16) |
|---|---|---|---|---|
| 2/14 수 | Bruteforce | 619,346 | SSH-Bruteforce 94,048 / FTP-BruteForce 53 | c4aab044ce25349b |
| 2/15 목 | DoS1 | 794,812 | GoldenEye 41,406 / Slowloris 9,908 | c4016153a96a1e33 |
| 2/16 금 | DoS2 | 591,873 | Hulk 145,199 / SlowHTTPTest 55 | 174d1394ed65d9f5 |
| 2/20 화 | DDoS1 | 954,846 | DDoS-LOIC-HTTP 575,364 | 0a2edf5910123c11 |
| 2/21 수 | DDoS2 | 561,396 | HOIC 198,861 / LOIC-UDP 1,730 | 615f24a8feb234f5 |
| 2/22 목 | Web1 | 830,224 | BF-Web 228 / BF-XSS 79 / SQLi 34 | dfd2b4ab9661e07c |
| 2/23 금 | Web2 | 829,405 | BF-Web 340 / BF-XSS 150 / SQLi 51 | b2e06bd0fca1ca0f |
| 2/28 수 | Infil1 | 456,873 | Infilteration 56,449 | 5ccbff0cb7b2f6a7 |
| 3/01 목 | Infil2 | 249,170 | Infilteration 62,034 | eefc4fbdbbd160bb |
| 3/02 금 | Botnet | 771,587 | Bot 144,535 | 4cd82632e2934593 |

- **극단 불균형 주의:** Web 일자는 공격 비율 ~0.04%(BF-Web/XSS/SQLi 수십~수백 건). FTP-BruteForce·SlowHTTPTest도 수십 건뿐 → 일부 클래스는 통계적으로 빈약(평가 시 명시).

## 이진 타깃 / Attempted
- `y = (Label != 'Benign')` (공격=1).
- 이 정제판엔 `Attempted` 카테고리 **없음** → 별도 처리 불필요. (Engelen 교정판으로 바꾸면 우리 모델링 선택상 `Attempted`는 비공격(0)으로 둠 — 단 저자 권고 아님.)

## 피처셋 (ablation 3종) — 동결
- **F0 Clean-full:** 77피처 전부 − (v0.2에서 검출되는 상수·중복 컬럼). bulk 계열(`Fwd/Bwd Avg Bytes/Bulk` 등)은 0분산 가능 → 검출 후 제거.
- **F1 No-fingerprint:** F0 − {`Fwd Seg Size Min`, `Init Fwd Win Bytes`, `Init Bwd Win Bytes`}.  *(v0.1에서 `Fwd Seg Size Min` 99.2% shortcut 확인)*
- **F2 Robust(헤드라인):** F1 − {`Protocol`}. *(`Dst Port`는 이미 부재)*
- `Flow Bytes/s`·`Flow Packets/s`: 0-duration에서 Inf 가능 → train 기준 cap 또는 결측 처리(정제판이라 대부분 처리됐을 것이나 재검).

## 평가 설계 — 동결
- **분할:** 행 무작위 ❌ → **capture_day 기준 LeaveOneGroupOut**. 테스트 일자는 전처리·피처선택·HPO·보정·임계값에 **일절 미사용**.
- **잠금된 최종 테스트 일자(튜닝 금지):**
  - **2/21(DDoS2)** — train {2/14,15,16,20} → LOIC-UDP는 seen-ish, **HOIC는 unseen-family**
  - **2/23(Web2)** — train {…,2/22} → **같은 공격군 다음날 전이**
  - **3/02(Bot)** — train {2/14~2/23} → **완전 unseen-family stress(open-set)**
  - 2/22 reverse는 민감도, **Infiltration(2/28·3/01)은 부록만**(라벨 불확실)
- **불균형:** SMOTE ❌. train만 `class_weight='balanced'` / `scale_pos_weight`. 보정·임계값은 train-day grouped OOF(자연분포)로.
- **지표(일자별 + 일자 macro):** AP · 공격 P/R/F1 · Balanced Acc · FPR · FP/100k Benign · Brier · log-loss · ECE · 공격군별 Recall · top-1 중요도 집중도.
- **위험점수:** `round(100×보정확률(sigmoid))`. SHAP은 점수에 미포함, 근거+근거품질(집중도) 별도.

## 재현 환경 — 동결
- Python 3.13 · pandas 3.0.2 · numpy 2.4.4 · scikit-learn 1.8.0 · xgboost(2026-06-23 설치 최신) · shap. **→ `requirements.txt`에 정확 버전 핀 고정 예정.**
- 시드 42(주), 43·44(샘플링 반복). CV=LeaveOneGroupOut(capture_day).

## 변경 이력
- 2026-06-23 최초 동결.
