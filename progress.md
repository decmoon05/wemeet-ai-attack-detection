# 진행 상황 (progress)

## 2026-06-23
- 주제(잠정): AI 기반 공격탐지 에이전트 — 네트워크 이상탐지 + 보안로그 분석. **주제 최종확정 전**.
- 데이터셋: **CSE-CIC-IDS2018** 확정.
- 조사 완료: 논문 21편 + 교수님 제공 3편(Sensors 리뷰 / Cloud GenAI / LogRESP-Agent) + GitHub 레포 + 개발자원 → `docs/2026-06-23-wemeet-ai-ids-research.md`.
- 발표자료 개선본 제작 완료(`output/발표자료/사이버보안 we-meet 발표자료_개선.pptx`).
- 정리: 메모리를 목차(MEMORY.md)+상세 4개(overview/decisions/findings/references)로 재구성. 디렉토리 정리 — 행정문서→`sources/program/`, 발표자료→`output/발표자료/`, 임시폴더(_wemeet_analyze) 삭제.
- 실행계획 `docs/2026-06-23-wemeet-plan.md` 작성 → **GPT-5.5 Pro 리뷰 검증 후 반영**: 위험점수 비융합(`R₀=round(100×보정확률)`), no-SMOTE, 날짜교차 F0/F1/F2 평가, novelty 재정의(shortcut-aware 평가+비권한 LLM+보정 triage), 제목 "보안로그/실시간" 제외, v0.0 데이터·실험 동결 추가, v0.7 삭제.

### v0.1 베이스라인 — 완료 (단, 결과는 "빨간불")
- [x] 프로젝트 구조 생성 / `src/train_baseline.py` 작성
- [x] 데이터 다운로드: Wednesday-14-02 (FTP/SSH BruteForce, 341MB, 1,048,575행×78피처, 공격비율 0.36)
- [x] 패키지 설치(xgboost·shap·streamlit·pyarrow)
- [x] v0.1 실행: RF/XGBoost 모두 **F1=1.0000**(XGB 학습 12s, RF 27s) → `output/metrics_v01.json`, `model_v01.joblib`
- 🚩 **100%는 허수.** 피처 중요도 1위 `Fwd Seg Size Min`이 **99.2%** 차지 = 단일 지름길로 풂. 일반화 X.
  - 원인: 단일 공격유형(BruteForce)·단일 일자 + 데이터 생성 artifact 피처. 문헌 경고(단일 데이터셋 고정확도 신뢰 금지)를 **우리 데이터로 직접 확인**.
- 다음: ① 다중 공격일자 결합 ② 지름길 피처 ablation(빼고 재측정) ③ 일자 교차 일반화 테스트(train days ≠ test days)

### v0.0 데이터·실험 동결 — 완료
- [x] Kaggle 정제판(dhoogla/csecicids2018) **10일치 parquet ~690MB** → `sources/cicids2018/`
- [x] 데이터 감사 → manifest `docs/2026-06-23-data-experiment-freeze.md` (78컬럼·666만행·일자별 라벨·sha256, 피처셋 F0/F1/F2, 잠금 테스트일자 2/21·2/23·3/02)
- 발견: dhoogla가 Dst Port·Timestamp·IP 이미 제거(누수 일부 차단). **라벨은 원본(교정 아님)** → 한계 명시.

### 다음 단계
1. ~~v0.1 베이스라인~~ ✅ / ~~v0.0 동결~~ ✅
2. **v0.2 정직한 평가**(`eval_honest.py`) ← 지금: 다중일자 결합 + F0/F1/F2 ablation + 날짜교차(LeaveOneGroupOut) + RF/XGB → 최종 모델·피처셋 확정
3. v0.3 SHAP 근거 → 4. v0.4 위험점수(보정확률) → 5. v0.5 LLM 설명 → 6. v0.6 Streamlit

### v0.2 정직한 평가 — corrected 결과 (2026-06-23, exploratory round 1)
- ⚠️ 초기 실행은 **테스트셋까지 cap**해서 prevalence 왜곡 → **폐기**. 수정: 학습만 cap, 테스트=풀 자연분포 + AP·오라클 Recall@FP/100k.
- **3계층 결과(XGB/F2):** ① DDoS 변형전이(2/21) **oR@50=0.99**, AP 1.00 — 강함 ② Web 희소(2/23, 0.065%) oR@50 **0.42**(부분) ③ **Bot unseen(3/2) oR@100=0 — 운영상 실패**(AP 0.42~0.70이나 top 경보가 FP → AP가 unseen 과대평가).
- XGB ≫ RF (하드 계층). 최종모델 XGB/F2 유력. `output/metrics_v02.json`.
- 남은 한계: 무작위=샘플상한 / threshold 아직 오라클 → **v0.4 과거기반 FP예산 임계값 필요** / Web은 family-weighting 개선 여지.
- 정책: 세 테스트일자 이미 관측 → **blind 아님(round 1 동결)**. 이후 seed/full-data 재실행만, 변경 시 이력 기록.

### v0.3 SHAP 근거 — 완료 (2026-06-23)
- 잠금모델 XGB/F2(DDoS fold)에 TreeExplainer. 전역 top: Fwd/Bwd Packet Length Max·Fwd/Flow IAT Min(플러드)·Fwd Header Length.
- 개별 근거(TP/FP) + **`output/shap/evidence_sample.json`**(이벤트별 pred·score·top-5 기여피처) = v0.5 LLM 입력. beeswarm/bar/waterfall PNG 저장(QA 통과). `src/explain.py`.

### v0.5 설명 레이어 — 완료 (2026-06-23)
- `src/llm_explainer.py`: 불변 evidence JSON → 5섹션 자연어 설명(요약/근거/위험도/권고/주의). **템플릿 경로(키 불필요·결정론)** 기본 + LLM 경로(키 있으면, 출력검증·폴백). 판정·점수 불변. `output/explanations_sample.md`.
- 값 인식 문구 개선 **적용**: benign 중앙값 대비 '높음/낮음' + 방향 확실한 피처만 도메인 힌트(IAT Min 등).

### v0.6 Streamlit 대시보드 — 완료 (2026-06-24)
- `src/build_demo.py` → `output/demo_events.json`(2/21 샘플 1700건: 모델점수·conformal 위험점수·우선순위·SHAP top5·설명). `src/app.py`(KPI·위험순 표·상세 근거/설명·성능 탭). 스모크 테스트 통과.
- 실행: `python -m streamlit run src/app.py` (3.13). **5요소 파이프라인 end-to-end 완성**: 데이터→탐지(XGB/F2)→conformal 위험점수→SHAP 근거→설명→대시보드.

### v0.4 보정·triage (2026-06-23)
- v0.4: forward-OOF sigmoid 보정 시도 → **글로벌 보정이 covariate shift로 깨짐**(ECE 0.13~0.25, Web BSS −37). GPT 고급검증으로 진단.
- **v0.4b 채택(conformal benign-tail + Neyman-Pearson 임계값, `conformal_triage.py`):** 분포무관 FP 제어. 결과(XGB/F2):
  - DDoS(2/21) **recall 0.825 @ 실제 6 FP/100k** (BSS_raw 0.81) — 배포가능
  - Web(2/23) recall 0.39~0.43 @ 14~76 FP/100k (BSS −7.7 → 확률 폐기)
  - Bot(3/2) recall **0** — 단조보정·확률로 불가 → **novelty 분기 필요**(미구현)
- **위험점수 = conformal p-value 기반 운영점수**(깨진 보정확률 폐기). 공격/정상: DDoS 70/14·Web 46/10·Bot 16/7. `output/metrics_v04b.json`.
- 보고: raw Brier 금지 → **BSS**. 확률은 DDoS만 신뢰, Web/Bot은 출력 보류.

### v0.6 데모 확인 · 보고서 · v0.7 novelty (2026-06-24)
- 대시보드 gstack 브라우저로 렌더 확인(스크린샷 `scratch/dash.png`) — KPI·위험순 표·SHAP 근거·5섹션 설명·성능탭 정상.
- **결과보고서 초안** `docs/2026-06-24-result-report-draft.md` (6목차 매핑, [팀작성] 표시).
- **v0.7 novelty(benign-only IsolationForest+conformal, `src/novelty.py`):** 거의 실패(Bot 0, Web 0.13@100FP). → unseen-family는 진짜 한계로 정직 서술. kNN+PCA 향후.
- 남은 것(선택): 풀데이터(cap 제거) 재실행으로 수치 확정.

### 갭 메우기 — 전 공격군·multiclass (2026-06-25)
- **갭1+2 전 공격군 날짜교차**(`src/eval_allfolds.py`, `metrics_allfolds.json`): 9 fold. **운영 가능 = DDoS-HOIC(2/21) 0.825 하나뿐.** DoS Hulk same-family인데 FP 91%, LOIC-HTTP·Bot은 AP높고 운영 0, Web/Infiltration 실패. "same-family면 된다" 가설 깨짐 → 정직 결론 강화.
- **갭3 multiclass 6클래스**(`src/multiclass.py`, `metrics_multiclass.json`): 무작위 macro-F1 **0.945** vs 시간순 **0.219**(공격군 시간상 비중첩). Web 0.70(희소). 이진과 동일 결론.
- 결과보고서 초안에 전 공격군·multiclass 표 통합(§3.2/3.3).

### 목표 재확정 → "실제 잘 막는 탐지기" (2026-06-25)
- 사용자 지적: 9개 중 1개만 잡으면 기여 아님. 목표를 **실제 unseen recall 올리기**로 확정.
- 검색 확인: cross-day/cross-dataset 일반화 붕괴는 **분야 전체 미해결**(Cantone 2024 등). "다 잡기"는 단일 데이터셋 불가 → "0→의미있게" 목표.
- GPT-5.5 Pro 처방(검증됨): 2단계 hybrid = XGB(known) + **Deep SAD 반지도 표현학습 + local-kNN**(unknown). IsolationForest 단순교체 비권장. 순차 OR + FP예산 분리.
- **Top1 진단(`src/diagnose.py`, `metrics_diagnose.json`):** oracle vs 운영 recall로 문제 분리 →
  - **임계값 전이 문제(회복 가능):** LOIC oracle 0.49/운영 0, DoS-GE 0.29/0.03 → 임계값 정책 개선으로 상승 여지
  - **표현 문제(Deep SAD 필요):** Bot oracle 0, Web(2/22) 0.006, DoS-Hulk(benign 시프트 FP91%)
- 다음: ① 임계값 정책 개선(LOIC·DoS-GE 회복) → ② Deep SAD로 Bot/Hulk.
- **① 임계값 정책(`src/threshold_policy.py`):** **DDoS-LOIC 0→0.489 완전 회복**(`median-day` 정책=일자별 분위 중앙값, worst-day의 한날 오염 제거). HOIC 0.825 유지. **기본 정책 worst-day→median-day 권장.** 단 DoS-GE·Bot은 회복 안 됨=표현 문제 확정.
- **② Deep SAD(`src/deepsad.py`):** LOFO에서 실패 — DoS 0.005·Bot 0·Web 0.011, IsoForest보다도 낮음. → "표현 한계"로 성급 결론할 뻔.
- **종료검증(`src/verify_limit.py`, GPT 처방):** 결론 뒤집힘! **target-day function oracle: Bot 0.996·DoS-GE 1.0·Web 0.68 @100FP** → **F2에 공격 구분 정보 충분히 있음.** raw-kNN도 Deep SAD처럼 실패 → 모델/표현 문제 아님 확정.
  - **진짜 원인 = 전이(transfer)/conditional shift:** 그날 안에선 100% 구분되나, 과거 날짜로 배운 규칙이 미래(다른 공격군) 날짜로 안 넘어감. P(Y|X)가 날짜마다 변함.
  - → 방향 전환: "표현 변경/temporal" 아니라 **도메인 일반화(GroupDRO·날짜불변 피처선택)**. temporal보다 가볍고 데이터 이미 있음.
- **도메인 일반화(`src/domain_general.py`):** 날짜불변 피처(8~10개: 공격방향 부호일치 + 날짜 비예측) 선택 + full-F2와 **OR 앙상블**(각 50FP/100k).
  - **결과 — unseen 0이 깨짐:** Bot 0→**0.107**, DoS 0→0.051, Web 0→0.057, DDoS 0.554 유지(full이), BruteForce 0(여전). `metrics_domain_general.json`.
  - 진단 확증: invariant 단독은 Bot 0.123이나 DDoS 0.55→0.04 폭락(불변강요=신호손실) → OR로 둘 다 살림.
  - **결론(방어가능):** 병목=표현 아닌 **전이(conditional shift)**, 날짜불변+OR로 unseen 0→0.05~0.12 개선. 단 운영수준 미달=단일 flow-level 천장.
- **상태: "왜 안 되는지 규명 + 부분 개선" 달성.** "1개만 잡는 실패작" 아님.

### GPT 2차 처방 검증 + temporal 착수 (2026-06-25)
- GPT 판정(검증됨): unseen recall ROI 순 = **① temporal(Port+Timestamp causal aggregate) ② soft GroupDRO branch(OR, 70:30) ③ SupCon MLP(낮음) / Transformer 생략.** GroupDRO는 새 정보 없이 invariant 재조합일 뿐 → temporal이 진짜 카드.
- **★ BruteForce 0 해석 정정(우리 데이터로 확정):** 일자 순서 = BruteForce(2/14) **첫 공격일** → 시간순 평가 시 학습할 과거 공격 0 = **cold-start.** "BruteForce 0"은 모델 실패 아니라 평가구조상 당연. **Bot(multi-source unseen)과 별도 보고 필수.**
- 현실적 천장(GPT, 학계 기준): F2-only zero-shot Bot 0.15~0.25 상단, +temporal Bot 0.15~0.35, Bot>0.5는 IP/host 없이는 비현실. 목표 = Bot 0.20+·DoS 0.15+·Web 0.10+·DDoS 0.50 유지 @100FP면 강한 결과.
- 종료조건: temporal + soft GroupDRO 둘 다 macro recall +0.05 미만이면 중단. Transformer는 model zoo 늘리기일 뿐.
- 다음: **temporal feature(원본 CSV Timestamp 기반 causal 1/10/60초 Port aggregate) 생성 → XGB ablation(T0~T4).** DoS/DDoS/BruteForce ROI 높음, Bot 제한적 예상.

### ★ temporal feature 성공 (2026-06-25) — 큰 진전
- 원본 CSV(Timestamp)에서 Dst Port별 causal 1/10/60초 집계 20피처 생성(캐시 `sources/raw_ts/cache/*.parquet`). `src/temporal_cache.py`+`temporal_eval.py`.
- **F2 vs F2+temporal LOFO (FP=100 고정 공정비교):**
  - **Bot 0.009→0.390 (Δ+0.381)** — GPT가 "IP없이 0.4 어렵다"던 걸 넘음. C2/beaconing이 시간맥락(반복연결)에 잡힘.
  - DoS 0.512→0.652, BruteForce(cold) 0.737→0.994, DDoS 0.383→0.402, **Web 0.023→0.014(미해결, flow희소)**.
  - temporal 중요도 40~64% = 모델이 실제 시간맥락 의존.
- **결론 강화:** 병목=전이, **해법=시간맥락 피처**(모델 아닌 데이터표현). "구식 모델이라 낮다"는 사용자 직관 적중 — 표현 추가하니 unseen 급상승.
- caveat: 임계값 테스트benign 오라클(진단상한) → 과거기반 운영값 재확인 필요. Web 미해결. Bot 0.39도 61% 놓침.

### ★ 운영 임계값 검증 완료 (2026-06-25, `temporal_operational.py`) — 오라클 착시 아님
- 과거기반 **worst-day 임계값**이 오라클 94~99% 유지 + 실제 FP 14~18/10만(예산 100 한참 아래):
  - **Bot 0.408@18 · DoS 0.616@16 · DDoS 0.502@14 · BruteForce 0.979@17** · Web 0.009(미해결)
- **GPT 정책추천(median-day/q75)은 우리 데이터에선 FP 240~540으로 예산 초과 → 틀림. 검증으로 worst-day 채택.** (GPT 무조건 수용 금지 원칙 적용)
- **확정 운영 수치(시작 대비):** Bot 0.009→**0.408**, DoS 0.51→**0.62**, DDoS 0.38→**0.50**, BruteForce(cold) 0.74→**0.98** @ FP~15/10만. temporal feature가 운영에서도 유지.
- GPT "최우선=IP복원"은 **우리 처리CSV에 IP 없음**(PCAP 수십GB 재처리 필요) → 현실적 최우선 아님. 다음 현실 카드 = temporal 확장(장기창·inter-arrival, IP불필요).
- Web만 구조적 한계(flow 희소+payload 없음). 라벨오류(2/23 BF 41.7%)도 원인.

### 확장 temporal (2026-06-25, `temporal_cache2.py`+`temporal2_eval.py`)
- IP 복원 시도 무산: 공개 CSV/parquet 4종(dhoogla정제·NF-v2·S3원본·solarmainframe) **전부 IP 제거됨**, 원본 PCAP은 440GB(디스크 84GB로 불가). → "획기적 상승=IP" 경로 막힘. 데이터 접근성의 벽(보고서 한계로 기록).
- 대신 IP 불필요 확장 temporal: 장기창 300/600초 + inter-arrival 규칙성(t_secfc_cv) + 연결실패율(zero-payload/no-bwd/syn-no-ack) 48피처. **port_key 버킷화**(ephemeral 1.8만 고유포트→~20 버킷)로 rolling 351초→수초 최적화.
- **공격군별 최선 피처셋 다름(중요):** Bot=확장temporal **0.489**(기존0.41 넘음, temp중요도 84%), DoS/BruteForce=기존temporal이 더 나음(확장은 −0.08/−0.24 노이즈), DDoS 0.50 동일, **Web 0(구조적 한계)**.
- **최종 베스트:** Bot 0.49·DoS 0.62·DDoS 0.50·BruteForce 0.98·Web 0 @FP~18. (공격군별 best 피처셋 선택 시)

### 1차 완성 = WE-Meet 안정 포인트 (2026-06-25)
- 방향 확정: **1차 완성**(보안로그 레이어+보고서 문서까지) = WE-Meet 안정 종료점. **이후 별도로 4주/학부 범위 무시하고 탐지율 끌어올리기 장기 구상.**
- **현업 검증(Sommer&Paxson 2010 + base rate fallacy):** 단일 ML로 다 못 잡음 = 분야 정설. 현업은 **다층(SIEM+NDR+EDR)+규칙 주력+ML 보조+사람 사후**. 우리는 NDR 한 층을 깊게 판 것 = "왜 다층이 필요한가" 실증.
- **정체성 정정:** 우리는 "이상탐지기"가 아니라 **지도학습 NDR + temporal로 unseen 일반화**. (순수 이상탐지=IsolationForest/DeepSAD는 실패)
- **보안로그 레이어 추가**(`src/log_analysis.py`): Bot일자 Windows evtx 파싱→호스트별 EventID통계·보안이벤트(7040/7045 서비스변경=봇넷 지속성)·드문이벤트 이상징후. **다층 방어의 로그층 데모**(과제명 "보안로그분석" 부분충족). 한계: System채널·라벨없음=분류 아닌 이상징후 분석.
- 다음: **보고서 hwp 문서들 채우기**(수행계획서 본문은 있음, 결과보고서·일지 양식 채우기).

### 결과보고서 hwpx 생성 (2026-06-25)
- 결과보고서 초안(md) 최신 결과로 전면 갱신: temporal로 unseen 0→0.49, 다층 방어 통찰, 보안로그 레이어 반영. `docs/2026-06-24-result-report-draft.md` + 양식칸별 `docs/result-report-fill.md`.
- **제출용 hwpx 생성**(`src/build_report_hwpx.py`): 기존 수행계획서 hwpx를 템플릿으로 `<hp:t>` 텍스트 치환 → `output/결과보고서_사이버보안WE-MEET.hwpx`(36문단, ZIP·XML 유효 검증). [작성예정]=소감·사진은 팀이.
- ⚠️ 한컴 미설치라 한글에서 열림 100% 보장은 못함 → 열어보고 문제시 수정(docx 대안 가능).
- **[수정] 양식 터뜨린 첫 시도 폐기 → 올바른 방법으로 재작성(`src/fill_report.py`):** 운영계획안 결과보고서 **양식 그대로 두고 빈칸 hp:t에만 텍스트 삽입**(라벨 기반 매핑). 표 23개 보존·XML 유효·❍ 기호 살림. 17개 항목 채움. 팀명·팀원표·소감·사진은 팀 몫으로 비움. `output/결과보고서_사이버보안WE-MEET.hwpx`(135KB).
- 교훈: hwpx는 양식 건드리지 말고 `<hp:t>` 빈칸 텍스트만 채울 것. 정규식 문단수술 금지(표/헤더 중첩 깨짐), lxml 파서로 노드 단위 처리.

### 멘토 과제 3종 (2026-06-26~29 마감)
- 6/26 소집 멘토링 취소 → 멘토 과제 3개로 대체. 팀대표(팀장) 메일 송부(참조 팀원).
- **#1 PPT(6/26 10시):** 결과 반영 멘토 소개용 7매 재빌드(`src/build_deck.py` → `output/발표자료/사이버보안 WE-Meet 팀과제1 PPT.pptx`). 표지→문제→5요소→정직한평가→temporal결과→다층방어→일정. 시각 QA 통과(네이비+틴트, Pretendard).
- **#2 진행간 어려운점(6/26 18시):** **docx 완성** `output/제출물/사이버보안 WE-Meet 팀과제2 진행간 어려운점.docx` — 5개 질문(artifact 식별/미관측 일반화/IP·payload 한계/SOC 운영/범위). 자유양식. QA 통과(2p).
- **#3 수행일지 1주차(6/29 10시):** **hwpx 완성** `output/제출물/사이버보안 WE-Meet 팀과제3 수행일지 1주차.hwpx` — 운영계획안 수행일지(참고1-2) **안내문 양식 그대로 두고 그 아래 1주차 내용 추가**(lxml, 양식 안 깨짐, XML 9/9 유효). `src/build_log_hwpx.py`. docx판은 삭제(hwpx로 대체).
- ※ 수행일지 양식은 '채울 빈칸 표' 없이 1·2·3 항목 안내문만 → 안내문 보존 + 아래 내용 작성 방식.
- #2는 자유양식이라 docx 유지(`팀과제2 진행간 어려운점.docx`).

### ★ 교수 1차 피드백 → 프로젝트 재정의 (2026-06-26)
- 교수 피드백: 데이터셋 OK / **"분석 vs 탐지강화 명확화·구체화"** / **강화면 특정 공격 범위 축소** / 추천논문 2편(Wang 2023 딥러닝 벤치마크, ROSE-BOX 2025 경량). 멘토매칭 진행중.
- 두 논문 전문 정독(long-reader): 둘 다 **쉬운 공격+무작위분할로 99~100%**, 어려운 공격(Web F1 0.5~0.7·Infiltration 0%)·정직평가는 빈칸. ROSE-BOX=RandomForest+SMOTE+BO-XGBoost, XGB-RF 피처선택, CSE2018은 DoS 3종만 100%(temporal 없음).
- **확정: "Bot 봇넷 탐지강화 + 날짜교차 정직평가 결합"**(사용자 선택). 상세 `docs/2026-06-26-project-redefinition.md`.
- 구체화: 모델=XGBoost+ROSE-BOX식 XGB-RF 피처선택+베이지안최적화 / 평가=날짜교차(학습 2/14~3/1, 시험 3/2 Bot)+효율(추론시간·CPU·모델크기) / **LLM=설명 전용(탐지 아님) 명확화**(PPT 오해 정정 필요). references.md에 ④⑤ 추가.

### #2 어려운점 쉬운 말 재작성 (2026-06-26)
- 전문용어·AI 문체(허상/지름길/전이/temporal/conformal/NDR/artifact) 제거 → 학생이 멘토에게 직접 묻는 평이한 문장. `src/build_docx.py build_q2()`. (Word 열려있어 `_q2_tmp.docx`로 보관, 닫으면 본명으로 교체)

### 개념 해설 PPT — 학습용 (2026-06-26)
- 팀장 이해용 **기술 개념 해설 deck 13장** `output/발표자료/사이버보안 WE-Meet 개념·전이 기술해설.pptx` (`src/build_concept_deck.py`).
- 구성: 학습지도(갭 메우는 계단) → 용어 ①모델·학습·분류 ②피처·라벨 ③분리·과적합·지름길 ④혼동행렬·재현율·임계값·AP ⑤일반화·분포이동 → ⑥**전이(covariate vs concept shift)** → ⑦oracle 증명 → ⑧temporal 개선 → ⑨conformal 위험점수 → ⑩SHAP·LLM → ⑪전체구조·핵심·한계.
- 비유 없이 용어 정의 중심·기술적. build_deck.py 시각 시스템 재사용. PDF→PNG로 표지·전이·oracle·temporal 4장 시각 검증 완료(경계초과 0).

### GitHub 팀 공유 (2026-06-26)
- **Public repo: https://github.com/decmoon05/wemeet-ai-attack-detection** (코드·문서 38파일, 348KB).
- 제외(.gitignore): `sources/`(데이터 6.8GB)·`paper/`(논문 저작권)·`output/`(산출물 바이너리)·`.gstack/`(토큰)·오피스 파일·`*.joblib`.
- 개인정보 마스킹: 학번 (학번 비공개)/(학번 비공개), 이메일·이름 익명화(src/docs/progress 전체). 제출용 최종 PPT·hwpx·docx(실명)는 git 제외 → 팀에 별도 공유.
- README 전면 개편: 팀원이 한눈에 이해하게 "핵심 스토리(100%함정→정직평가→전이규명→시간맥락개선)" + 코드맵 + 폴더표.
- ⚠️ 메일 제목 규칙: "사이버보안 WE-Meet 팀 과제 #N ...". #2 마감은 본문상 18시(첫줄 오전 표기와 혼선 → 10시 전 완료 권장).
- **#1 PPT 내용중심 개정 + 수치 대폭 보강:** 카피문구 제거 + 실측 수치/표 추가. **9장**(표지+01문제·02데이터셋·03구성·04평가발견·05전공격군9fold표·06temporal결과·07추가검증(운영임계값·multiclass·로그)·08다층방어·09일정). 데이터 규모(666만flow·10일·14공격), 9-fold AP/탐지율/FP 표, multiclass 0.945/0.219, 로그 7045/7040 등 멘토가 읽고 이해되게. `output/발표자료/사이버보안 WE-Meet 팀과제1 PPT.pptx`. 전체 QA 통과.

### 미확정/확인필요
- 팀원 가용시간, 멘토 기업 배정, 제출 채널, 주제 최종확정.
