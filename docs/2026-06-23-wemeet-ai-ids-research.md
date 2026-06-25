# 사이버보안 WE-Meet — AI 기반 공격탐지 에이전트 조사 노트

> 작성일 2026-06-23 · 팀 팀장·팀원 · 충남대 데이터보안활용 융합대학사업단 하기 계절학기
> ⚠️ **주제 확정 전** 상태에서의 조사 정리본. 개발 착수 시 이 문서를 기준으로 시작.

---

## 0. 프로젝트 한눈에

- **과제명:** AI 기반 공격탐지 에이전트 개발 — 네트워크 이상 탐지 및 보안 로그 분석 중심
- **본질:** 논문 ❌. 네트워크 통신 기록으로 **정상/공격을 분류**하고 **위험점수·근거·설명**을 화면·보고서로 보여주는 실무형 데모 제작 → 결과보고서 + 멘토링 일지 3회 + 발표/시연.
- **개발 방식:** AI 보조 개발(코딩 에이전트/LLM) + 검증된 라이브러리. 사람은 데이터 선택·해석·시각화·문서에 집중.
- **이수 산출물:** 수행계획서(20%) · 멘토링 일지 3회(30%) · 결과보고서(50%) + 정성평가. (팀 계획서는 이미 제출 완료)

---

## 1. 무엇을 만드나 — 5요소 통합 시스템

```
데이터(트래픽/로그 CSV) → ① 전처리 → ② RF/XGBoost 이진 분류(정상/공격)
   → ③ 0~100 위험점수 → ④ SHAP 탐지 근거 → ⑤ LLM 자연어 설명 → Streamlit 대시보드
```

- **MVP:** 정상/공격 **이진 분류** + 위험점수 + 근거 2~3개 + 설명.
- **핵심 원칙:** **LLM은 탐지를 판정하지 않고, 모델 결과를 설명만** 한다. (LLM 오류·API 장애가 나도 탐지·시연이 유지됨 → 최신 연구가 입증한 정설)
- **선택 기능:** 공격 유형 다중 분류, Isolation Forest 비교. **제외:** Autoencoder, 실시간 패킷 캡처, LLM 단독 탐지, 자동 차단.
- **평가 지표:** 공격 클래스 Precision/Recall/F1, 혼동행렬, PR-AUC. 도전 목표 Recall·F1 ≥ 0.85. 불균형 처리(`class_weight`/`scale_pos_weight`) 기본 적용.

---

## 2. 데이터셋 — CSE-CIC-IDS2018 확정

| 데이터셋 | 연도 | 성격 | 비고 |
|---|---|---|---|
| **CSE-CIC-IDS2018 (확정)** | 2018 | 일반 네트워크, 현대 공격 7종 | CSE+CIC(캐나다), AWS 모사망. CSV(80+ 피처, CICFlowMeter). 수GB→샘플링·정제 필요 |
| CIC-IoT2023 | 2023 | IoT 공격 33종 | 가장 최신·공식 튜토리얼 有, 단 IoT 주제·대용량 |
| UNSW-NB15 | 2015 | 일반 네트워크 | 여전히 표준 벤치마크·가장 가벼움. 연도 옛날 |
| TON_IoT | 2019 | IoT+OS로그+네트워크 | "로그 분석"에 부합 |

- 공식: https://www.unb.ca/cic/datasets/ids-2018.html · 다운로드 `aws s3 sync --no-sign-request --region <region> "s3://cse-cic-ids2018/" dest-dir`
- **반전 사실:** 2025 최신 논문들도 UNSW-NB15·CSE-CIC-IDS2018을 여전히 가장 많이 씀 → "오래됨 ≠ 폐기".

### ⚠️ 데이터 라벨 오류 (개발 전 필독, 실증됨)
- 최대 **7.5% 오라벨**, **웹 브루트포스 플로우 41.7% 오라벨**, Infiltration 심각 오염, LOIC-HTTP/UDP 혼입, 플로우 구성 버그(TCP segmentation/ICMP/ARP).
- 같은 데이터셋 내 평가는 "거의 완벽"이지만 **외부 검증 시 거의 무작위** → 데이터 누수/편향. **단일 데이터셋 고정확도 신뢰 금지.**

### 정제판 (실재 검증)
- **학술 교정판:** Engelen 수정 CICFlowMeter https://github.com/GintsEngelen/CICFlowMeter · 2018 교정문서 https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html
- **즉시 사용 정제 parquet:** dhoogla https://www.kaggle.com/datasets/dhoogla/csecicids2018 (inf 제거·float32·parquet)
- **NetFlow 표준화판:** NF-CSE-CIC-IDS2018-v2 https://www.kaggle.com/datasets/dhoogla/nfcsecicids2018v2
- **권고:** dhoogla 정제본으로 *시작* + 보고서에 Engelen 교정문서 인용("알려진 라벨 오류 인지·보정").

---

## 3. 선행 논문 (검증된 1차 URL만)

### A. ML/DL 기반 NIDS — 벤치마크 분류
- Talukder et al. 2024, *J. Big Data* — 오버샘플링+스태킹, UNSW/CICIDS RF계열 고성능. https://arxiv.org/abs/2401.12262
- Xuan & Manohar 2023 — 멀티 데이터셋 ML IDS + HPO. https://arxiv.org/abs/2312.01941

### B. Explainable IDS (SHAP/XAI)
- Mohale & Obagbuwa 2025, *Frontiers* — UNSW-NB15 + XGB/RF + SHAP/LIME, `sttl` 핵심지표. https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1520741/full
- Arreche et al. 2024 — XAI 기반 feature selection. https://arxiv.org/abs/2410.10050
- Kalakoti et al. 2025 — 실제 SOC 경보 분류 XAI(우선순위화). https://arxiv.org/abs/2506.07882

### C. LLM × 보안 경보/SOC/IDS
- **Khediri et al. 2024 (IEEE PAIS)** — CICIDS2017, SHAP+LLM 자연어 설명. **우리 핵심과 최근접.** https://www.researchgate.net/publication/381129130
- **Houssel et al. 2024** — GPT-4/Llama3 직접 탐지는 부정확 → LLM은 설명용. (우리 설계 입증) https://arxiv.org/abs/2408.04342
- Farrukh et al. 2024 — XG-NID(GNN+LLM, 설명+대응). https://arxiv.org/abs/2408.16021
- 서베이: SOC용 LLM https://arxiv.org/abs/2509.10858 · NIDS용 LLM https://arxiv.org/abs/2507.04752 · CORTEX(멀티에이전트 triage) https://arxiv.org/abs/2510.00311

### A2. 위험점수 / 경보 우선순위 (우리 novelty)
- **SHAPoint 2025** — SHAP값 binning→정수 점수. **0~100 점수 청사진.** https://arxiv.org/abs/2509.23756
- Moran 2026 — 위험점수 3축(심각도+탐지신뢰도+조직위험). https://arxiv.org/abs/2605.27299
- Ndichu et al. 2026 — 경보 스크리닝/우선순위 서베이(119건). https://arxiv.org/abs/2605.08316
- Jiang et al. 2025 — 우선순위 metric taxonomy. https://arxiv.org/abs/2502.11070

### B2. 에이전트형 IDS (과제명 "에이전트" 직결)
- **IDS-Agent (NeurIPS 2024 Workshop)** — 최초 LLM 에이전트 IDS, ML분류기를 도구로+설명+zero-day. **가장 가까운 선행(단 IoT).** https://openreview.net/forum?id=uuCcK4cmlH
- CyberRAG 2025 — 경보→근거 리포트 RAG 에이전트. https://arxiv.org/abs/2507.02424
- GRIDAI 2025 — 멀티에이전트 탐지룰 생성/수리. https://arxiv.org/abs/2510.13257
- Agentic AI & Cybersecurity 서베이 2026. https://arxiv.org/abs/2601.05293

### C2. 데이터셋 품질 비판/정제
- **Lanvin et al. 2022 (CRiSIS)** — CICIDS2017 라벨/캡처 오류 실증·수정. https://hal.science/hal-03775466
- Pekar & Jozsa 2024 — 무결성별 성능 비교, 정제판 NFS-2023 제안. https://arxiv.org/abs/2401.16843
- Goldschmidt & Chudá 2025 — NIDS 데이터셋 서베이·권고. https://arxiv.org/abs/2502.06688

---

## 4. GitHub 레포 (전부 실재 검증)

### 베이스라인(모델링)
- **Western-OC2-Lab/IDS-ML (★592)** — RF/XGB/스태킹+베이지안 HPO, CICIDS2017. https://github.com/Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning
- abhinav-bhardwaj/IoT-...-UNSW-NB15 (★205) · noushinpervez/Intrusion-Detection-CICIDS2017 (★133) · SubrataMaji/IDS-UNSW-NB15 (★92)

### 우리와 가장 닮은 3개 (내부 해부 완료)
- **Markl1T/network-intrusion-detection-agent** — ✅ **셋 중 유일 실동작**(라이브 데모, .pkl 포함). 3단계(IsolationForest→XGB/RF 이진→다중분류), NF-UNSW-NB15-v2. **전처리 코드 차용 가치 높음.** LLM·0~100점수 없음. https://github.com/Markl1T/network-intrusion-detection-agent
  - 전처리 핵심: `df[features].replace([np.inf,-np.inf],np.nan).fillna(0).clip(-1e9,1e9).astype(np.float32)`
- **epsilon003/LLM-Guided-Intrusion-Detection-System** — ✅ **LLM 설명 코드 실재**. 멀티백엔드(OpenAI/Anthropic/template 폴백), 입력=탐지dict+상위5피처, 프롬프트가 **5섹션(요약/기술상세/위험평가/권고/예방)** 강제. severity=confidence 4단계. https://github.com/epsilon003/LLM-Guided-Intrusion-Detection-System
- **ANSBG/CyberGuardML** — ⚠️ **껍데기**(학습/risk/SHAP 노트북 0바이트). 화면·스키마 설계만 참고. 샘플 CSV 역설계: `risk_score(0~100)=XGB확률+IsolationForest 이상점수 가중결합`. https://github.com/ANSBG/CyberGuardML

### 차별요소별 추가
- DB+XAI: ChandraVerse/xai-network-intrusion-detection · harshilpatel1799/...Explainable-XAI-ML(★60, SHAP/LIME/ELI5)
- XAI+RISK: tripti2405/Two-Stage-Hybrid-IDS · Parth525273/intelligent-ids-system
- LLM: ZahraaElsayed/Smart-IDS(로컬 Ollama+Qwen2.5) · bnardpolo/CyberSentinel(RF+XGB+CICIDS2017+LLM) · zhsh9/SentinelGuard
- DB+XAI 풀스택: Mandar123454/AI-Powered-NIDS(SHAP+Flask SOC+Azure)

---

## 5. 개발 빌딩블록·튜토리얼 (바로 쓸 것)

- **SHAP(tabular):** 공식 Census/XGBoost 예제 https://shap.readthedocs.io/en/latest/example_notebooks/tabular_examples/tree_based_models/Census%20income%20classification%20with%20XGBoost.html · TreeExplainer API
- **위험점수:** SHAPoint(위 논문) + scikit-learn `CalibratedClassifierCV` https://scikit-learn.org/stable/modules/calibration.html (확률 보정 후 ×100; 안 하면 "확률"이라 부르지 말 것)
- **Streamlit:** `st.column_config.ProgressColumn`(위험막대)/`st.dataframe`(행선택 drill-down) · streamlit-shap 컴포넌트 https://github.com/snehankekre/streamlit-shap · 동작예제 dataprofessor/streamlit-shap · RF-IDS 앱 debjotyms/streamlit-ml-intrusion-detection-system
- **LLM 구조화 출력:** Claude Structured Outputs https://platform.claude.com/docs/en/build-with-claude/structured-outputs · OpenAI Structured Outputs · Instructor+Pydantic https://python.useinstructor.com/
- **end-to-end 튜토리얼:** tamerthamoqa/cic-ids-2018-...classification(RF 골격) · Western-OC2-Lab/IDS-ML(RF vs XGB+HPO) · Medium XGBoost CICIDS2018(`scale_pos_weight`) https://medium.com/@mohammedsaimquadri/how-we-built-an-end-to-end-xgboost-based-intrusion-detection-system-using-the-cicids2018-dataset-187fa4e01f55
- **Kaggle 전처리 노트북:** ericanacletoribeiro(정제) · athena21(SMOTE) · dhoogla(2018 정제) · prantokumar(2018 전체)

---

## 6. "어디서 뭘 베낄지" 매핑

| 우리 모듈 | 참고처 |
|---|---|
| 전처리(Inf/NaN/메모리) | Markl1T `clean_features` + dhoogla 정제 노트북 |
| RF/XGBoost 분류·평가·HPO | Western-OC2-Lab/IDS-ML |
| 불균형(SMOTE) | athena21 Kaggle |
| SHAP 근거 | SHAP 공식 Census/XGBoost 예제 |
| 0~100 위험점수 | SHAPoint + CalibratedClassifierCV + CyberGuardML 점수 의도 |
| LLM 자연어 설명 | epsilon003 `llm_explainer.py` 5섹션 프롬프트 |
| Streamlit 화면 | dataprofessor/streamlit-shap + CyberGuardML 레이아웃 + Markl1T 앱 |

---

## 7. 개발 함정 & 표준 전처리

CIC 계열 전처리 표준 4단계:
1. `df.replace([np.inf,-np.inf], np.nan)` — `Flow Bytes/s`·`Flow Packets/s`의 0-나눗셈 inf 처리
2. `dropna()` 또는 0/중앙값 대치
3. `drop_duplicates()` + 중간에 섞인 헤더 행 제거(`df[df['Label']!='Label']`)
4. 라벨 정규화(대소문자/하이픈 통일) → SMOTE/언더샘플링 → RF/XGBoost
- 메모리: float32 다운캐스트 + parquet 저장.

---

## 8. 우리 차별점 (novelty)

- ✅ 아키텍처(탐지=ML, 설명=LLM)는 **최신 흐름과 정확히 일치** → 안심하고 진행.
- 🎯 **핵심 novelty = "SHAP 기여도 + 모델 확률을 융합한 0~100 위험점수"** — 이 조합의 학술 선례를 명확히 못 찾음(빈틈).
- 🎯 **5요소(분류+대시보드+SHAP+위험점수+LLM설명) 통합형 단일 시스템**은 논문에도 레포에도 없음 → 통합 자체가 가치.
- 데이터: 정제판 사용 + 원본 라벨 오류 명시로 평가 신뢰도 확보.

---

## 9. 추천 개발 순서

1. 데이터 굴리기 — dhoogla 정제본 로딩 → tamerthamoqa/Western-OC2-Lab 코드로 RF/XGBoost 학습·평가
2. SHAP 붙이기 — TreeExplainer + summary/force/waterfall
3. 0~100 위험점수 — CalibratedClassifierCV 보정 후 스케일(SHAPoint 참고)
4. LLM 설명 — epsilon003 5섹션 프롬프트 + Claude Structured Outputs(IP 마스킹, 실패 시 template 폴백)
5. Streamlit 조립 — streamlit-shap + column_config(위험막대) + 위험도순 표·상세·혼동행렬

---

## 10. 확인 필요 / 미확정

1. 팀원 정확한 가용시간
2. 멘토 기업 배정 여부 + 멘토링 조기/비동기 인정 여부
3. 개발 환경(노트북/Colab/학교서버) + 외부 LLM API·인터넷 허용 여부
4. 제출 채널·형식·서명 요건
5. **주제 자체가 아직 미확정** — 본 문서는 "AI 공격탐지 에이전트" 전제 조사본

### 검증 한계 (정직 표기)
- Kaggle 노트북 **셀 코드·정확 추천수는 직접 못 봄**(로그인/JS). 실재·URL·개략 성격만 확인.
- 일부 논문 본문 미정독(arXiv 초록·메타데이터 교차검증 기준). 2026 상반기 프리프린트는 피어리뷰 미확인.
- GitHub 레포 내부·데이터셋 함정/정제판은 실제 파일·문서로 검증함.
