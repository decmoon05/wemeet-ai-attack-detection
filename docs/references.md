# 참고문헌·출처 (References)

> WE-Meet 프로젝트에서 인용·참고한 모든 출처 모음. 보고서 참고문헌으로 바로 사용 가능.
> **검증상태 표기:** ✅직접확인(본문/페이지 열람) · 🔶메타데이터만(제목·초록·검색스니펫, 본문 미정독) · ⚠️주의(게이트/인용오류 가능).
> 인용 시 🔶·⚠️ 항목은 원문 재확인 권장. 최종 업데이트 2026-06-25.

---

## A. 데이터셋 (우리가 사용)
- **CSE-CIC-IDS2018** (CSE + Canadian Institute for Cybersecurity, 2018) ✅
  - 공식: https://www.unb.ca/cic/datasets/ids-2018.html
  - 사용본: dhoogla 정제판(parquet) https://www.kaggle.com/datasets/dhoogla/csecicids2018 ✅ (cleaned이며 **라벨 교정판 아님**)
  - 원본 timestamp 포함 CSV: AWS S3 `s3://cse-cic-ids2018/` ✅
- **CICIDS2017** (참고) https://www.unb.ca/cic/datasets/ids-2017.html ✅
- 데이터셋 라벨 교정: **Engelen et al.** CNS2022 교정 문서 ✅ https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html
  - (FTP/SSH Attempted 재분류, Web BF `Total Fwd Packets>20` 재라벨 등 — 우리가 직접 확인·인용)
  - 수정 CICFlowMeter: https://github.com/GintsEngelen/CICFlowMeter 🔶

## B. 평가·일반화 문제 (우리 핵심 논지의 근거)
- **Cantone, Marrone, et al. (2024), "Machine Learning in NIDS: A Cross-Dataset Generalization Study"**, IEEE Access ✅
  - arXiv: https://arxiv.org/abs/2402.10974
  - 핵심: 같은 데이터셋 내 거의 완벽 → cross-dataset에선 random에 가까움. **우리 "무작위 0.99 vs 날짜교차 붕괴" 결론의 직접 근거.**
- **Lanvin et al. (2022), "Errors in the CICIDS2017 Dataset..."**, CRiSIS 2022 🔶 (HAL 오픈, 본문 일부)
  - https://hal.science/hal-03775466
- **D'hooge et al. (2022), "Establishing the Contaminating Effect of Metadata Feature Inclusion..."**, DIMVA 2022 ✅(검색 확인)
  - https://link.springer.com/chapter/10.1007/978-3-031-09484-2_2
  - 핵심: **Dst Port 단독으로 IDS 데이터셋 70~100% 분리** = shortcut. **우리 F2 피처 제거(Port/Protocol)의 근거.**
- **Goldschmidt & Chudá (2025), "Network Intrusion Datasets: A Survey, Limitations, Recommendations"** 🔶
  - https://arxiv.org/abs/2502.06688
- Pekar & Jozsa (2024), 데이터 무결성별 성능 비교(NFS-2023 정제판) 🔶 https://arxiv.org/abs/2401.16843

## C. 설명가능성(XAI) / SHAP
- **SHAP 공식 문서** ✅ (Census/XGBoost 예제, TreeExplainer) https://shap.readthedocs.io/
- **Mohale & Obagbuwa (2025)**, Frontiers in Computer Science — UNSW-NB15 + XGB/RF + SHAP/LIME 🔶
  - https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1520741/full
- Arreche et al. (2024), XAI 기반 feature selection for NIDS 🔶 https://arxiv.org/abs/2410.10050

## D. LLM × 보안 (우리 "LLM은 설명만" 원칙 근거)
- **Khediri et al. (2024)**, IEEE PAIS — CICIDS2017 SHAP+LLM 자연어 설명 ⚠️(ResearchGate 게이트, 메타만)
  - https://www.researchgate.net/publication/381129130
- **Houssel et al. (2024)**, "Towards Explainable NIDS using LLMs" 🔶 — GPT-4/Llama3 직접탐지 부정확 → LLM은 설명용 (우리 설계 근거)
  - https://arxiv.org/abs/2408.04342
- **IDS-Agent (Li et al., NeurIPS 2024 Workshop)** ✅ — 최초 LLM 에이전트 IDS, ML분류기+LLM설명
  - **OpenReview ID = `uuCcK4cmlH`** https://openreview.net/forum?id=uuCcK4cmlH ⚠️(GPT가 한때 틀린 ID 인용했음 — 이게 정확)
- **LLM vs ML 벤치마크 (2025)** 🔶 — XGBoost(F1 96.96%, CPU 4%)가 LLM 능가. "탐지엔 ML이 LLM보다 나음" 근거
  - https://link.springer.com/article/10.1007/s10462-025-11432-2
  - https://dl.acm.org/doi/10.1145/3696379
- 서베이: SOC용 LLM https://arxiv.org/abs/2509.10858 🔶 · NIDS용 LLM https://arxiv.org/abs/2507.04752 🔶

## E. 교수님 제공 논문 (paper/ 폴더) ✅ 본문 정독
- ① **Boateng et al. (2026), "Application of AI in Cyberattack Detection: A Review"**, *Sensors* 26, 1518. DOI 10.3390/s26051518
- ② **Alharthi & Garcia (2026 preprint), "Automating Cloud Security and Forensics Through a Secure-by-Design GenAI Framework"**, ICDF2C 2025 ⚠️(arXiv ID·인용 일부 비정상 — 서지 재확인 필요)
- ③ **Lee, Jeong, Han, Lee (2025), "LogRESP-Agent: A Recursive AI Framework for Context-Aware Log Anomaly Detection and TTP Analysis"**, *Applied Sciences* 15, 7237. DOI 10.3390/app15137237 (가천대)
- ④ **Wang, Houng, Chen, Tseng (2023), "Network Anomaly Intrusion Detection Based on Deep Learning Approach"**, *Sensors* 23(4), 2171. DOI 10.3390/s23042171 ✅(전문 정독, 21p) — 대만 타이베이공대. CSE-CIC-IDS2018 전량으로 6개 딥러닝(DNN/CNN/RNN/LSTM/결합) 벤치마크, 전체 98%대. **단 Infiltration F1 0~5%·Web 53~74%(소수클래스 실패), 무작위 분할·accuracy 위주.** → "쉬운 공격은 풀렸고 어려운 공격이 미해결"의 근거. (1차 피드백 추천)
- ⑤ **Peng, Han, Li, Liu, Liu, Gu (2025), "ROSE-BOX: A Lightweight and Efficient Intrusion Detection Framework for Resource-Constrained IIoT Environments"**, *Applied Sciences* 15, 6448. DOI 10.3390/app15126448 ✅(전문 정독, 23p) — 하얼빈공대. **RO(RandomForest)+S(SMOTE)+BO-X(베이지안최적화 XGBoost).** XGB-RF 피처선택+EarlyStopping으로 경량화, 효율을 추론시간(μs)·CPU%로 측정(모델크기·엣지보드 미측정). **CSE-CIC-IDS2018은 DoS Hulk+SlowHTTPTest+정상 3종만 → 100%, 무작위 분할·temporal 없음**(우리 artifact 함정과 동일 가능성). → 우리 강화 노선의 방법 차용처 + 차별점(어려운 공격·날짜교차) 명확화. (1차 피드백 추천)

## F. 모델·방법론 (우리 unseen 개선 시도에 사용/검토)
- **위험점수/보정·conformal:**
  - SHAPoint (2025) — SHAP→점수 binning 🔶 https://arxiv.org/abs/2509.23756
  - scikit-learn Probability Calibration ✅ https://scikit-learn.org/stable/modules/calibration.html
  - Tong et al. (2013), Neyman-Pearson classification 🔶 https://www.jmlr.org/papers/volume14/tong13a/tong13a.pdf
  - Conformal outlier p-values (Bates et al., Ann. Statist. 2023) 🔶 https://projecteuclid.org/journals/annals-of-statistics/...
- **이상탐지/표현학습 (우리가 시도):**
  - **Deep SAD** (Ruff et al., ICLR 2020) ✅ https://openreview.net/forum?id=HkgH0TEYwH · 구현 https://github.com/lukasruff/Deep-SAD-PyTorch 🔶
  - DROCC (Goyal et al., ICML 2020) 🔶 https://proceedings.mlr.press/v119/goyal20c.html
  - Mahalanobis OOD (Lee et al., NeurIPS 2018) 🔶
  - Outlier Exposure (Hendrycks et al.) 🔶 https://openreview.net/pdf?id=HyxCxhRcY7
  - ADBench (2022) 🔶 https://openreview.net/forum?id=foA_SFQ9zo0
- **도메인 일반화 (우리가 시도/검토):**
  - **GroupDRO** (Sagawa et al., ICLR 2020) ✅ https://arxiv.org/abs/1911.08731
  - SupCon (Khosla et al., 2020) 🔶 https://arxiv.org/abs/2004.11362
  - SAINT (tabular transformer, 2021) 🔶 https://arxiv.org/abs/2106.01342
  - "Why tree-based models still outperform deep learning on tabular" (NeurIPS 2022) 🔶 — Transformer 비권장 근거
    https://proceedings.neurips.cc/paper_files/paper/2022/hash/0378c7692da36807bdec87ab043cdadc-Abstract-Datasets_and_Benchmarks.html
- **temporal/시간맥락:**
  - "Temporal Analysis of NetFlow Datasets for NIDS" (2025) 🔶 https://arxiv.org/abs/2503.04404

## G. 도구·라이브러리
- scikit-learn, XGBoost, SHAP, PyTorch, Streamlit, pandas, PyMuPDF — 공식 문서 ✅

---

## 우리 프로젝트가 "직접 실증한" 것 (인용이 아니라 우리 결과)
- 무작위분할 F1 0.99 vs 날짜교차 macro-F1 0.219 (`metrics_multiclass.json`)
- target-day function oracle: Bot 0.996 → **F2에 정보 있음, 병목은 전이** (`metrics_verify_limit.json`)
- 도메인 일반화(불변피처+OR): unseen 0→0.05~0.12 (`metrics_domain_general.json`)
- BruteForce(2/14)가 첫 공격일 = cold-start (우리 데이터 확인)
