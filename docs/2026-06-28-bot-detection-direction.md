# 봇넷 탐지 방향 — 심층 분석 확정안 (2026-06-28)

> 6각도 리서치 → 종합 → **적대적 검증** 워크플로우(wf_8639c50d, 에이전트 8·토큰 45만) 결과.
> 종합안(synth)을 **검증(crit)이 우리 실제 코드·데이터로 교정한 최종 실행안**. 검증 판정 = **조건부 GO**.

## 한 줄 방향
교수 2차 피드백("알려진 공격은 행위로 탐지, 봇넷 0.49는 본질적 천장이 아니라 행위 분석 정교화 부족")을 정면 수용. **모델(RF/XGB)을 갈아엎지 않고** 기존 temporal 파이프라인 위에 행위 피처를 더한다. 단 — **4주의 진짜 목표는 "0.49를 더 올리기"가 아니라, ① 0.49가 '포트8080 지문'이 아니라 전이 가능한 행위 신호임을 증명하고 ② in-sample FP 누수를 교정하고 ③ 교수 언어로 정직하게 프레이밍하는 것**이다.

## ⚠️ 검증이 잡아낸 결정적 사실 (반드시 반영 — 내 1차안의 오류 포함)
1. **타임스탬프가 초 단위(서브초 없음).** 연속 flow 시작시각 차(di)가 0/1초로 양자화 → **FFT/ACF/Lomb-Scargle "진짜 주기성"은 측정 불가에 가깝다.** → robust 통계(CV/MAD/엔트로피/최빈간격 점유율)만 시도. (내 1차안의 "주기성 심화" 레버는 데이터상 거의 무력 — 폐기/축소)
2. **현재 "0.49 @18FP/100k"의 FP는 in-sample 누수.** 테스트 benign(te_b)이 학습 benign과 중복이고 임계값도 같은 benign에서 추출 → **recall만 정직, FP는 낙관.** 우리 자신의 findings 기준(테스트=풀 자연분포) 위반. → **held-out benign(일자 분리) 또는 worst-day 운영 임계값으로 교체. 이 FP 수치 헤드라인 사용 금지.**
3. **"Dst Port ablation"은 strawman였다.** 포트 식별자는 이미 피처에서 제외(NONFEAT)돼 제거해도 무변화. **진짜 누수 경로 = temporal 피처가 `port_key`로 groupby 계산된다는 것.** Bot의 98.4%가 8080이고 temporal 중요도 0.84 → "이 캡처의 8080=봇" 지문일 위험 = **v0.1 artifact 재발.** → ablation을 **'그룹핑 키' 수준**(포트무관 키/키 셔플/8080 특별취급 제거)으로 바꿔 행위 신호임을 증명.
4. **Bot = 단일 일자(3/2)·단일 C2·단일 포트·IP 부재** → '날짜교차 Bot'은 사실상 단일 표적 검증. 주기성 이득이 한 캡처 과적합일 수 있음 → 보고서에 정직 명시.
5. **"RITA/Zeek 비커닝 이식"은 과장.** RITA는 host-pair·서브초 기반인데 우리는 둘 다 없음 → **"RITA-영감 집계 규칙성 근사"**로 정직 표기.
6. **DistriNet Improved CSV에 IP 재수록** 주장은 **미확인 가정**(팀 기존 결론 "공개판 전부 IP 제거"와 충돌). Phase-0에서 헤더만 **수 시간 타임박스**로 확인, IP 가정 위 설계 착수 금지. 설령 있어도 host-pair 전환은 4주 밖 future work.

## 검증된 4주 로드맵 (조건부 GO)
- **0주차(1~2일) 게이트:** ① 원본 CSV의 port8080 flow 시작시각 차(di) 히스토그램 → 1초 양자화·집계 하에서 주기성이 측정 가능한지 확인(안 되면 FFT/ACF 폐기) ② Ares 라벨노이즈(protocol/port=0 ≈0.09%, RST teardown 'Attempted') 정량화 ③ DistriNet Improved 헤더 IP 유무 확인 ④ 오픈규칙→피처 매핑표 초안.
- **1주차 — 행위 피처(가볍게):** robust di 통계(CV/MAD/엔트로피/±10% 양자화 최빈간격 점유율) + **크기 일관성**(port_key×윈도 per-flow 바이트/패킷 std·CV, Pkt Len 이봉성). LOFO(FP=100 고정)로 순증 측정 → 효과 있는 것만 채택. **FFT/ACF/Lomb-Scargle 제외.**
- **2주차 — 핵심 검증:** **그룹핑-키 ablation**(포트무관/셔플/8080 특별취급 제거)으로 타이밍·크기 규칙성만으로 날짜교차 Bot recall 유지되는지 → 통과=행위, 실패=8080 지문(정직 보고). 동시에 **FP를 held-out benign(일자 분리)/worst-day로 재측정**해 헤드라인 교체.
- **3주차 — 교수 정합:** ① 기존 단일-flow 행위 피처(Flow IAT·Active/Idle·Pkt Len Std·flag)에 대한 **Bot SHAP 귀속**(교수 3 "단위 행위") ② Suricata threshold/flowbits·RITA 4차원 → 우리 피처 **매핑표**(교수 5 "오픈규칙") ③ "60초 내 동일 port 소형 동방향 flow K회" **룰 baseline vs ML 비교**(교수 4 "시나리오" 경량).
- **4주차 — 보고서:** temporal=오픈규칙 행위 탐지의 ML 이식(집계 근사로 정직 표기), recall 상승=행위 정교화. 100%=동일분포 sanity floor / 날짜교차=data-different 일반화(일부만 유지가 정상). 단일 봇캡처·단일포트 한계 명시. JA3/DGA/IP평판/host-pair=future work.
- **종료조건:** 새 피처가 macro recall +0.05를 못 주면 추가 중단 → 잔여 시간을 **검증·정직평가·정합 서사**에 투입.

## 버릴 것 / 범위 밖
- IP 평판(Shadowserver/Feodo/ET botcc) · JA3/JA4 · DGA/DNS · IRC/HTTP payload 시그니처 → **데이터에 payload·IP·DNS 없음** + 일부는 교수가 피하라 한 IP 의존. (오픈규칙은 '행위·임계값 로직'만 포팅, content 매칭은 버림)
- 딥 시퀀스(LSTM/CNN-LSTM)·그래프(GNN/XG-BoT)·BotMiner cross-plane·풀 시나리오 엔진 → IP 토폴로지/host 시퀀스 필수, 경량 트리 정체성과 충돌. 발상만 차용(Dst Port=pseudo-host, lag 피처).
- 440GB PCAP 재처리(디스크 84GB), novelty/이상탐지(이미 Bot 0 실패), GroupDRO 고도화, multiclass·SMOTE, 위험점수·LLM 고도화 → 무게 낮춤/보류.
- 단계태그 엔진·near-dup 해시버킷(기둥3) → **저비용 lag 1~2개로만 축소**, 나머지 future work.
- 'zero-day/처음 보는 공격/전이=본질적 천장' 프레이밍 → 폐기.

## 교수 피드백 정합 매핑
| 교수 피드백 | 우리 대응 |
|---|---|
| 1) 데이터 달라져도 탐지=규칙 정교화 | 그룹핑-키 ablation + 날짜교차 평가 |
| 2) 알려진 공격 100% 기본·봇넷 FN 허용 | 100%=동일분포 sanity floor / 날짜교차 recall@고정FP, PR-AUC |
| 3) 단위 행위(패킷/단일 로그) 명확한 분석 | 단일-flow 행위 피처 Bot SHAP 귀속(prong A) |
| 4) 시나리오·연관(단일 장비 의존 X) | 경량 lag 피처 + 룰 baseline (엔진은 안 지음) |
| 5) 오픈규칙(Snort/Suricata) 힌트 | RITA 4차원·Suricata threshold/flowbits → 피처 매핑표 |
| 6) 자원 활용 부수적 | 효율(경량성·모델크기) 무게 낮춤 |
| 7) 위험도 가볍게+테스트 많이 | conformal 유지, 에너지는 검증·ablation에 |

## 핵심 출처 (검증된)
- Ares 봇넷(IDS2018 Bot): 전부 port 8080, hello/report/upload(스크린샷)·400초 주기 — DistriNet CNS2022 문서.
- 봇넷 경량 ML: RandomForest가 CNN 대체·PR-AUC≈0.54(봇넷 본질적 난이도) — arXiv 2605.23004.
- 비커닝 주기성 피처: AlAhmadi 2016, RITA/Zeek(host-pair·서브초 기반 — 우리는 근사).
- 시나리오/킬체인: Wilkens KCSM(arXiv 2103.14628, IP 필수 → 우리는 경량 차용).
- 정직평가 정당성: Arp et al. "Dos and Don'ts", TESSERACT.
