# -*- coding: utf-8 -*-
"""v0.5 설명 레이어 — 불변 evidence JSON → 사람이 읽는 5섹션 설명.

원칙: 설명기는 모델의 판정/점수를 바꾸지 않는다(설명만). 입력은 구조화 JSON뿐(원시 트래픽/IP 미전송).
문구는 정상(benign) 중앙값 대비 '높음/낮음'으로 값 인식(고정 방향 주장 금지).
경로: (1) 템플릿(키 불필요·결정론) (2) LLM(선택, ANTHROPIC 키). 실패 시 템플릿 폴백.
입력: output/shap/evidence_sample.json → 출력: output/explanations_sample.md
"""
import os, json, sys, glob, re
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass
import numpy as np
import pandas as pd

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DATA = os.path.join(ROOT, "sources", "cicids2018")
EVID = os.path.join(ROOT, "output", "shap", "evidence_sample.json")
OUTMD = os.path.join(ROOT, "output", "explanations_sample.md")
BENIGN_DAYS = ["DoS2-Friday-16-02-2018", "DDoS1-Tuesday-20-02-2018"]   # 정상 기준 표본

KOR = {  # 피처 → 한글 이름
    "Flow IAT Min": "패킷 도착 간격(최소)", "Fwd IAT Min": "순방향 도착 간격(최소)",
    "Flow IAT Mean": "평균 도착 간격", "Flow Packets/s": "초당 패킷 수",
    "Fwd Packets/s": "순방향 초당 패킷", "Bwd Packets/s": "역방향 초당 패킷",
    "Fwd Packet Length Max": "순방향 최대 패킷 크기", "Bwd Packet Length Max": "역방향 최대 패킷 크기",
    "Packet Length Mean": "평균 패킷 크기", "Packet Length Max": "최대 패킷 크기",
    "Fwd Header Length": "순방향 헤더 길이", "Bwd Header Length": "역방향 헤더 길이",
    "Total Fwd Packets": "순방향 패킷 수", "Total Backward Packets": "역방향 패킷 수",
    "Flow Duration": "흐름 지속시간", "Fwd Packet Length Std": "순방향 패킷 크기 편차",
    "Bwd Packet Length Std": "역방향 패킷 크기 편차", "Fwd Packets Length Total": "순방향 총 전송량",
}
# (낮을 때 의미, 높을 때 의미) — 방향이 확실한 피처만
HINT = {
    "Flow IAT Min": ("도착 간격이 매우 짧음 → 대량·고빈도 요청(플러드/DoS) 가능", None),
    "Fwd IAT Min": ("연속 전송 간격 짧음", None),
    "Flow Packets/s": (None, "초당 패킷이 많음 → 고빈도 트래픽"),
    "Fwd Packets/s": (None, "초당 패킷이 많음 → 고빈도 트래픽"),
    "Bwd Packets/s": (None, "응답 패킷률 높음"),
}
PROMPT_SYS = ("You are a cybersecurity analyst assistant. Input is an ML model's DETECTION RESULT "
              "(already decided). NEVER change verdict/score/priority. Explain ONLY in Korean, 5 sections: "
              "1)요약 2)근거 3)위험도 4)권고 확인 5)주의. Use only provided features; never invent. "
              "Avoid certainty; say '모델이 ~로 평가'.")


def benign_medians(features, cap=40000, seed=42):
    frames = []
    for f in glob.glob(os.path.join(DATA, "*.parquet")):
        if any(d in os.path.basename(f) for d in BENIGN_DAYS):
            df = pd.read_parquet(f); df.columns = [c.strip() for c in df.columns]
            b = df[df['Label'].astype(str).str.strip().str.lower() == 'benign']
            frames.append(b.sample(min(cap, len(b)), random_state=seed))
    full = pd.concat(frames, ignore_index=True)
    med = {}
    for feat in features:
        if feat in full.columns:
            med[feat] = float(pd.to_numeric(full[feat], errors='coerce').replace([np.inf, -np.inf], np.nan).median())
    return med


def risk_band(s): return "높음 (P1)" if s >= 0.9 else ("중간 (P2)" if s >= 0.5 else "낮음 (P3)")


def evidence_lines(top, med):
    out = []
    for c in top:
        f, s, v = c["feature"], c["shap"], c["value"]
        name = KOR.get(f, f); m = med.get(f)
        if m is None:
            rel = ""
        elif v > m * 1.15:
            rel = f"정상 중앙값({m:g}) 대비 **높음**"
        elif v < m * 0.85:
            rel = f"정상 중앙값({m:g}) 대비 **낮음**"
        else:
            rel = f"정상 중앙값({m:g})과 비슷"
        hint = ""
        if f in HINT and m is not None:
            low_h, high_h = HINT[f]
            if v < m * 0.85 and low_h: hint = f" → {low_h}"
            elif v > m * 1.15 and high_h: hint = f" → {high_h}"
        direction = "공격 방향" if s > 0 else "정상 방향"
        out.append(f"  - **{name}** = {v}: {rel}{hint} *({direction} 기여, SHAP {s:+.2f})*")
    return out


def template_explain(ev, med):
    score = ev["model_score"]; verdict = "공격 의심" if ev["pred"] == "attack" else "정상"
    s = [f"**1) 요약** — 모델이 이 흐름을 **{verdict}**으로 평가했습니다 (모델 점수 {score:.2f}).",
         "**2) 근거** — 판단에 가장 크게 기여한 특징:"]
    s += evidence_lines(ev["top_evidence"], med)
    s.append(f"**3) 위험도** — 모델 위험도 **{risk_band(score)}**. *(운영 위험점수·우선순위는 conformal triage(v0.4b)로 별도 산출)*")
    pos = [c for c in ev["top_evidence"] if c["shap"] > 0]
    if pos:
        top_name = KOR.get(pos[0]["feature"], pos[0]["feature"])
        s.append(f"**4) 권고 확인** — 해당 출발지/세션 트래픽을 점검하고 ‘{top_name}’ 관련 비정상 패턴을 확인하세요. 유사 흐름 동반 조회 권장.")
    else:
        s.append("**4) 권고 확인** — 비정상 신호 약함 → 우선순위 낮게 모니터링.")
    s.append("**5) 주의** — 벤치마크 데이터(CSE-CIC-IDS2018) 기반 **모델 추정**이며 확정 아님. 학습에 없던 새 공격군은 미탐될 수 있고 정상이 오탐될 수 있어 분석가 확인 필요.")
    return "\n".join(s)


def llm_explain(ev, med):
    try:
        if os.environ.get("ANTHROPIC_API_KEY"):
            import anthropic
            payload = {k: ev[k] for k in ("pred", "model_score", "top_evidence")}
            msg = anthropic.Anthropic().messages.create(
                model="claude-opus-4-8", max_tokens=700, system=PROMPT_SYS,
                messages=[{"role": "user", "content": json.dumps(payload, ensure_ascii=False)}])
            return msg.content[0].text + "\n\n*(LLM 생성 — 판정·점수 고정)*"
    except Exception as e:
        print(f"  (LLM 실패 → 템플릿 폴백: {e})")
    return template_explain(ev, med)


def main():
    data = json.load(open(EVID, encoding="utf-8"))
    feats = {c["feature"] for ev in data["events"] for c in ev["top_evidence"]}
    med = benign_medians(feats)
    use_llm = bool(os.environ.get("ANTHROPIC_API_KEY"))
    print(f"설명 경로: {'LLM(claude)+폴백' if use_llm else '템플릿(키 없음)'} · 정상 중앙값 {len(med)}개 로드")
    out = [f"# 탐지 결과 설명 샘플 — fold {data['fold']}", ""]
    for ev in data["events"]:
        head = f"## event {ev['event_id']}  [{ev.get('kind','')}, 실제={ev.get('true_label','?')}]"
        body = (llm_explain(ev, med) if use_llm else template_explain(ev, med))
        out += [head, body, ""]
        print("\n" + "=" * 70); print(head); print(body)
    open(OUTMD, "w", encoding="utf-8").write("\n".join(out))
    print(f"\n저장: {OUTMD}")


if __name__ == "__main__":
    main()
