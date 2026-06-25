# -*- coding: utf-8 -*-
"""v0.6 Streamlit 대시보드 — AI 공격탐지 triage 데모.
실행: streamlit run src/app.py   (먼저 python src/build_demo.py 로 데이터 생성)
"""
import os, json
import pandas as pd
import streamlit as st

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DEMO = os.path.join(ROOT, "output", "demo_events.json")

st.set_page_config(page_title="사이버보안 WE-Meet — 공격탐지 triage", layout="wide")


@st.cache_data
def load():
    d = json.load(open(DEMO, encoding="utf-8"))
    df = pd.DataFrame(d["events"])
    return d, df


if not os.path.exists(DEMO):
    st.error("output/demo_events.json 없음 → 먼저 `python src/build_demo.py` 실행")
    st.stop()

data, df = load()
st.title("🛡️ AI 기반 공격탐지 에이전트 — Triage")
st.caption(f"CSE-CIC-IDS2018 · fold {data['fold']} · XGBoost/F2 · 위험점수=conformal benign-tail (모델 추정, 확정 아님)")

# ---------- KPI ----------
c1, c2, c3, c4 = st.columns(4)
c1.metric("총 이벤트", data["n"])
c2.metric("P1 (긴급)", int((df["priority"] == "P1").sum()))
c3.metric("P2 (의심)", int((df["priority"] == "P2").sum()))
c4.metric("P3 (관찰)", int((df["priority"] == "P3").sum()))

# ---------- 필터 ----------
left, right = st.columns([2, 3])
with left:
    st.subheader("위험순 이벤트")
    prios = st.multiselect("우선순위", ["P1", "P2", "P3", "관찰"], default=["P1", "P2", "P3"])
    rmin = st.slider("최소 위험점수", 0, 100, 0)
    view = df[df["priority"].isin(prios) & (df["risk"] >= rmin)].sort_values("risk", ascending=False)
    st.dataframe(
        view[["event_id", "risk", "priority", "model_score", "pred", "true_label"]],
        use_container_width=True, height=460, hide_index=True,
        column_config={
            "risk": st.column_config.ProgressColumn("위험점수", min_value=0, max_value=100, format="%d"),
            "model_score": st.column_config.NumberColumn("모델점수", format="%.3f"),
            "pred": "판정", "true_label": "실제(참고)",
        },
    )

# ---------- 상세 ----------
with right:
    st.subheader("이벤트 상세 · 근거 · 설명")
    ids = view["event_id"].tolist()
    if ids:
        eid = st.selectbox("이벤트 선택", ids)
        ev = next(e for e in data["events"] if e["event_id"] == eid)
        a, b, c = st.columns(3)
        a.metric("위험점수", ev["risk"]); b.metric("우선순위", ev["priority"])
        c.metric("모델점수", f"{ev['model_score']:.3f}")
        st.markdown("**탐지 근거 (SHAP top)**")
        st.dataframe(pd.DataFrame(ev["top_evidence"]), hide_index=True, use_container_width=True)
        st.markdown("**설명**")
        st.markdown(ev["explanation"])

# ---------- 성능(정직한 평가) ----------
with st.expander("📊 모델 성능 (정직한 평가 — v0.4b conformal triage)"):
    st.markdown("""
| Fold | 운영 Recall @ FP/100k | 비고 |
|---|---|---|
| 2/21 DDoS 변형전이 | **0.825 @ ~6** | 배포가능 |
| 2/23 Web 희소(0.065%) | 0.40 @ 14~76 | 부분 탐지 |
| 3/2 Bot **unseen-family** | **0.0** | 미지 공격군 미탐 → novelty 분기 필요 |

- 무작위분할 F1 0.99는 **상한(배포지표 아님)**. 임계값은 0.5가 아니라 **과거 데이터 기반 NP FP예산**.
- 위험점수는 보정확률이 아니라 **conformal benign-tail 운영점수**(Web/Bot 확률은 신뢰 낮아 출력 보류).
""")
