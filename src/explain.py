# -*- coding: utf-8 -*-
"""v0.3 SHAP 근거 — 잠금모델 XGB/F2의 전역/개별 탐지 근거 + LLM용 구조화 evidence.

DDoS fold(2/21): 학습 2/14~2/20 → 테스트 2/21. 전역 beeswarm/bar + 개별 waterfall(TP/FP)
+ evidence_sample.json(이벤트별 top-k 기여 피처 → v0.5 LLM 입력).
"""
import glob, os, re, json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import shap
from xgboost import XGBClassifier

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DATA = os.path.join(ROOT, "sources", "cicids2018")
OUT = os.path.join(ROOT, "output", "shap"); os.makedirs(OUT, exist_ok=True)
DROP = ['Fwd Seg Size Min', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Protocol']  # F2
TRAIN_ORD = [214, 215, 216, 220]; TEST_ORD = 221; CAP = 20000


def day_of(p): return os.path.basename(p).split('_')[0]
def order_of(d): q = d.split('-'); return int(q[-2]) * 100 + int(q[-3])


def read_day(path, cap=None, seed=42):
    df = pd.read_parquet(path); df.columns = [c.strip() for c in df.columns]
    if cap:
        df = pd.concat([g.sample(cap, random_state=seed) if len(g) > cap else g
                        for _, g in df.groupby('Label', sort=False)], ignore_index=True)
    return df


def to_Xy(df):
    y = (df['Label'].astype(str).str.strip().str.lower() != 'benign').astype(int).values
    lab = df['Label'].astype(str).values
    X = df.drop(columns=['Label']).drop(columns=[c for c in DROP], errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    return X, y, lab


def main():
    paths = {order_of(day_of(f)): f for f in glob.glob(os.path.join(DATA, "*.parquet"))}
    tr = pd.concat([read_day(paths[o], cap=CAP) for o in TRAIN_ORD], ignore_index=True)
    Xtr, ytr, _ = to_Xy(tr); cols = list(Xtr.columns[Xtr.nunique() > 1])
    pos = int(ytr.sum()); neg = len(ytr) - pos
    model = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.2, tree_method='hist',
                          n_jobs=-1, random_state=42, scale_pos_weight=neg / pos, eval_metric='logloss')
    model.fit(Xtr[cols], ytr)

    te = read_day(paths[TEST_ORD]); Xte, yte, lab = to_Xy(te); Xte = Xte.reindex(columns=cols, fill_value=0)
    score = model.predict_proba(Xte[cols])[:, 1]

    expl = shap.TreeExplainer(model)

    # --- 전역: 샘플 3000 (정상/공격 혼합) ---
    rng = np.random.RandomState(42)
    samp = rng.choice(len(Xte), size=min(3000, len(Xte)), replace=False)
    svg = expl(Xte[cols].iloc[samp])
    mean_abs = np.abs(svg.values).mean(0)
    top_global = sorted(zip(cols, mean_abs), key=lambda x: -x[1])[:12]
    print("=== 전역 top-12 기여 피처 (mean|SHAP|) ===")
    for f, v in top_global:
        print(f"  {v:8.4f}  {f}")
    try:
        shap.plots.bar(svg, max_display=15, show=False); plt.tight_layout()
        plt.savefig(os.path.join(OUT, "global_bar.png"), dpi=120, bbox_inches='tight'); plt.close()
        shap.plots.beeswarm(svg, max_display=15, show=False); plt.tight_layout()
        plt.savefig(os.path.join(OUT, "global_beeswarm.png"), dpi=120, bbox_inches='tight'); plt.close()
        print("  전역 플롯 저장: global_bar.png, global_beeswarm.png")
    except Exception as e:
        print(f"  (전역 플롯 스킵: {e})")

    # --- 개별: TP(공격·고점수) 4 + FP(정상·고점수 오탐) 4 ---
    tp_idx = [i for i in np.argsort(-score) if yte[i] == 1][:4]
    fp_idx = [i for i in np.argsort(-score) if yte[i] == 0][:4]
    sel = tp_idx + fp_idx
    svs = expl(Xte[cols].iloc[sel])
    evidence = []
    for j, i in enumerate(sel):
        contrib = sorted(zip(cols, svs.values[j], Xte[cols].iloc[i].values),
                         key=lambda x: -abs(x[1]))[:5]
        ev = {'event_id': int(i), 'true_label': lab[i],
              'pred': 'attack' if score[i] >= 0.5 else 'benign',
              'model_score': round(float(score[i]), 4),
              'kind': 'TP(공격 적중)' if (yte[i] == 1) else 'FP(정상 오탐)',
              'top_evidence': [{'feature': f, 'shap': round(float(s), 4), 'value': round(float(v), 3)}
                               for f, s, v in contrib]}
        evidence.append(ev)
        try:
            shap.plots.waterfall(svs[j], max_display=8, show=False)
            plt.savefig(os.path.join(OUT, f"local_{ev['kind'][:2]}_{i}.png"), dpi=110, bbox_inches='tight'); plt.close()
        except Exception:
            pass

    with open(os.path.join(OUT, "evidence_sample.json"), 'w', encoding='utf-8') as f:
        json.dump({'fold': '2/21 DDoS', 'global_top': [[f, round(float(v), 4)] for f, v in top_global],
                   'events': evidence}, f, ensure_ascii=False, indent=2)

    print("\n=== 개별 이벤트 근거 예시 (LLM 입력용) ===")
    for ev in evidence[:6]:
        print(f"\n[{ev['kind']}] event {ev['event_id']} | true={ev['true_label']} | score={ev['model_score']}")
        for c in ev['top_evidence']:
            sign = '↑공격' if c['shap'] > 0 else '↓정상'
            print(f"    {sign}  {c['feature']}={c['value']}  (SHAP {c['shap']:+.3f})")
    print(f"\n저장: {OUT}\\evidence_sample.json + 플롯들")


if __name__ == '__main__':
    main()
