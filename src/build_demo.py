# -*- coding: utf-8 -*-
"""v0.6 데모 데이터 — 테스트일(2/21) 샘플을 스코어링: 모델점수·conformal 위험점수·우선순위·SHAP top3·설명.
출력: output/demo_events.json (Streamlit 대시보드 입력)."""
import os, sys, json, glob, re
sys.path.insert(0, os.path.dirname(__file__))
import numpy as np
import pandas as pd
from scipy.stats import binom
import shap
from xgboost import XGBClassifier
from llm_explainer import template_explain, benign_medians

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DATA = os.path.join(ROOT, "sources", "cicids2018")
DROP = ['Fwd Seg Size Min', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Protocol']
TRAIN = [214, 215, 216, 220]; TEST = 221; CAP = 20000


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


def np_thr(b, a, delta=0.05):
    s = np.sort(b); n = len(s)
    for k in range(1, n + 1):
        if binom.sf(k - 1, n, 1 - a) <= delta:
            return float(s[k - 1])
    return float(s[-1]) + 1e-9


def main():
    paths = {order_of(day_of(f)): f for f in glob.glob(os.path.join(DATA, "*.parquet"))}
    tr = pd.concat([read_day(paths[o], cap=CAP) for o in TRAIN], ignore_index=True)
    Xtr, ytr, _ = to_Xy(tr); cols = list(Xtr.columns[Xtr.nunique() > 1])
    pos = int(ytr.sum()); neg = len(ytr) - pos
    model = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.2, tree_method='hist',
                          n_jobs=-1, random_state=42, scale_pos_weight=neg / pos, eval_metric='logloss').fit(Xtr[cols], ytr)

    # conformal benign 보정셋 + NP 임계값(우선순위 경계)
    benign_tr = tr[tr['Label'].astype(str).str.strip().str.lower() == 'benign']
    Xb, _, _ = to_Xy(benign_tr); Xb = Xb.reindex(columns=cols, fill_value=0)
    cal = np.sort(model.predict_proba(Xb[cols])[:, 1])
    thr = {b: np_thr(cal, b / 1e5) for b in (20, 50, 100)}

    # 테스트일 샘플(공격 500 + 정상 1200)
    te = read_day(paths[TEST]); Xte, yte, lab = to_Xy(te); Xte = Xte.reindex(columns=cols, fill_value=0)
    rng = np.random.RandomState(42)
    atk_i = np.where(yte == 1)[0]; ben_i = np.where(yte == 0)[0]
    sel = np.concatenate([rng.choice(atk_i, min(500, len(atk_i)), False),
                          rng.choice(ben_i, min(1200, len(ben_i)), False)])
    Xs = Xte.iloc[sel]; scores = model.predict_proba(Xs[cols])[:, 1]

    # conformal p-value → 운영 위험점수(0~100)
    def pval(s): return (1 + (len(cal) - np.searchsorted(cal, s, 'left'))) / (len(cal) + 1)
    risk = 100 * np.clip(-np.log10(np.clip(pval(scores), 1e-6, 1)) / 6, 0, 1)

    def prio(sc):
        return "P1" if sc >= thr[20] else ("P2" if sc >= thr[50] else ("P3" if sc >= thr[100] else "관찰"))

    expl = shap.TreeExplainer(model); sv = expl(Xs[cols])
    med = benign_medians(set(cols))

    events = []
    for j in range(len(sel)):
        i = int(sel[j]); sc = float(scores[j])
        contrib = sorted(zip(cols, sv.values[j], Xs[cols].iloc[j].values), key=lambda x: -abs(x[1]))[:5]
        top = [{'feature': f, 'shap': round(float(s), 3), 'value': round(float(v), 3)} for f, s, v in contrib]
        ev = {'event_id': i, 'true_label': lab[sel[j]], 'pred': 'attack' if sc >= 0.5 else 'benign',
              'model_score': round(sc, 4), 'risk': round(float(risk[j]), 1), 'priority': prio(sc),
              'top_evidence': top}
        ev['explanation'] = template_explain(ev, med)
        ev['summary'] = ('공격 의심' if sc >= 0.5 else '정상') + f" · {ev['priority']} · 위험 {ev['risk']}"
        events.append(ev)

    events.sort(key=lambda e: -e['risk'])
    out = {'fold': '2/21 (train 2/14~2/20)', 'thresholds': {str(k): round(v, 4) for k, v in thr.items()},
           'n': len(events), 'events': events}
    p = os.path.join(ROOT, 'output', 'demo_events.json')
    json.dump(out, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    from collections import Counter
    print("저장:", p, "| 이벤트", len(events), "| 우선순위", dict(Counter(e['priority'] for e in events)))


if __name__ == '__main__':
    main()
