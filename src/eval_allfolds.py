# -*- coding: utf-8 -*-
"""갭1+2 — 전 공격군 날짜교차 이진 평가 (XGB/F2).

시간순: 테스트일 이전 clean 일자로만 학습. 각 공격일을 held-out 테스트로.
Infiltration은 라벨 불신 → 별도 표기(부록). 테스트는 풀 자연분포 + conformal NP 임계값.
"""
import glob, os, re, json, time
import numpy as np
import pandas as pd
from scipy.stats import binom
from sklearn.metrics import average_precision_score, recall_score
from xgboost import XGBClassifier

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DATA = os.path.join(ROOT, "sources", "cicids2018")
DROP = ['Fwd Seg Size Min', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Protocol']
CAP, TREES, CALB, DELTA = 60000, 300, 200000, 0.05
# 테스트 대상 일자 (order: MM*100+DD) → (라벨, 학습에 같은군 있었나)
FOLDS = [
    (215, 'DoS(2/15) GoldenEye·Slowloris', 'unseen'),   # 첫 DoS
    (216, 'DoS(2/16) Hulk·SlowHTTP', 'same-family'),     # DoS 이미 봄(2/15)
    (220, 'DDoS(2/20) LOIC-HTTP', 'unseen'),
    (221, 'DDoS(2/21) HOIC', 'same-family'),
    (222, 'Web(2/22) BF·XSS·SQLi', 'unseen'),
    (223, 'Web(2/23)', 'same-family'),
    (302, 'Bot(3/2)', 'unseen'),
    (228, 'Infiltration(2/28) [라벨불신]', 'unseen·부록'),
    (301, 'Infiltration(3/1) [라벨불신]', 'same·부록'),
]
INFIL = {228, 301}


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
    X = df.drop(columns=['Label']).drop(columns=[c for c in DROP], errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    return X, y


def xgb(ytr):
    pos = max(int(ytr.sum()), 1); neg = len(ytr) - pos
    return XGBClassifier(n_estimators=TREES, max_depth=8, learning_rate=0.2, tree_method='hist',
                         n_jobs=-1, random_state=42, scale_pos_weight=neg / pos, eval_metric='logloss')


def np_thr(b, a, delta=DELTA):
    s = np.sort(b); n = len(s)
    for k in range(1, n + 1):
        if binom.sf(k - 1, n, 1 - a) <= delta:
            return float(s[k - 1])
    return float(s[-1]) + 1e-9


def main():
    t0 = time.time()
    paths = {order_of(day_of(f)): f for f in glob.glob(os.path.join(DATA, "*.parquet"))}
    all_clean = sorted(o for o in paths if o not in INFIL)
    out = []
    for d, lbl, expo in FOLDS:
        train_days = [o for o in all_clean if o < d]   # 과거 clean만 (Infiltration 학습 제외)
        if not train_days:
            continue
        tr = pd.concat([read_day(paths[o], cap=CAP) for o in train_days], ignore_index=True)
        Xtr, ytr = to_Xy(tr); cols = list(Xtr.columns[Xtr.nunique() > 1])
        m = xgb(ytr).fit(Xtr[cols], ytr)
        # conformal benign 보정셋
        bn = tr[tr['Label'].astype(str).str.strip().str.lower() == 'benign']
        Xb, _ = to_Xy(bn); Xb = Xb.reindex(columns=cols, fill_value=0)
        cal = np.sort(m.predict_proba(Xb[cols])[:, 1])
        # 테스트(풀 자연분포)
        te = read_day(paths[d]); Xte, yte = to_Xy(te); Xte = Xte.reindex(columns=cols, fill_value=0)
        s = m.predict_proba(Xte[cols])[:, 1]
        row = {'fold': lbl, 'exposure': expo, 'n': int(len(yte)), 'atk': int(yte.sum()),
               'prev': round(float(yte.mean()), 5), 'AP': round(average_precision_score(yte, s), 4)}
        for b in (20, 100):
            thr = np_thr(cal, b / 1e5)
            atk = s[yte == 1]; ben = s[yte == 0]
            row[f'rec@{b}'] = round(float((atk > thr).mean()), 3) if len(atk) else None
            row[f'fp@{b}'] = round(float((ben > thr).mean() * 1e5), 1)
        out.append(row); print(f"  {lbl} ({time.time()-t0:.0f}s)")

    json.dump({'cap': CAP, 'results': out}, open(os.path.join(ROOT, 'output', 'metrics_allfolds.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print("\n" + "=" * 112)
    print(f"{'fold':<34}{'노출':<14}{'공격수':>9}{'prev':>9}{'AP':>8}{'rec@20':>8}{'fp@20':>8}{'rec@100':>9}{'fp@100':>8}")
    for r in out:
        print(f"{r['fold']:<34}{r['exposure']:<14}{r['atk']:>9}{r['prev']:>9}{r['AP']:>8}"
              f"{str(r['rec@20']):>8}{r['fp@20']:>8}{str(r['rec@100']):>9}{r['fp@100']:>8}")
    print("=" * 112)


if __name__ == '__main__':
    main()
