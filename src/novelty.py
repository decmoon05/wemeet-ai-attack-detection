# -*- coding: utf-8 -*-
"""v0.7 novelty 분기 — benign-only IsolationForest + conformal p-value로 '미지 의심' 탐지.

지도학습이 못 잡는 unseen-family(Bot)를 보완. 정상만 학습 → 정상 이탈도(p-value)로 플래그.
검증: 각 공격군 day에서 novelty recall@고정 FP/100k (그 day benign으로 FP 측정).
'zero-day 탐지기' 아님 → 'benign 분포 이탈 의심' flag.
"""
import glob, os, re, json
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import IsolationForest

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DATA = os.path.join(ROOT, "sources", "cicids2018")
DROP = ['Fwd Seg Size Min', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Protocol']
FIT_DAYS = [214, 216, 220]      # benign 학습
CAL_DAY = 222                   # benign 보정(held-out)
EVAL = {214: 'BruteForce', 216: 'DoS-Hulk', 221: 'DDoS', 223: 'Web', 302: 'Bot(unseen)'}
BUDGETS = [20, 50, 100]


def day_of(p): return os.path.basename(p).split('_')[0]
def order_of(d): q = d.split('-'); return int(q[-2]) * 100 + int(q[-3])


def read_day(path):
    df = pd.read_parquet(path); df.columns = [c.strip() for c in df.columns]; return df


def feats(df, cols=None):
    X = df.drop(columns=['Label']).drop(columns=[c for c in DROP], errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    if cols is not None: X = X.reindex(columns=cols, fill_value=0)
    return X


def benign(df): return df[df['Label'].astype(str).str.strip().str.lower() == 'benign']


def main():
    paths = {order_of(day_of(f)): f for f in glob.glob(os.path.join(DATA, "*.parquet"))}

    # benign 학습 표본
    bf = pd.concat([benign(read_day(paths[o])).sample(30000, random_state=42) for o in FIT_DAYS], ignore_index=True)
    Xf = feats(bf); cols = list(Xf.columns[Xf.nunique() > 1])
    scaler = RobustScaler().fit(Xf[cols])
    iso = IsolationForest(n_estimators=200, max_samples=4096, contamination='auto',
                          random_state=42, n_jobs=-1).fit(scaler.transform(Xf[cols]))

    def nov(df):   # 클수록 이상(정상 이탈)
        return -iso.score_samples(scaler.transform(feats(df, cols)[cols]))

    # benign 보정셋 → conformal p-value 기준
    cal = np.sort(nov(benign(read_day(paths[CAL_DAY])).sample(40000, random_state=1)))

    def pval(scores):   # 작을수록 이상
        return (1 + (len(cal) - np.searchsorted(cal, scores, 'left'))) / (len(cal) + 1)

    print(f"benign-only IsolationForest 학습({len(bf):,}) · 보정({len(cal):,}) · 피처 {len(cols)}")
    out = []
    for o, name in EVAL.items():
        df = read_day(paths[o]); y = (df['Label'].astype(str).str.strip().str.lower() != 'benign').astype(int).values
        p = pval(nov(df))
        row = {'day': name, 'n': int(len(df)), 'atk': int(y.sum())}
        for b in BUDGETS:
            a = b / 1e5
            flag = p <= a    # 미지 의심
            rec = float(flag[y == 1].mean()) if y.sum() else None
            fp = float(flag[y == 0].mean() * 1e5)
            row[f'rec@{b}'] = round(rec, 3) if rec is not None else None
            row[f'fp@{b}'] = round(fp, 1)
        out.append(row)

    json.dump({'method': 'benign-only IsolationForest + conformal', 'results': out},
              open(os.path.join(ROOT, 'output', 'metrics_novelty.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)

    print("\n" + "=" * 90)
    print(f"{'day':<16}{'atk':>9}{'rec@20':>9}{'fp@20':>9}{'rec@50':>9}{'fp@50':>9}{'rec@100':>9}{'fp@100':>9}")
    for r in out:
        print(f"{r['day']:<16}{r['atk']:>9}{str(r['rec@20']):>9}{r['fp@20']:>9}{str(r['rec@50']):>9}{r['fp@50']:>9}{str(r['rec@100']):>9}{r['fp@100']:>9}")
    print("=" * 90)
    print("\n해석: novelty는 '정상 이탈 의심' flag. 지도학습이 놓친 Bot을 일부라도 잡으면 보완 가치.")


if __name__ == '__main__':
    main()
