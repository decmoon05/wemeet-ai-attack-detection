# -*- coding: utf-8 -*-
"""① 임계값 정책 개선 — LOIC·DoS-GE의 '임계값 전이 문제' 회복 시도.

문제: 과거 benign margin tail이 임계값을 과도하게 높여 운영 recall 0.
정책 비교(모두 과거 benign만 사용, 테스트 미사용):
 - all-past Q(1-a)        (기존)
 - last-1 / last-2 day
 - pooled 모든 과거 benign (날짜 무관 합본)
 - trimmed: 과거 일자별 분위의 '중앙값'(worst-day max 대신) → 한 날 오염 완화
 - recency exp weight (half-life 1, 2일) 가중 분위
검증: 각 정책의 운영 recall@FP + 실제 테스트 FP/100k. oracle도 표시.
"""
import glob, os, re, json, time, sys
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DATA = os.path.join(ROOT, "sources", "cicids2018")
DROP = ['Fwd Seg Size Min', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Protocol']
CAP, TREES, FP = 60000, 300, 100
TARGETS = {220: 'DDoS-LOIC(2/20)', 215: 'DoS-GE/Slow(2/15)', 221: 'DDoS-HOIC(2/21)', 302: 'Bot(3/2)'}
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


def main():
    t0 = time.time(); a = FP / 1e5
    paths = {order_of(day_of(f)): f for f in glob.glob(os.path.join(DATA, "*.parquet"))}
    clean = sorted(o for o in paths if o not in INFIL)
    out = []
    for d, lbl in TARGETS.items():
        tdays = [o for o in clean if o < d]
        tr = pd.concat([read_day(paths[o], cap=CAP) for o in tdays], ignore_index=True)
        Xtr, ytr = to_Xy(tr); cols = list(Xtr.columns[Xtr.nunique() > 1])
        m = xgb(ytr).fit(Xtr[cols], ytr)
        def margin(df):
            X, y = to_Xy(df); X = X.reindex(columns=cols, fill_value=0)
            return m.predict(X[cols], output_margin=True), y
        te = read_day(paths[d]); s_te, y_te = margin(te)
        atk = s_te[y_te == 1]; ben_te = s_te[y_te == 0]

        # 날짜별 benign margin
        by_day = {}
        for o in tdays:
            b = read_day(paths[o]); b = b[b['Label'].astype(str).str.strip().str.lower() == 'benign']
            if len(b) > 120000: b = b.sample(120000, random_state=1)
            sb, _ = margin(b); by_day[o] = sb

        def rec(thr): return round(float((atk >= thr).mean()), 3) if len(atk) else None
        def fp_te(thr): return round(float((ben_te >= thr).mean() * 1e5), 0)
        def Q(arr): return float(np.quantile(arr, 1 - a, method='higher'))

        pol = {}
        # all-past worst (일자별 분위 max) = 기존
        pol['worst-day'] = max(Q(by_day[o]) for o in tdays)
        # pooled 합본 분위
        pol['pooled'] = Q(np.concatenate([by_day[o] for o in tdays]))
        # trimmed: 일자별 분위의 중앙값(한 날 오염 완화)
        pol['median-day'] = float(np.median([Q(by_day[o]) for o in tdays]))
        # last-1 / last-2
        pol['last-1'] = Q(by_day[tdays[-1]])
        if len(tdays) >= 2:
            pol['last-2'] = Q(np.concatenate([by_day[o] for o in tdays[-2:]]))
        # recency exp weight (half-life 1일): 가중 분위 근사 = 가중 표본 재샘플
        w = {o: 0.5 ** ((d - o) / 1.0) for o in tdays}   # 단순 거리 가중
        wpool = np.concatenate([np.repeat(by_day[o], max(1, int(round(w[o] * 5)))) for o in tdays])
        pol['recency-hl1'] = Q(wpool)

        oracle_thr = Q(ben_te)
        row = {'fold': lbl, 'oracle_rec': rec(oracle_thr),
               'policies': {k: {'rec': rec(v), 'fp_te': fp_te(v)} for k, v in pol.items()}}
        out.append(row); print(f"  {lbl} ({time.time()-t0:.0f}s)")

    json.dump({'budget': FP, 'results': out},
              open(os.path.join(ROOT, 'output', 'metrics_threshold_policy.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print("\n" + "=" * 110)
    pols = ['worst-day', 'pooled', 'median-day', 'last-1', 'last-2', 'recency-hl1']
    print(f"{'fold':<18}{'oracle':>8}" + "".join(f"{p[:10]:>14}" for p in pols))
    for r in out:
        line = f"{r['fold']:<18}{str(r['oracle_rec']):>8}"
        for p in pols:
            c = r['policies'].get(p)
            line += f"{(str(c['rec'])+'/'+str(int(c['fp_te']))) if c else '-':>14}"
        print(line)
    print("=" * 110)
    print("표기 rec/fp_te = 운영recall / 실제 테스트 FP_per_100k. fp가 예산(100) 크게 넘으면 무효.")


if __name__ == '__main__':
    main()
