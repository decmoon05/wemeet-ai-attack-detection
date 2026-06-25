# -*- coding: utf-8 -*-
"""v0.4b 분포무관 triage — benign conformal p-value + Neyman-Pearson 임계값 (XGB/F2).

GPT 고급검증 반영:
- 깨진 확률보정 우회: 운영점수=benign-tail conformal p-value(과거 정상 기준), 임계값=NP order-statistic.
- 위험점수는 '확률' 아님 → operational risk(log-tail). 확률 품질은 BSS로 보고(raw Brier 금지).
- 단조보정은 Bot recall 못 살림 → Bot은 별도 novelty 필요(여기선 미구현, 결과만 확인).
"""
import glob, os, re, time, json
import numpy as np
import pandas as pd
from scipy.stats import binom
from sklearn.metrics import average_precision_score, brier_score_loss
from xgboost import XGBClassifier

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DATA = os.path.join(ROOT, "sources", "cicids2018")
FINGERPRINT = ['Fwd Seg Size Min', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes']
ROBUST_EXTRA = ['Protocol']
INFIL = {228, 301}
FOLDS = {221: '2/21 DDoS', 223: '2/23 Web', 302: '3/2 Bot'}
BUDGETS = [20, 50, 100]
CAP, TREES, CAL_BENIGN, DELTA = 150000, 350, 300000, 0.05   # near-full 확정 실행


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
    X = df.drop(columns=['Label']).drop(columns=[c for c in FINGERPRINT + ROBUST_EXTRA], errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    return X, y


def xgb(ytr):
    pos = max(int(ytr.sum()), 1); neg = len(ytr) - pos
    return XGBClassifier(n_estimators=TREES, max_depth=8, learning_rate=0.2, tree_method='hist',
                         n_jobs=-1, random_state=42, scale_pos_weight=neg / pos, eval_metric='logloss')


def np_threshold(benign_scores, alpha, delta=DELTA):
    """Neyman-Pearson order-statistic 임계값: P(FPR>alpha)<=delta. alert = score > thr."""
    s = np.sort(benign_scores); n = len(s)           # 오름차순
    for k in range(1, n + 1):                        # P(Bin(n,1-a) >= k) <= delta 되는 최소 k
        if binom.sf(k - 1, n, 1 - alpha) <= delta:
            return float(s[k - 1])                   # k번째로 '작은' 값(=상위 tail) → 보수적 임계값
    return float(s[-1]) + 1e-9                        # 표본 부족 → 사실상 전부 차단


def benign_pvalue(cal_benign, scores):
    cal = np.sort(cal_benign)
    n_ge = len(cal) - np.searchsorted(cal, scores, side='left')
    return (1.0 + n_ge) / (len(cal) + 1.0)


def op_risk(pB, floor=1e-6):
    p = np.clip(pB, floor, 1.0)
    return 100.0 * np.clip(-np.log10(p) / -np.log10(floor), 0, 1)


def main():
    t0 = time.time()
    paths = {order_of(day_of(f)): f for f in glob.glob(os.path.join(DATA, "*.parquet"))}
    clean = sorted(o for o in paths if o not in INFIL)
    out = []

    for d, lbl in FOLDS.items():
        tr_days = [o for o in clean if o < d]
        tr = pd.concat([read_day(paths[o], cap=CAP) for o in tr_days], ignore_index=True)
        Xtr, ytr = to_Xy(tr); cols = list(Xtr.columns[Xtr.nunique() > 1])
        m = xgb(ytr).fit(Xtr[cols], ytr)

        # conformal benign 보정셋: 과거 일자 정상(uncap) 샘플
        ben = pd.concat([read_day(paths[o]) for o in tr_days], ignore_index=True)
        ben = ben[ben['Label'].astype(str).str.strip().str.lower() == 'benign']
        if len(ben) > CAL_BENIGN:
            ben = ben.sample(CAL_BENIGN, random_state=42)
        Xb, _ = to_Xy(ben); Xb = Xb.reindex(columns=cols, fill_value=0)
        cal_scores = m.predict_proba(Xb[cols])[:, 1]

        # 테스트(풀 자연분포)
        te = read_day(paths[d]); Xte, yte = to_Xy(te); Xte = Xte.reindex(columns=cols, fill_value=0)
        s = m.predict_proba(Xte[cols])[:, 1]
        prev = float(yte.mean())
        bs = brier_score_loss(yte, s); bss = round(1 - bs / (prev * (1 - prev)), 3) if 0 < prev < 1 else None

        pB = benign_pvalue(cal_scores, s); risk = op_risk(pB)
        rec = {'fold': lbl, 'n': int(len(yte)), 'prev': round(prev, 5),
               'AP': round(average_precision_score(yte, s), 4), 'BSS_raw': bss,
               'risk_atk': round(float(risk[yte == 1].mean()), 1) if (yte == 1).any() else None,
               'risk_ben': round(float(risk[yte == 0].mean()), 1), 'ops': {}}
        for b in BUDGETS:
            thr = np_threshold(cal_scores, b / 1e5)
            atk = s[yte == 1]; bn = s[yte == 0]
            r = float((atk > thr).mean()) if len(atk) else None
            fp = (bn > thr).sum(); fprate = fp / len(bn) * 1e5
            rec['ops'][b] = {'recall': round(r, 3) if r is not None else None,
                             'fp_per_100k': round(fprate, 1), 'fp_count': int(fp)}
        out.append(rec); print(f"  {lbl} done ({time.time()-t0:.0f}s)")

    with open(os.path.join(ROOT, 'output', 'metrics_v04b.json'), 'w', encoding='utf-8') as f:
        json.dump({'model': 'XGB/F2', 'method': 'conformal benign-tail + NP threshold',
                   'cal_benign': CAL_BENIGN, 'delta': DELTA, 'results': out}, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 100)
    for r in out:
        print(f"\n[{r['fold']}] n={r['n']:,} prev={r['prev']} AP={r['AP']} "
              f"BSS_raw={r['BSS_raw']}  운영위험점수 공격/정상={r['risk_atk']}/{r['risk_ben']}")
        print(f"   {'FP예산':>8}{'recall':>9}{'실제FP/100k':>13}{'FP건수':>9}")
        for b in BUDGETS:
            o = r['ops'][b]
            print(f"   {b:>8}{str(o['recall']):>9}{o['fp_per_100k']:>13}{o['fp_count']:>9}")
    print("=" * 100)


if __name__ == '__main__':
    main()
