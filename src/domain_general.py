# -*- coding: utf-8 -*-
"""도메인 일반화 — 전이(transfer) 문제 공략.

진단: F2에 정보는 충분(target-day oracle Bot 0.996)하나 과거→미래 전이가 0.
가설: 날짜/공격군 특이 피처가 전이를 막는다. → '여러 공격군에서 공격방향 일치 + 날짜 비예측' 불변 피처만 학습.

방법:
 1. invariant feature 선택: (a) 날짜 예측력 낮고 (b) 여러 공격군에서 공격방향(공격 평균 > 정상 평균 방향) 부호 일치
 2. leave-one-family-out: 한 공격군 빼고 학습 → held-out family를 unseen으로 평가
 3. full-F2 vs invariant-only 비교 (recall@100FP, 과거 benign 임계값 median-day)
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
INFIL = {228, 301}
PER_DAY_BEN, PER_FAM = 25000, 15000


def day_of(p): return os.path.basename(p).split('_')[0]
def order_of(d): q = d.split('-'); return int(q[-2]) * 100 + int(q[-3])


def fam(l):
    l = l.lower()
    if l == 'benign': return 'Benign'
    if 'ddos' in l: return 'DDoS'
    if 'bot' in l: return 'Bot'
    if 'infil' in l: return 'Infiltration'
    if 'web' in l or 'xss' in l or 'sql' in l: return 'Web'
    if 'ftp' in l or 'ssh' in l or 'brute' in l: return 'BruteForce'
    if 'dos' in l: return 'DoS'
    return 'Other'


def load():
    parts = []
    for f in glob.glob(os.path.join(DATA, "*.parquet")):
        if order_of(day_of(f)) in INFIL: continue
        df = pd.read_parquet(f); df.columns = [c.strip() for c in df.columns]
        df['fam'] = df['Label'].astype(str).map(fam)
        df['day'] = order_of(day_of(f))
        b = df[df['fam'] == 'Benign']; parts.append(b.sample(min(PER_DAY_BEN, len(b)), random_state=42))
        for fm, g in df[df['fam'] != 'Benign'].groupby('fam'):
            if fm in ('Other', 'Infiltration'): continue
            parts.append(g.sample(min(PER_FAM, len(g)), random_state=42))
    return pd.concat(parts, ignore_index=True)


def to_X(df, cols=None):
    X = df.drop(columns=['Label', 'fam', 'day'], errors='ignore').drop(columns=[c for c in DROP], errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    if cols is not None: X = X.reindex(columns=cols, fill_value=0)
    return X


def select_invariant(full, cols, train_fams):
    """train_fams(held-out 제외) 기준: 공격방향 부호가 여러 family에서 일치 + 날짜 비예측 피처."""
    Xall = to_X(full, cols)
    ben = full['fam'] == 'Benign'
    ben_med = Xall[ben].median()
    # family별 공격방향 부호(공격 중앙값 > 정상 중앙값?)
    signs = []
    for fm in train_fams:
        m = full['fam'] == fm
        if m.sum() < 100: continue
        signs.append(np.sign(Xall[m].median() - ben_med))
    if not signs:
        return cols
    S = pd.concat(signs, axis=1)
    # 부호 일관성: 모든 family에서 같은 방향(절대 평균 부호 = 1) 인 피처
    consistency = S.replace(0, np.nan).mean(axis=1).abs()
    consistent = consistency[consistency >= 0.6].index.tolist()  # 60%+ family 방향일치
    # 날짜 비예측: 날짜별 benign 중앙값 변동(분산)이 작은 피처
    day_med = Xall[ben].groupby(full[ben]['day']).median()
    # 정규화 변동(robust): IQR 대비 날짜간 표준편차
    iqr = (Xall[ben].quantile(0.75) - Xall[ben].quantile(0.25)).replace(0, 1e-9)
    day_var = (day_med.std() / iqr).abs()
    stable = day_var[day_var <= day_var.median()].index.tolist()  # 변동 하위 50%
    inv = [c for c in cols if c in consistent and c in stable]
    return inv if len(inv) >= 8 else consistent[:20]


def xgb(ytr):
    pos = max(int(ytr.sum()), 1); neg = len(ytr) - pos
    return XGBClassifier(n_estimators=250, max_depth=6, learning_rate=0.2, tree_method='hist',
                         n_jobs=-1, random_state=42, scale_pos_weight=neg / pos, eval_metric='logloss')


def thr_median_day(margins_by_day, fp):
    return float(np.median([np.quantile(m, 1 - fp / 1e5, method='higher') for m in margins_by_day.values()]))


def main():
    t0 = time.time(); FP = 100
    full = load()
    cols = list(to_X(full).columns); cols = [c for c in cols if to_X(full)[c].nunique() > 1]
    fams = [f for f in full['fam'].unique() if f != 'Benign']
    print(f"로드 {len(full):,} · family {fams} · F2 {len(cols)}피처 ({time.time()-t0:.0f}s)")

    out = []
    for hold in ['DoS', 'Bot', 'Web', 'DDoS', 'BruteForce']:
        train_fams = [f for f in fams if f != hold]
        tr = full[(full['fam'] == 'Benign') | (full['fam'].isin(train_fams))]
        inv = select_invariant(full, cols, train_fams)

        def run(feat):
            Xtr = to_X(tr, feat); ytr = (tr['fam'] != 'Benign').astype(int).values
            m = xgb(ytr).fit(Xtr, ytr)
            # 과거 benign 일자별 margin (median-day 임계값)
            mbd = {}
            for d, g in tr[tr['fam'] == 'Benign'].groupby('day'):
                mbd[d] = m.predict(to_X(g, feat), output_margin=True)
            thr = thr_median_day(mbd, FP)
            te = full[full['fam'] == hold]; teb = full[full['fam'] == 'Benign']
            sa = m.predict(to_X(te, feat), output_margin=True)
            sb = m.predict(to_X(teb, feat), output_margin=True)
            return round(float((sa >= thr).mean()), 3), round(float((sb >= thr).mean() * 1e5), 0)

        # 각 모델의 alert 마스크 반환 버전 (OR 결합용, FP예산 각 절반)
        def run_mask(feat, fp_budget):
            Xtr = to_X(tr, feat); ytr = (tr['fam'] != 'Benign').astype(int).values
            m = xgb(ytr).fit(Xtr, ytr)
            mbd = {}
            for d, g in tr[tr['fam'] == 'Benign'].groupby('day'):
                mbd[d] = m.predict(to_X(g, feat), output_margin=True)
            thr = thr_median_day(mbd, fp_budget)
            te = full[full['fam'] == hold]; teb = full[full['fam'] == 'Benign']
            sa = m.predict(to_X(te, feat), output_margin=True)
            sb = m.predict(to_X(teb, feat), output_margin=True)
            return (sa >= thr), (sb >= thr)

        r_full, fp_full = run(cols)
        r_inv, fp_inv = run(inv)
        # OR 결합: 각 50 FP/100k 예산 → 합쳐서 ~100
        a_full, b_full = run_mask(cols, 50)
        a_inv, b_inv = run_mask(inv, 50)
        te_atk = full[full['fam'] == hold]
        atk_or = a_full | a_inv; ben_or = b_full | b_inv
        r_or = round(float(atk_or.mean()), 3); fp_or = round(float(ben_or.mean() * 1e5), 0)
        out.append({'holdout': hold, 'n_inv_feat': len(inv),
                    'full_F2_rec': r_full, 'full_F2_fp': fp_full,
                    'invariant_rec': r_inv, 'invariant_fp': fp_inv,
                    'OR_rec': r_or, 'OR_fp': fp_or})
        print(f"  [{hold}] full {r_full}@{fp_full} | inv({len(inv)}f) {r_inv}@{fp_inv} | OR {r_or}@{fp_or} ({time.time()-t0:.0f}s)")

    json.dump({'fp_budget': FP, 'results': out},
              open(os.path.join(ROOT, 'output', 'metrics_domain_general.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print("\n" + "=" * 96)
    print(f"{'held-out(unseen)':<16}{'full-F2':>11}{'(fp)':>7}{'invariant':>11}{'(fp)':>7}{'OR결합':>10}{'(fp)':>7}")
    for r in out:
        print(f"{r['holdout']:<16}{str(r['full_F2_rec']):>11}{str(r['full_F2_fp']):>7}"
              f"{str(r['invariant_rec']):>11}{str(r['invariant_fp']):>7}{str(r['OR_rec']):>10}{str(r['OR_fp']):>7}")
    print("=" * 96)
    print("OR결합 = full(잘되던 군)+invariant(unseen) 둘다 살림. 각 50FP/100k 예산.")


if __name__ == '__main__':
    main()
