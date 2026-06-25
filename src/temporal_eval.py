# -*- coding: utf-8 -*-
"""temporal 평가 — 캐시 parquet로 F2 vs F2+temporal LOFO 비교 (빠름).

캐시: sources/raw_ts/cache/<day>.parquet (temporal 피처 포함).
F2(temporal 제외) vs F2+temporal 을 leave-one-family-out으로. median-day 임계값 @100FP.
BruteForce는 cold-start라 별도 표기.
"""
import glob, os, re, json, time, sys
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
CACHE = os.path.join(ROOT, "sources", "raw_ts", "cache")
# temporal 피처(이 접두/이름)만 토글
TEMP_PREFIX = ('p_fc_', 'p_pk_', 'p_syn_', 'p_rst_', 't_', 'g1', 'g10', 'g60')
TEMP_NAMES = {'g1', 'g10', 'g60'}
# 누수/비피처 컬럼
NONFEAT = ['Label', 'fam', 'day', 'second', 'Timestamp', 'Flow ID', 'Src IP', 'Dst IP',
           'Src Port', 'Dst Port', 'Protocol', 'tot_pkts',
           'Fwd Seg Size Min', 'Init Fwd Win Byts', 'Init Bwd Win Byts']


def is_temporal(c):
    return c in TEMP_NAMES or any(c.startswith(p) for p in TEMP_PREFIX)


def load_all():
    dfs = []
    for f in sorted(glob.glob(os.path.join(CACHE, "*.parquet"))):
        d = pd.read_parquet(f)
        dfs.append(d)
    return pd.concat(dfs, ignore_index=True)


def to_X(df, use_temporal, cols=None):
    drop = [c for c in NONFEAT if c in df.columns]
    if not use_temporal:
        drop += [c for c in df.columns if is_temporal(c)]
    X = df.drop(columns=drop, errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    if cols is not None: X = X.reindex(columns=cols, fill_value=0)
    return X


def main():
    t0 = time.time()
    full = load_all()
    full['fam'] = full['Label'].astype(str).map(lambda l: (
        'Benign' if str(l).lower() == 'benign' else
        'DDoS' if 'ddos' in str(l).lower() else
        'Bot' if 'bot' in str(l).lower() else
        'Web' if any(k in str(l).lower() for k in ('web', 'xss', 'sql')) else
        'BruteForce' if any(k in str(l).lower() for k in ('ftp', 'ssh', 'brute')) else
        'DoS' if 'dos' in str(l).lower() else 'Other'))
    n_temp = sum(is_temporal(c) for c in full.columns)
    n_f2 = len([c for c in full.columns if c not in NONFEAT and not is_temporal(c)])
    print(f"로드 {len(full):,} · F2 ~{n_f2}피처 · temporal {n_temp}피처 · fam {dict(full['fam'].value_counts())} ({time.time()-t0:.0f}s)")

    out = []
    for hold in ['DoS', 'DDoS', 'Web', 'Bot', 'BruteForce']:
        if hold not in full['fam'].values: continue
        tr = full[(full['fam'] == 'Benign') | ((full['fam'] != hold) & (full['fam'] != 'Other'))]
        cold = (hold == 'BruteForce')

        def run(use_t):
            Xtr = to_X(tr, use_t); ytr = (tr['fam'] != 'Benign').astype(int).values
            cols = list(Xtr.columns[Xtr.nunique() > 1]); Xtr = Xtr[cols]
            pos = max(int(ytr.sum()), 1); neg = len(ytr) - pos
            m = XGBClassifier(n_estimators=250, max_depth=8, learning_rate=0.2, tree_method='hist',
                              n_jobs=-1, random_state=42, scale_pos_weight=neg / pos, eval_metric='logloss').fit(Xtr, ytr)
            te_a = full[full['fam'] == hold]; te_b = full[full['fam'] == 'Benign']
            sa = m.predict(to_X(te_a, use_t, cols), output_margin=True)
            sb = m.predict(to_X(te_b, use_t, cols), output_margin=True)
            # 공정비교: 테스트 benign으로 FP=100 강제 고정(=같은 오탐예산에서 recall)
            thr = float(np.quantile(sb, 1 - 100 / 1e5, method='higher'))
            rec = round(float((sa >= thr).mean()), 3); fp = round(float((sb >= thr).mean() * 1e5), 0)
            imp_t = None
            if use_t:
                fi = dict(zip(cols, m.feature_importances_))
                imp_t = round(float(sum(v for k, v in fi.items() if is_temporal(k))), 3)
            return rec, fp, imp_t

        r0, f0, _ = run(False); r1, f1, it = run(True)
        out.append({'holdout': hold, 'cold_start': bool(cold), 'F2_rec': float(r0), 'F2_fp': float(f0),
                    'F2temp_rec': float(r1), 'F2temp_fp': float(f1),
                    'temporal_imp': (float(it) if it is not None else None), 'delta': round(float(r1 - r0), 3)})
        print(f"  [{hold}{'·cold' if cold else ''}] F2 {r0}@{f0} → +temp {r1}@{f1} (Δ{r1-r0:+.3f}, temp중요도 {it}) ({time.time()-t0:.0f}s)")

    json.dump({'results': out}, open(os.path.join(ROOT, 'output', 'metrics_temporal.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print("\n" + "=" * 92)
    print(f"{'held-out(unseen)':<16}{'F2':>9}{'(fp)':>7}{'F2+temporal':>13}{'(fp)':>7}{'Δ':>8}{'temp중요도':>10}")
    for r in out:
        print(f"{r['holdout']+('·cold' if r['cold_start'] else ''):<16}{str(r['F2_rec']):>9}{str(r['F2_fp']):>7}"
              f"{str(r['F2temp_rec']):>13}{str(r['F2temp_fp']):>7}{r['delta']:>+8.3f}{str(r['temporal_imp']):>10}")
    print("=" * 92)
    print("Δ>0 + fp 예산 근처 = temporal 개선. BruteForce는 cold-start 해석주의. temp중요도=모델이 temporal에 의존한 정도.")


if __name__ == '__main__':
    main()
