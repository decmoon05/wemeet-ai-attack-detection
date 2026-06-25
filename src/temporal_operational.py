# -*- coding: utf-8 -*-
"""운영 임계값 검증 — temporal Bot 0.39가 '과거기반' 임계값에서 얼마나 남나.

오라클(테스트benign) vs 과거기반(median-day/last-2/q75) 임계값 비교.
GPT 검증: Bot 0.39는 진단상한. 운영값이 핵심.
"""
import glob, os, json, time, sys, re
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
CACHE = os.path.join(ROOT, "sources", "raw_ts", "cache")
TEMP_PREFIX = ('p_fc_', 'p_pk_', 'p_syn_', 'p_rst_', 't_', 'g1', 'g10', 'g60')
TEMP_NAMES = {'g1', 'g10', 'g60'}
NONFEAT = ['Label', 'fam', 'day', 'second', 'Timestamp', 'Dst Port', 'Protocol', 'tot_pkts',
           'Fwd Seg Size Min', 'Init Fwd Win Byts', 'Init Bwd Win Byts']


def is_temp(c): return c in TEMP_NAMES or any(c.startswith(p) for p in TEMP_PREFIX)


def load_all():
    return pd.concat([pd.read_parquet(f) for f in sorted(glob.glob(os.path.join(CACHE, "*.parquet")))], ignore_index=True)


def to_X(df, cols=None):
    X = df.drop(columns=[c for c in NONFEAT if c in df.columns], errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    if cols is not None: X = X.reindex(columns=cols, fill_value=0)
    return X


def main():
    t0 = time.time()
    full = load_all()
    full['fam'] = full['Label'].astype(str).map(lambda l: (
        'Benign' if str(l).lower() == 'benign' else 'DDoS' if 'ddos' in str(l).lower() else
        'Bot' if 'bot' in str(l).lower() else 'Web' if any(k in str(l).lower() for k in ('web', 'xss', 'sql')) else
        'BruteForce' if any(k in str(l).lower() for k in ('ftp', 'ssh', 'brute')) else
        'DoS' if 'dos' in str(l).lower() else 'Other'))
    print(f"로드 {len(full):,} ({time.time()-t0:.0f}s)")

    out = []
    for hold in ['Bot', 'DoS', 'DDoS', 'BruteForce', 'Web']:
        if hold not in full['fam'].values: continue
        tr = full[(full['fam'] == 'Benign') | ((full['fam'] != hold) & (full['fam'] != 'Other'))]
        Xtr = to_X(tr); ytr = (tr['fam'] != 'Benign').astype(int).values
        cols = list(Xtr.columns[Xtr.nunique() > 1]); Xtr = Xtr[cols]
        pos = max(int(ytr.sum()), 1); neg = len(ytr) - pos
        m = XGBClassifier(n_estimators=250, max_depth=8, learning_rate=0.2, tree_method='hist',
                          n_jobs=-1, random_state=42, scale_pos_weight=neg / pos, eval_metric='logloss').fit(Xtr, ytr)
        te_a = full[full['fam'] == hold]; te_b = full[full['fam'] == 'Benign']
        sa = m.predict(to_X(te_a, cols), output_margin=True)
        sb = m.predict(to_X(te_b, cols), output_margin=True)

        # 과거 benign 일자별 99.9% 분위
        days = sorted(tr[tr['fam'] == 'Benign']['day'].unique())
        qd = {}
        for dd, g in tr[tr['fam'] == 'Benign'].groupby('day'):
            qd[dd] = float(np.quantile(m.predict(to_X(g, cols), output_margin=True), 1 - 100 / 1e5, method='higher'))
        def at(thr): return round(float((sa >= thr).mean()), 3), round(float((sb >= thr).mean() * 1e5), 0)

        thr_oracle = float(np.quantile(sb, 1 - 100 / 1e5, method='higher'))
        thr_median = float(np.median(list(qd.values())))
        thr_worst = float(np.max(list(qd.values())))
        thr_last2 = float(np.median([qd[d] for d in days[-2:]]))
        thr_q75 = float(np.quantile(list(qd.values()), 0.75))

        r_or, f_or = at(thr_oracle); r_md, f_md = at(thr_median)
        r_ws, f_ws = at(thr_worst); r_l2, f_l2 = at(thr_last2); r_q7, f_q7 = at(thr_q75)
        out.append({'hold': hold, 'oracle': [r_or, f_or], 'median_day': [r_md, f_md],
                    'worst_day': [r_ws, f_ws], 'last2': [r_l2, f_l2], 'q75': [r_q7, f_q7]})
        print(f"  [{hold}] oracle {r_or}@{f_or} | median {r_md}@{f_md} | worst {r_ws}@{f_ws} | last2 {r_l2}@{f_l2} | q75 {r_q7}@{f_q7} ({time.time()-t0:.0f}s)")

    def conv(o):
        return {k: ([float(x) for x in v] if isinstance(v, list) else v) for k, v in o.items()}
    json.dump({'results': [conv(o) for o in out]}, open(os.path.join(ROOT, 'output', 'metrics_temporal_operational.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print("\n" + "=" * 100)
    print(f"{'unseen':<12}{'oracle':>14}{'median-day':>14}{'worst-day':>14}{'last-2':>14}{'q75':>14}")
    for o in out:
        def s(v): return f"{v[0]}@{int(v[1])}"
        print(f"{o['hold']:<12}{s(o['oracle']):>14}{s(o['median_day']):>14}{s(o['worst_day']):>14}{s(o['last2']):>14}{s(o['q75']):>14}")
    print("=" * 100)
    print("rec@fp. 과거기반(median/worst/last2/q75)이 oracle 대비 얼마나 남나 + 실제 fp가 예산(100) 지키나.")


if __name__ == '__main__':
    main()
