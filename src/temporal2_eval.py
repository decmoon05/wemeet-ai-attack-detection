# -*- coding: utf-8 -*-
"""확장 temporal 평가 — cache2(장기창+규칙성+실패율)로 LOFO, worst-day 운영 임계값.
기존 temporal 결과(Bot 0.41 등)와 비교해 확장 피처가 더 올리는지.
"""
import glob, os, json, time, sys, re
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
CACHE2 = os.path.join(ROOT, "sources", "raw_ts", "cache2")
NONFEAT = ['Label', 'fam', 'day', 'second', 'Timestamp', 'Dst Port', 'Protocol', 'tot_pkts', 'port_key',
           'f_zero_payload', 'f_no_bwd', 'f_syn_no_ack',
           'Fwd Seg Size Min', 'Init Fwd Win Byts', 'Init Bwd Win Byts']
TEMP_PREFIX = ('p_', 'g10', 'g60', 'g300', 'g600', 't_')


def is_temp(c): return any(c.startswith(p) for p in TEMP_PREFIX)


def load_all():
    return pd.concat([pd.read_parquet(f) for f in sorted(glob.glob(os.path.join(CACHE2, "*.parquet")))], ignore_index=True)


def to_X(df, use_temporal, cols=None):
    drop = [c for c in NONFEAT if c in df.columns]
    if not use_temporal:
        drop += [c for c in df.columns if is_temp(c)]
    X = df.drop(columns=drop, errors='ignore')
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
    nt = sum(is_temp(c) for c in full.columns)
    print(f"로드 {len(full):,} · 확장 temporal {nt}피처 ({time.time()-t0:.0f}s)")

    out = []
    for hold in ['Bot', 'DoS', 'DDoS', 'BruteForce', 'Web']:
        if hold not in full['fam'].values: continue
        tr = full[(full['fam'] == 'Benign') | ((full['fam'] != hold) & (full['fam'] != 'Other'))]

        def run(use_t):
            Xtr = to_X(tr, use_t); ytr = (tr['fam'] != 'Benign').astype(int).values
            cols = list(Xtr.columns[Xtr.nunique() > 1]); Xtr = Xtr[cols]
            pos = max(int(ytr.sum()), 1); neg = len(ytr) - pos
            m = XGBClassifier(n_estimators=250, max_depth=8, learning_rate=0.2, tree_method='hist',
                              n_jobs=-1, random_state=42, scale_pos_weight=neg / pos, eval_metric='logloss').fit(Xtr, ytr)
            te_a = full[full['fam'] == hold]; te_b = full[full['fam'] == 'Benign']
            sa = m.predict(to_X(te_a, use_t, cols), output_margin=True)
            sb = m.predict(to_X(te_b, use_t, cols), output_margin=True)
            # worst-day 운영 임계값 (과거 benign 일자별 99.9%의 max)
            qd = []
            for dd, g in tr[tr['fam'] == 'Benign'].groupby('day'):
                qd.append(float(np.quantile(m.predict(to_X(g, use_t, cols), output_margin=True), 1 - 100 / 1e5, method='higher')))
            thr = float(np.max(qd))
            rec = round(float((sa >= thr).mean()), 3); fp = round(float((sb >= thr).mean() * 1e5), 0)
            it = None
            if use_t:
                fi = dict(zip(cols, m.feature_importances_)); it = round(float(sum(v for k, v in fi.items() if is_temp(k))), 3)
            return rec, fp, it

        r0, f0, _ = run(False); r1, f1, it = run(True)
        out.append({'hold': hold, 'F2_rec': r0, 'F2_fp': f0, 'ext_rec': r1, 'ext_fp': f1, 'temp_imp': it, 'delta': round(r1 - r0, 3)})
        print(f"  [{hold}] F2 {r0}@{f0} → +확장temporal {r1}@{f1} (Δ{r1-r0:+.3f}, temp중요도 {it}) ({time.time()-t0:.0f}s)")

    json.dump({'results': [{k: (float(v) if isinstance(v, (int, float, np.floating)) and v is not None else v) for k, v in o.items()} for o in out]},
              open(os.path.join(ROOT, 'output', 'metrics_temporal2.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print("\n" + "=" * 78)
    print(f"{'unseen':<13}{'F2(worst-day)':>16}{'+확장temporal':>18}{'Δ':>8}")
    for o in out:
        a = f"{o['F2_rec']}@{int(o['F2_fp'])}"
        b = f"{o['ext_rec']}@{int(o['ext_fp'])}"
        print(f"{o['hold']:<13}{a:>16}{b:>18}{o['delta']:>+8.3f}")
    print("=" * 78)
    print("확장 temporal이 기존(cache) 대비 Bot 0.41 넘으면 = 장기창/규칙성/실패율 추가효과.")


if __name__ == '__main__':
    main()
