# -*- coding: utf-8 -*-
"""최우선 카드 — temporal causal aggregate 피처로 unseen 전이 개선 시도.

원본 CSV(Timestamp 有)에서 Dst Port별 causal 1/10/60초 집계 피처 생성(현재·미래 제외).
F2(=원래 robust) vs F2+temporal 을 leave-one-family-out으로 비교.
IP 없음 → burst형(DDoS/DoS/BruteForce) 기대, Bot 제한적(GPT 예측).
※ raw Timestamp·절대시각은 모델 미투입(누수 방지).
"""
import glob, os, re, json, time, sys
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
RAW = os.path.join(ROOT, "sources", "raw_ts")
DROP_LEAK = ['Flow ID', 'Src IP', 'Source IP', 'Src Port', 'Dst IP', 'Destination IP', 'Timestamp',
             'Fwd Seg Size Min', 'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Protocol', 'Dst Port',
             'second', 'fam', 'day']
PER_DAY_BEN, PER_FAM = 20000, 12000
# (파일, day순서)
FILES = {'BruteForce-14-02-2018.csv': 214, 'DoS-15-02-2018.csv': 215, 'DoS2-16-02-2018.csv': 216,
         'DDoS1-20-02-2018.csv': 220, 'DDoS2-21-02-2018.csv': 221, 'Web1-22-02-2018.csv': 222,
         'Web2-23-02-2018.csv': 223, 'Bot-02-03-2018.csv': 302}
DDOS_BIG = 'DDoS1-20-02-2018.csv'


def fam(l):
    l = str(l).lower()
    if l == 'benign': return 'Benign'
    if 'ddos' in l: return 'DDoS'
    if 'bot' in l: return 'Bot'
    if 'web' in l or 'xss' in l or 'sql' in l: return 'Web'
    if 'ftp' in l or 'ssh' in l or 'brute' in l: return 'BruteForce'
    if 'dos' in l: return 'DoS'
    return 'Other'


def add_temporal(df):
    """Dst Port별 causal 1/10/60초 집계 (현재 초 제외)."""
    d = df.copy()
    d['Timestamp'] = pd.to_datetime(d['Timestamp'], errors='coerce', dayfirst=True)
    d = d.dropna(subset=['Timestamp']).sort_values('Timestamp')
    d['second'] = d['Timestamp'].dt.floor('s')
    for c in ['Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'SYN Flag Cnt', 'RST Flag Cnt', 'Flow Duration']:
        if c not in d.columns: d[c] = 0
    d['tot_pkts'] = pd.to_numeric(d['Tot Fwd Pkts'], errors='coerce').fillna(0) + pd.to_numeric(d['Tot Bwd Pkts'], errors='coerce').fillna(0)
    port = d.groupby(['Dst Port', 'second']).agg(
        fc=('Label', 'size'), pk=('tot_pkts', 'sum'),
        syn=('SYN Flag Cnt', 'sum'), rst=('RST Flag Cnt', 'sum')).reset_index()
    glob_ = d.groupby('second').size().rename('gc').to_frame().sort_index()
    for w in (1, 10, 60):
        glob_[f'g{w}'] = glob_['gc'].rolling(f'{w}s', closed='left', min_periods=1).sum()
    def win(g):
        dp = g['Dst Port'].iloc[0]
        g = g.sort_values('second').set_index('second')
        for w in (1, 10, 60):
            r = g[['fc', 'pk', 'syn', 'rst']].rolling(f'{w}s', closed='left', min_periods=1).sum()
            r.columns = [f'p_{c}_{w}' for c in r.columns]
            g = g.join(r)
        g = g.reset_index()
        g['Dst Port'] = dp                       # 그룹 키 보존
        return g
    ph = pd.concat([win(g) for _, g in port.groupby('Dst Port', sort=False)], ignore_index=True)
    d = d.merge(ph, on=['Dst Port', 'second'], how='left')
    d = d.merge(glob_[['g1', 'g10', 'g60']].reset_index(), on='second', how='left')
    # 비율/burst (포트 부하 정규화)
    d['t_port_share_10'] = d['p_fc_10'] / (d['g10'] + 1)
    d['t_port_share_60'] = d['p_fc_60'] / (d['g60'] + 1)
    d['t_syn_ratio_10'] = d['p_syn_10'] / (d['p_fc_10'] + 1)
    d['t_rst_ratio_10'] = d['p_rst_10'] / (d['p_fc_10'] + 1)
    d['t_burst'] = (d['p_fc_1'] + 1) / (d['p_fc_60'] / 60 + 1)
    return d


def load(path, day, cap_ben=PER_DAY_BEN, cap_fam=PER_FAM):
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    df = df[df['Label'].astype(str) != 'Label']
    df['fam'] = df['Label'].map(fam); df['day'] = day
    df = add_temporal(df)
    # 샘플(자연분포 평가 위해 테스트는 호출부에서 별도; 여기선 학습풀 cap)
    parts = []
    b = df[df['fam'] == 'Benign']
    parts.append(b.sample(min(cap_ben, len(b)), random_state=42))
    for fm, g in df[df['fam'] != 'Benign'].groupby('fam'):
        if fm == 'Other': continue
        parts.append(g.sample(min(cap_fam, len(g)), random_state=42))
    return pd.concat(parts, ignore_index=True)


TEMPORAL_COLS = ['p_fc_1', 'p_fc_10', 'p_fc_60', 'p_pk_10', 'p_syn_10', 'p_rst_10',
                 't_port_share_10', 't_port_share_60', 't_syn_ratio_10', 't_rst_ratio_10', 't_burst']


def to_X(df, use_temporal, cols=None):
    X = df.drop(columns=[c for c in DROP_LEAK if c in df.columns] + ['Label'], errors='ignore')
    if not use_temporal:
        X = X.drop(columns=[c for c in X.columns if c in TEMPORAL_COLS or c.startswith('p_') or c.startswith('g') and c[1:].isdigit()], errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    if cols is not None: X = X.reindex(columns=cols, fill_value=0)
    return X


def main():
    t0 = time.time()
    print("일자별 원본 로딩+temporal 생성...")
    days = {}
    for f, o in FILES.items():
        p = os.path.join(RAW, f)
        if not os.path.exists(p): print(f"  (없음 {f})"); continue
        cb = 12000 if f == DDOS_BIG else PER_DAY_BEN   # 3.9GB는 가볍게
        days[o] = load(p, o, cap_ben=cb)
        print(f"  {f}: {len(days[o]):,} fam={dict(days[o]['fam'].value_counts())} ({time.time()-t0:.0f}s)")

    full = pd.concat(days.values(), ignore_index=True)
    fams = [x for x in full['fam'].unique() if x != 'Benign']
    out = []
    # cold-start(BruteForce, 첫 공격일) 제외하고 LOFO. 단 표기는 함.
    for hold in ['DoS', 'DDoS', 'Web', 'Bot', 'BruteForce']:
        if hold not in fams: continue
        tr = full[(full['fam'] == 'Benign') | ((full['fam'] != hold) & (full['fam'] != 'Other'))]
        cold = (hold == 'BruteForce')   # 학습에 다른 공격은 있음(우리 풀은 전 일자) → 진짜 cold는 시간순일 때. 여기선 표기만.

        def run(use_t):
            Xtr = to_X(tr, use_t); ytr = (tr['fam'] != 'Benign').astype(int).values
            cols = list(Xtr.columns[Xtr.nunique() > 1]); Xtr = Xtr[cols]
            pos = max(int(ytr.sum()), 1); neg = len(ytr) - pos
            m = XGBClassifier(n_estimators=250, max_depth=8, learning_rate=0.2, tree_method='hist',
                              n_jobs=-1, random_state=42, scale_pos_weight=neg / pos, eval_metric='logloss').fit(Xtr, ytr)
            # median-day 임계값(과거 benign 일자별)
            mbd = {}
            for dd, g in tr[tr['fam'] == 'Benign'].groupby('day'):
                mbd[dd] = m.predict(to_X(g, use_t, cols), output_margin=True)
            thr = float(np.median([np.quantile(v, 1 - 100 / 1e5, method='higher') for v in mbd.values()]))
            te_a = full[full['fam'] == hold]; te_b = full[full['fam'] == 'Benign']
            sa = m.predict(to_X(te_a, use_t, cols), output_margin=True)
            sb = m.predict(to_X(te_b, use_t, cols), output_margin=True)
            return round(float((sa >= thr).mean()), 3), round(float((sb >= thr).mean() * 1e5), 0)

        r0, f0 = run(False); r1, f1 = run(True)
        out.append({'holdout': hold, 'cold_start': cold, 'F2_rec': r0, 'F2_fp': f0,
                    'F2temporal_rec': r1, 'F2temporal_fp': f1, 'delta': round(r1 - r0, 3)})
        tag = ' [cold-start]' if cold else ''
        print(f"  [{hold}]{tag} F2 {r0}@{f0} → +temporal {r1}@{f1}  Δ{r1-r0:+.3f} ({time.time()-t0:.0f}s)")

    json.dump({'results': out}, open(os.path.join(ROOT, 'output', 'metrics_temporal.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print("\n" + "=" * 88)
    print(f"{'held-out(unseen)':<18}{'F2':>10}{'(fp)':>7}{'F2+temporal':>14}{'(fp)':>7}{'Δrecall':>9}")
    for r in out:
        print(f"{r['holdout']+(' [cold]' if r['cold_start'] else ''):<18}{str(r['F2_rec']):>10}{str(r['F2_fp']):>7}"
              f"{str(r['F2temporal_rec']):>14}{str(r['F2temporal_fp']):>7}{r['delta']:>+9.3f}")
    print("=" * 88)
    print("Δ>0 + fp 예산(100) 근처 = temporal이 전이 개선. BruteForce는 cold-start라 해석 주의.")


if __name__ == '__main__':
    main()
