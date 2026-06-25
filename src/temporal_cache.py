# -*- coding: utf-8 -*-
"""일자별 temporal feature 생성 → parquet 캐시 (메모리/속도 분리).
거대파일(DDoS1 3.9GB)은 청크로 읽어 benign/공격 샘플만. 결과: sources/raw_ts/cache/<day>.parquet
"""
import os, sys, time
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
import numpy as np
import pandas as pd

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
RAW = os.path.join(ROOT, "sources", "raw_ts")
CACHE = os.path.join(RAW, "cache"); os.makedirs(CACHE, exist_ok=True)
FILES = {'BruteForce-14-02-2018.csv': 214, 'DoS-15-02-2018.csv': 215, 'DoS2-16-02-2018.csv': 216,
         'DDoS1-20-02-2018.csv': 220, 'DDoS2-21-02-2018.csv': 221, 'Web1-22-02-2018.csv': 222,
         'Web2-23-02-2018.csv': 223, 'Bot-02-03-2018.csv': 302}
KEEP_RAW = ['Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'SYN Flag Cnt', 'RST Flag Cnt']  # temporal 입력
PER_BEN, PER_ATK = 20000, 12000


def fam(l):
    l = str(l).lower()
    if l == 'benign': return 'Benign'
    if 'ddos' in l: return 'DDoS'
    if 'bot' in l: return 'Bot'
    if 'web' in l or 'xss' in l or 'sql' in l: return 'Web'
    if 'ftp' in l or 'ssh' in l or 'brute' in l: return 'BruteForce'
    if 'dos' in l: return 'DoS'
    return 'Other'


def read_big(path, sample_benign=120000):
    """청크로 읽어 공격 전부 + benign 샘플 (메모리 절약)."""
    atk, ben = [], []
    for ch in pd.read_csv(path, low_memory=False, chunksize=400000):
        ch.columns = [c.strip() for c in ch.columns]
        ch = ch[ch['Label'].astype(str) != 'Label']
        f = ch['Label'].map(fam)
        atk.append(ch[f != 'Benign'])
        b = ch[f == 'Benign']
        ben.append(b.sample(min(len(b), 20000), random_state=42))
    df = pd.concat(atk + ben, ignore_index=True)
    return df


def add_temporal(df):
    d = df.copy()
    d['Timestamp'] = pd.to_datetime(d['Timestamp'], errors='coerce', dayfirst=True)
    d = d.dropna(subset=['Timestamp']).sort_values('Timestamp').reset_index(drop=True)
    d['second'] = d['Timestamp'].dt.floor('s')
    for c in KEEP_RAW:
        if c not in d.columns: d[c] = 0
        d[c] = pd.to_numeric(d[c], errors='coerce').fillna(0)
    d['tot_pkts'] = d['Tot Fwd Pkts'] + d['Tot Bwd Pkts']
    port = d.groupby(['Dst Port', 'second']).agg(
        fc=('Label', 'size'), pk=('tot_pkts', 'sum'),
        syn=('SYN Flag Cnt', 'sum'), rst=('RST Flag Cnt', 'sum')).reset_index()
    rows = []
    for dp, g in port.groupby('Dst Port', sort=False):
        g = g.sort_values('second').set_index('second')
        for w in (1, 10, 60):
            r = g[['fc', 'pk', 'syn', 'rst']].rolling(f'{w}s', closed='left', min_periods=1).sum()
            r.columns = [f'p_{c}_{w}' for c in r.columns]; g = g.join(r)
        g = g.reset_index(); g['Dst Port'] = dp; rows.append(g)
    ph = pd.concat(rows, ignore_index=True)
    gl = d.groupby('second').size().rename('gc').to_frame().sort_index()
    for w in (1, 10, 60):
        gl[f'g{w}'] = gl['gc'].rolling(f'{w}s', closed='left', min_periods=1).sum()
    d = d.merge(ph, on=['Dst Port', 'second'], how='left').merge(gl[['g1', 'g10', 'g60']].reset_index(), on='second', how='left')
    d['t_port_share_10'] = d['p_fc_10'] / (d['g10'] + 1)
    d['t_port_share_60'] = d['p_fc_60'] / (d['g60'] + 1)
    d['t_syn_ratio_10'] = d['p_syn_10'] / (d['p_fc_10'] + 1)
    d['t_rst_ratio_10'] = d['p_rst_10'] / (d['p_fc_10'] + 1)
    d['t_burst'] = (d['p_fc_1'] + 1) / (d['p_fc_60'] / 60 + 1)
    return d


def main():
    t0 = time.time()
    for f, o in FILES.items():
        outp = os.path.join(CACHE, f"{o}.parquet")
        if os.path.exists(outp):
            print(f"  스킵(이미있음) {o}"); continue
        path = os.path.join(RAW, f)
        if not os.path.exists(path): print(f"  없음 {f}"); continue
        sz = os.path.getsize(path) / 1e9
        df = read_big(path) if sz > 1.0 else pd.read_csv(path, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        df = df[df['Label'].astype(str) != 'Label']
        df['fam'] = df['Label'].map(fam); df['day'] = o
        df = add_temporal(df)
        # 샘플(학습풀용 cap)
        parts = [df[df['fam'] == 'Benign'].sample(min(PER_BEN, (df['fam'] == 'Benign').sum()), random_state=42)]
        for fm, g in df[df['fam'] != 'Benign'].groupby('fam'):
            if fm == 'Other': continue
            parts.append(g.sample(min(PER_ATK, len(g)), random_state=42))
        out = pd.concat(parts, ignore_index=True)
        # 불필요 원본 컬럼 정리(temporal+F2만 남김; Label/fam/day 유지)
        out.to_parquet(outp, index=False)
        print(f"  캐시 {f} → {o}.parquet ({len(out):,}, {sz:.1f}GB src) ({time.time()-t0:.0f}s)")
    print("DONE", time.time() - t0)


if __name__ == '__main__':
    main()
