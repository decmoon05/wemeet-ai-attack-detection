# -*- coding: utf-8 -*-
"""확장 temporal 캐시 — 기존(1/10/60초) + 장기창(300/600초) + inter-arrival 규칙성 + 연결실패율.
IP 불필요(Dst Port key만). 결과: sources/raw_ts/cache2/<day>.parquet
GPT 처방 중 IP 안 쓰는 피처만 채택.
"""
import os, sys, time
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
import numpy as np
import pandas as pd

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
RAW = os.path.join(ROOT, "sources", "raw_ts")
CACHE = os.path.join(RAW, "cache2"); os.makedirs(CACHE, exist_ok=True)
FILES = {'BruteForce-14-02-2018.csv': 214, 'DoS-15-02-2018.csv': 215, 'DoS2-16-02-2018.csv': 216,
         'DDoS1-20-02-2018.csv': 220, 'DDoS2-21-02-2018.csv': 221, 'Web1-22-02-2018.csv': 222,
         'Web2-23-02-2018.csv': 223, 'Bot-02-03-2018.csv': 302}
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


def read_big(path):
    atk, ben = [], []
    for ch in pd.read_csv(path, low_memory=False, chunksize=400000):
        ch.columns = [c.strip() for c in ch.columns]
        ch = ch[ch['Label'].astype(str) != 'Label']
        f = ch['Label'].map(fam)
        atk.append(ch[f != 'Benign'])
        b = ch[f == 'Benign']; ben.append(b.sample(min(len(b), 20000), random_state=42))
    return pd.concat(atk + ben, ignore_index=True)


def add_temporal(df):
    d = df.copy()
    d['Timestamp'] = pd.to_datetime(d['Timestamp'], errors='coerce', dayfirst=True)
    d = d.dropna(subset=['Timestamp']).sort_values('Timestamp').reset_index(drop=True)
    d['second'] = d['Timestamp'].dt.floor('s')
    for c in ['Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'SYN Flag Cnt', 'RST Flag Cnt', 'ACK Flag Cnt', 'Flow Duration']:
        if c not in d.columns: d[c] = 0
        d[c] = pd.to_numeric(d[c], errors='coerce').fillna(0)
    d['tot_pkts'] = d['Tot Fwd Pkts'] + d['Tot Bwd Pkts']
    # 포트 카테고리화: ephemeral(49152+) 1.8만개 고유포트 → 집계 무의미·느림. 알려진 포트만 개별, 나머지 묶음.
    KNOWN = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080, 8443}
    dp = pd.to_numeric(d['Dst Port'], errors='coerce').fillna(-1).astype('int64')
    d['port_key'] = np.where(dp.isin(list(KNOWN)), dp,
                             np.where(dp < 1024, -2, np.where(dp < 49152, -3, -4)))  # -2:기타well-known -3:registered -4:ephemeral
    # 이하 집계는 Dst Port 대신 port_key 사용
    d['f_zero_payload'] = (pd.to_numeric(d['TotLen Fwd Pkts'], errors='coerce').fillna(0) == 0).astype(int)
    d['f_no_bwd'] = (d['Tot Bwd Pkts'] == 0).astype(int)
    d['f_syn_no_ack'] = ((d['SYN Flag Cnt'] > 0) & (d['ACK Flag Cnt'] == 0)).astype(int)

    # ── 초 단위 집계 → 창 rolling (현재 초 제외) ──
    port = d.groupby(['port_key', 'second']).agg(
        fc=('Label', 'size'), pk=('tot_pkts', 'sum'),
        syn=('SYN Flag Cnt', 'sum'), rst=('RST Flag Cnt', 'sum'),
        zp=('f_zero_payload', 'sum'), nb=('f_no_bwd', 'sum'), sna=('f_syn_no_ack', 'sum')).reset_index()
    rows = []
    for dp, g in port.groupby('port_key', sort=False):
        g = g.sort_values('second').set_index('second')
        for w in (1, 10, 60, 300, 600):
            r = g[['fc', 'pk', 'syn', 'rst', 'zp', 'nb', 'sna']].rolling(f'{w}s', closed='left', min_periods=1).sum()
            r.columns = [f'p_{c}_{w}' for c in r.columns]; g = g.join(r)
        g = g.reset_index(); g['port_key'] = dp; rows.append(g)
    ph = pd.concat(rows, ignore_index=True)
    gl = d.groupby('second').size().rename('gc').to_frame().sort_index()
    for w in (10, 60, 300, 600):
        gl[f'g{w}'] = gl['gc'].rolling(f'{w}s', closed='left', min_periods=1).sum()
    d = d.merge(ph, on=['port_key', 'second'], how='left').merge(gl[['g10', 'g60', 'g300', 'g600']].reset_index(), on='second', how='left')

    # ── inter-arrival 규칙성: port별 '초 카운트'의 변동(작은 테이블에서 계산, 빠름) ──
    # 원시 flow 대신 port-second 집계의 flow수 시계열 변동계수 → port 트래픽의 규칙/버스트성
    reg = port.sort_values(['port_key', 'second']).copy()
    reg['fc_std'] = reg.groupby('port_key')['fc'].transform(lambda s: s.rolling(10, min_periods=3).std())
    reg['fc_mean'] = reg.groupby('port_key')['fc'].transform(lambda s: s.rolling(10, min_periods=3).mean())
    reg['t_secfc_cv'] = (reg['fc_std'] / (reg['fc_mean'] + 1e-6)).fillna(0)
    d = d.merge(reg[['port_key', 'second', 't_secfc_cv']], on=['port_key', 'second'], how='left')
    d['t_secfc_cv'] = d['t_secfc_cv'].fillna(0)

    # ── 비율/burst/변화율 ──
    d['t_port_share_60'] = d['p_fc_60'] / (d['g60'] + 1)
    d['t_port_share_600'] = d['p_fc_600'] / (d['g600'] + 1)
    d['t_syn_ratio_60'] = d['p_syn_60'] / (d['p_fc_60'] + 1)
    d['t_rst_ratio_60'] = d['p_rst_60'] / (d['p_fc_60'] + 1)
    d['t_fail_ratio_60'] = (d['p_zp_60'] + d['p_nb_60']) / (d['p_fc_60'] + 1)
    d['t_synonack_ratio_60'] = d['p_sna_60'] / (d['p_fc_60'] + 1)
    d['t_burst_1_60'] = (d['p_fc_1'] + 1) / (d['p_fc_60'] / 60 + 1)
    d['t_rate_60_600'] = (d['p_fc_60'] / 60 + 1) / (d['p_fc_600'] / 600 + 1)  # 단기/장기 변화율
    return d


def main():
    t0 = time.time()
    for f, o in FILES.items():
        outp = os.path.join(CACHE, f"{o}.parquet")
        if os.path.exists(outp): print(f"  스킵 {o}"); continue
        path = os.path.join(RAW, f)
        if not os.path.exists(path): print(f"  없음 {f}"); continue
        sz = os.path.getsize(path) / 1e9
        df = read_big(path) if sz > 1.0 else pd.read_csv(path, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        df = df[df['Label'].astype(str) != 'Label']
        df['fam'] = df['Label'].map(fam); df['day'] = o
        df = add_temporal(df)
        parts = [df[df['fam'] == 'Benign'].sample(min(PER_BEN, (df['fam'] == 'Benign').sum()), random_state=42)]
        for fm, g in df[df['fam'] != 'Benign'].groupby('fam'):
            if fm == 'Other': continue
            parts.append(g.sample(min(PER_ATK, len(g)), random_state=42))
        out = pd.concat(parts, ignore_index=True)
        out.to_parquet(outp, index=False)
        print(f"  캐시 {f} → {o} ({len(out):,}) ({time.time()-t0:.0f}s)")
    print("DONE", round(time.time() - t0))


if __name__ == '__main__':
    main()
