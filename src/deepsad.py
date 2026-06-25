# -*- coding: utf-8 -*-
"""② Deep SAD 반지도 표현학습 + latent relative-kNN novelty.

GPT 처방: 정상은 latent center 근처로, 과거 공격(family-balanced)은 margin 밖으로.
novelty = latent relative local-kNN. 검증 = broad-family leave-one-out(LOFO):
한 공격군 통째로 빼고 학습 → 그 군이 unseen일 때 novelty recall@FP. IsolationForest와 비교.

먼저 PoC: 한 family만 LOFO로 빠르게 (DoS, Bot). 되면 전체로 확장.
"""
import glob, os, re, json, time, sys, argparse
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.preprocessing import RobustScaler
from sklearn.neighbors import NearestNeighbors
from sklearn.ensemble import IsolationForest

torch.manual_seed(42); np.random.seed(42)
ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DATA = os.path.join(ROOT, "sources", "cicids2018")
DROP = ['Fwd Seg Size Min', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Protocol']
INFIL = {228, 301}
PER_DAY_BENIGN, PER_FAM_ATK = 25000, 15000


def day_of(p): return os.path.basename(p).split('_')[0]
def order_of(d): q = d.split('-'); return int(q[-2]) * 100 + int(q[-3])


def fam(lbl):
    l = lbl.lower()
    if l == 'benign': return 'Benign'
    if 'ddos' in l: return 'DDoS'
    if 'bot' in l: return 'Bot'
    if 'infil' in l: return 'Infiltration'
    if 'web' in l or 'xss' in l or 'sql' in l: return 'Web'
    if 'ftp' in l or 'ssh' in l or 'brute' in l: return 'BruteForce'
    if 'dos' in l: return 'DoS'
    return 'Other'


def load_pool():
    """전 일자에서 benign(일자별 cap) + 공격(family별 cap) 표본 + family 라벨."""
    parts = []
    for f in glob.glob(os.path.join(DATA, "*.parquet")):
        if order_of(day_of(f)) in INFIL: continue
        df = pd.read_parquet(f); df.columns = [c.strip() for c in df.columns]
        df['fam'] = df['Label'].astype(str).map(fam)
        b = df[df['fam'] == 'Benign']
        b = b.sample(min(PER_DAY_BENIGN, len(b)), random_state=42)
        parts.append(b)
        for fm, g in df[df['fam'] != 'Benign'].groupby('fam'):
            parts.append(g.sample(min(PER_FAM_ATK, len(g)), random_state=42))
    full = pd.concat(parts, ignore_index=True)
    return full


def to_X(df, cols=None):
    X = df.drop(columns=['Label', 'fam'], errors='ignore').drop(columns=[c for c in DROP], errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    if cols is not None: X = X.reindex(columns=cols, fill_value=0)
    return X


class Enc(nn.Module):
    def __init__(self, d, z=16):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(d, 128), nn.LayerNorm(128), nn.GELU(),
                                 nn.Linear(128, 64), nn.LayerNorm(64), nn.GELU(),
                                 nn.Linear(64, z))
    def forward(self, x): return self.net(x)


def train_sad(Xtr, ytr, fams, d, z=16, margin_mult=1.5, attack_w=1.0, epochs=30):
    dev = 'cpu'
    X = torch.tensor(Xtr, dtype=torch.float32)
    y = torch.tensor(ytr, dtype=torch.float32)
    enc = Enc(d, z).to(dev)
    opt = torch.optim.Adam(enc.parameters(), lr=1e-3, weight_decay=1e-5)
    # warm-up으로 center
    enc.train()
    for _ in range(3):
        opt.zero_grad(); zb = enc(X)
        loss = (zb[y == 0]).pow(2).sum(1).mean()
        loss.backward(); opt.step()
    with torch.no_grad():
        center = enc(X)[y == 0].mean(0)
    dist0 = (enc(X)[y == 0] - center).norm(dim=1).detach()
    margin = float(np.quantile(dist0.numpy(), 0.95)) * margin_mult

    # family-balanced 인덱스 풀
    ben_idx = np.where(ytr == 0)[0]
    fam_arr = np.array(fams)
    atk_fams = [f for f in np.unique(fam_arr) if f != 'Benign']
    bs = 512
    for ep in range(epochs):
        # batch: benign 256 (일자무관 랜덤) + 공격 256 (family 균등)
        bi = np.random.choice(ben_idx, 256, replace=len(ben_idx) < 256)
        ai = []
        per = 256 // max(len(atk_fams), 1)
        for fm in atk_fams:
            idx = np.where(fam_arr == fm)[0]
            ai.append(np.random.choice(idx, per, replace=len(idx) < per))
        ai = np.concatenate(ai)
        idx = np.concatenate([bi, ai])
        xb = X[idx]; yb = y[idx]
        enc.train(); opt.zero_grad()
        zb = enc(xb); dd = (zb - center).norm(dim=1)
        ln = dd[yb == 0].pow(2).mean()
        la = F.relu(margin - dd[yb == 1]).pow(2).mean()
        loss = ln + attack_w * la
        loss.backward(); opt.step()
    enc.eval()
    with torch.no_grad():
        Z = enc(X).numpy()
    return enc, center, Z


class RelKNN:
    def __init__(self, k=25): self.k = k
    def fit(self, Zref):
        self.nn = NearestNeighbors(n_neighbors=self.k + 1, n_jobs=-1).fit(Zref)
        dref, _ = self.nn.kneighbors(Zref); self.rad = dref[:, -1]; return self
    def score(self, Z):
        d, i = self.nn.kneighbors(Z, n_neighbors=self.k)
        return d[:, -1] / (np.median(self.rad[i], axis=1) + 1e-8)


def recall_fp(score_atk, score_ben_ref, score_ben_te, atk_mask, fp=100):
    """과거 benign 기준 임계값(median-day 불가 → pooled 분위) → 테스트 recall + 실제 FP."""
    thr = float(np.quantile(score_ben_ref, 1 - fp / 1e5, method='higher'))
    rec = float((score_atk >= thr).mean()) if len(score_atk) else None
    fpr = float((score_ben_te >= thr).mean() * 1e5)
    return (round(rec, 3) if rec is not None else None, round(fpr, 0))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--holdout', nargs='+', default=['DoS', 'Bot'], help='LOFO로 뺄 family들')
    ap.add_argument('--epochs', type=int, default=30)
    a = ap.parse_args()
    t0 = time.time()
    full = load_pool()
    print(f"풀 로드: {len(full):,}행, family {dict(full['fam'].value_counts())} ({time.time()-t0:.0f}s)")
    cols = list(to_X(full).columns)
    cols = [c for c in cols if to_X(full)[c].nunique() > 1]
    scaler = RobustScaler().fit(to_X(full[full['fam'] == 'Benign'], cols)[cols])

    out = []
    for hold in a.holdout:
        # 학습: held-out family 제거 (benign + 나머지 공격)
        tr = full[(full['fam'] == 'Benign') | ((full['fam'] != hold) & (full['fam'] != 'Other'))]
        tr = tr[tr['fam'] != 'Infiltration']
        Xtr = scaler.transform(to_X(tr, cols)[cols]); ytr = (tr['fam'] != 'Benign').astype(int).values
        fams = tr['fam'].values
        # 테스트: held-out family 공격 + benign(held-out 안 본 정상)
        te_atk = full[full['fam'] == hold]
        te_ben = full[full['fam'] == 'Benign'].sample(40000, random_state=7)
        Xatk = scaler.transform(to_X(te_atk, cols)[cols])
        Xben = scaler.transform(to_X(te_ben, cols)[cols])
        # benign ref(임계값용): 학습 benign 일부
        ben_ref = full[full['fam'] == 'Benign'].sample(40000, random_state=9)
        Xref = scaler.transform(to_X(ben_ref, cols)[cols])

        # --- Deep SAD ---
        enc, center, Ztr = train_sad(Xtr, ytr, fams, len(cols), epochs=a.epochs)
        with torch.no_grad():
            Zref = enc(torch.tensor(Xref, dtype=torch.float32)).numpy()
            Zatk = enc(torch.tensor(Xatk, dtype=torch.float32)).numpy()
            Zben = enc(torch.tensor(Xben, dtype=torch.float32)).numpy()
        Zbenign_tr = Ztr[ytr == 0]
        knn = RelKNN(25).fit(Zbenign_tr)
        s_ref = knn.score(Zref); s_atk = knn.score(Zatk); s_ben = knn.score(Zben)
        sad_rec, sad_fp = recall_fp(s_atk, s_ref, s_ben, None, fp=100)

        # --- IsolationForest baseline (같은 입력) ---
        iso = IsolationForest(n_estimators=200, max_samples=4096, random_state=42, n_jobs=-1)
        iso.fit(scaler.transform(to_X(full[full['fam'] == 'Benign'].sample(60000, random_state=3), cols)[cols]))
        i_ref = -iso.score_samples(Xref); i_atk = -iso.score_samples(Xatk); i_ben = -iso.score_samples(Xben)
        iso_rec, iso_fp = recall_fp(i_atk, i_ref, i_ben, None, fp=100)

        out.append({'holdout': hold, 'n_atk': int(len(te_atk)),
                    'DeepSAD_rec@100': sad_rec, 'DeepSAD_fp': sad_fp,
                    'IsoForest_rec@100': iso_rec, 'IsoForest_fp': iso_fp})
        print(f"  [{hold}] DeepSAD rec {sad_rec}@fp{sad_fp} | Iso rec {iso_rec}@fp{iso_fp} ({time.time()-t0:.0f}s)")

    json.dump({'method': 'DeepSAD relative-kNN vs IsolationForest, LOFO', 'results': out},
              open(os.path.join(ROOT, 'output', 'metrics_deepsad.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print("\n" + "=" * 80)
    print(f"{'held-out family':<18}{'공격수':>9}{'DeepSAD@100':>14}{'(fp)':>7}{'IsoForest@100':>15}{'(fp)':>7}")
    for r in out:
        print(f"{r['holdout']:<18}{r['n_atk']:>9}{str(r['DeepSAD_rec@100']):>14}{str(r['DeepSAD_fp']):>7}"
              f"{str(r['IsoForest_rec@100']):>15}{str(r['IsoForest_fp']):>7}")
    print("=" * 80)
    print("판정: DeepSAD가 IsoForest보다 recall 높고 fp가 예산(100) 근처면 = 표현학습 효과 있음.")


if __name__ == '__main__':
    main()
