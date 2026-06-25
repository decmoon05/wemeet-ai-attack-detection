# -*- coding: utf-8 -*-
"""종료 검증 — '표현 한계' 결론을 굳히기 위한 GPT 처방 4종.

(1) target-day function oracle: 테스트일 라벨로 그날 내부 grouped-OOF(XGB+ExtraTrees) →
    F2에 '그날 공격 구분 정보'가 원리적으로 있나(진단상한, 운영 아님).
(2) raw relative-kNN: Deep SAD latent 대신 raw F2(log1p+robust)에서 kNN → encoder가 정보 파괴했나.
(3) Deep SAD positive-control은 deepsad.py 결과로 갈음(seen은 잘 밀어냈는지 별도).
대상: Bot·Web(2/22)·DoS-GE(2/15) = 표현 문제 의심 fold.
"""
import glob, os, re, json, time, sys
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.preprocessing import RobustScaler
from sklearn.neighbors import NearestNeighbors
from xgboost import XGBClassifier

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DATA = os.path.join(ROOT, "sources", "cicids2018")
DROP = ['Fwd Seg Size Min', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Protocol']
TARGETS = {302: 'Bot(3/2)', 222: 'Web(2/22)', 215: 'DoS-GE(2/15)', 221: 'DDoS-HOIC(2/21)'}  # HOIC=positive control


def day_of(p): return os.path.basename(p).split('_')[0]
def order_of(d): q = d.split('-'); return int(q[-2]) * 100 + int(q[-3])


def to_Xy(df):
    y = (df['Label'].astype(str).str.strip().str.lower() != 'benign').astype(int).values
    X = df.drop(columns=['Label']).drop(columns=[c for c in DROP], errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    return X, y


def oof_oracle(X, y, est, fp=100, n_splits=5):
    groups = pd.util.hash_pandas_object(X, index=False).to_numpy()  # 동일 행 분리 방지
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=42)
    oof = np.full(len(X), np.nan)
    for tr, te in cv.split(X, y, groups):
        m = clone(est)
        nneg = (y[tr] == 0).sum(); npos = max((y[tr] == 1).sum(), 1)
        sw = np.where(y[tr] == 1, nneg / npos, 1.0)
        try:
            m.fit(X.iloc[tr], y[tr], sample_weight=sw)
        except TypeError:
            m.fit(X.iloc[tr], y[tr])
        oof[te] = m.predict_proba(X.iloc[te])[:, 1]
    thr = np.quantile(oof[y == 0], 1 - fp / 1e5, method='higher')
    return round(float((oof[y == 1] >= thr).mean()), 3), round(float((oof[y == 0] >= thr).mean() * 1e5), 0)


def raw_knn_lofo(target_order, k=25, fp=100):
    """held-out family를 뺀 benign으로 kNN ref → 그 family를 raw F2(log1p+robust) kNN으로 탐지."""
    paths = {order_of(day_of(f)): f for f in glob.glob(os.path.join(DATA, "*.parquet"))}
    # 학습 benign = target 이전 일자 benign
    train_days = [o for o in sorted(paths) if o < target_order and o not in (228, 301)]
    bens = []
    for o in train_days:
        df = pd.read_parquet(paths[o]); df.columns = [c.strip() for c in df.columns]
        b = df[df['Label'].astype(str).str.strip().str.lower() == 'benign']
        bens.append(b.sample(min(20000, len(b)), random_state=42))
    bdf = pd.concat(bens, ignore_index=True)
    Xb, _ = to_Xy(bdf)
    cols = list(Xb.columns[Xb.nunique() > 1])
    def prep(df):
        X, y = to_Xy(df); X = X.reindex(columns=cols, fill_value=0)
        return np.log1p(np.clip(X[cols].values, 0, None)), y
    sc = RobustScaler().fit(prep(bdf)[0])
    Zref = sc.transform(prep(bdf)[0])
    nn = NearestNeighbors(n_neighbors=k + 1, n_jobs=-1).fit(Zref)
    dref, _ = nn.kneighbors(Zref); rad = dref[:, -1]
    def score(Z):
        d, i = nn.kneighbors(Z, n_neighbors=k); return d[:, -1] / (np.median(rad[i], axis=1) + 1e-8)
    s_ref = score(Zref)
    te = pd.read_parquet(paths[target_order]); te.columns = [c.strip() for c in te.columns]
    Zt, yt = prep(te); Zt = sc.transform(Zt)
    s = score(Zt)
    thr = float(np.quantile(s_ref, 1 - fp / 1e5, method='higher'))
    atk = s[yt == 1]; ben = s[yt == 0]
    return round(float((atk >= thr).mean()), 3), round(float((ben >= thr).mean() * 1e5), 0)


def main():
    t0 = time.time()
    paths = {order_of(day_of(f)): f for f in glob.glob(os.path.join(DATA, "*.parquet"))}
    xgb = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.2, tree_method='hist',
                        n_jobs=-1, random_state=42, eval_metric='logloss')
    et = ExtraTreesClassifier(n_estimators=200, n_jobs=-1, random_state=42)

    print("=== (1) target-day function oracle: F2에 '그날' 공격 구분 정보가 있나 (진단상한) ===")
    print(f"{'fold':<16}{'XGB_OOF':>10}{'(fp)':>7}{'ExtraT_OOF':>12}{'(fp)':>7}")
    res = {'function_oracle': {}, 'raw_knn_lofo': {}}
    for o, lbl in TARGETS.items():
        df = pd.read_parquet(paths[o]); df.columns = [c.strip() for c in df.columns]
        # 너무 크면 샘플(자연분포 유지: benign/attack 비율 보존 위해 층화 샘플)
        if len(df) > 250000:
            df = df.groupby((df['Label'].astype(str).str.lower() != 'benign')).apply(
                lambda g: g.sample(min(len(g), int(250000 * len(g) / len(df)) + 1), random_state=42)).reset_index(drop=True)
        X, y = to_Xy(df); cols = list(X.columns[X.nunique() > 1]); X = X[cols]
        rx, fx = oof_oracle(X, y, xgb)
        re_, fe = oof_oracle(X, y, et)
        res['function_oracle'][lbl] = {'xgb_recall': rx, 'xgb_fp': fx, 'et_recall': re_, 'et_fp': fe}
        print(f"{lbl:<16}{rx:>10}{fx:>7}{re_:>12}{fe:>7}  ({time.time()-t0:.0f}s)")

    print("\n=== (2) raw F2 relative-kNN (LOFO, Deep SAD latent 아닌 raw) ===")
    print(f"{'fold':<16}{'rawKNN_rec':>12}{'(fp)':>7}")
    for o, lbl in TARGETS.items():
        if lbl.startswith('DDoS-HOIC'): continue
        rk, fk = raw_knn_lofo(o)
        res['raw_knn_lofo'][lbl] = {'recall': rk, 'fp': fk}
        print(f"{lbl:<16}{rk:>12}{fk:>7}  ({time.time()-t0:.0f}s)")

    json.dump(res, open(os.path.join(ROOT, 'output', 'metrics_verify_limit.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print("\n해석:")
    print(" - function_oracle 높음 → F2에 '그날' 정보 있음 = 전이(날짜간) 문제. 낮음 → F2 자체 표현 한계.")
    print(" - raw_knn이 Deep SAD보다 높음 → encoder가 정보 파괴. 둘 다 0 → 표현 한계 증거 강화.")


if __name__ == '__main__':
    main()
