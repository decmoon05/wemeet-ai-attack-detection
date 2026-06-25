# -*- coding: utf-8 -*-
"""v0.4 보정 + 과거기반 운영 임계값 (XGB/F2).

GPT 가이드 반영:
- forward-only OOF(테스트 이전 일자만)로 sigmoid(Platt) 보정 — 보정데이터는 풀 자연분포.
- 임계값은 0.5가 아니라 과거 OOF의 "최악 날짜 FP/100k 예산"으로 결정(테스트 미사용).
- 위험점수 = round(100 × 보정확률).
- 오라클(테스트 기반) recall과 과거기반(운영) recall을 함께 제시 → 둘의 차이가 'unseen 대가'.
"""
import glob, os, re, json, time
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss
from xgboost import XGBClassifier

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DATA = os.path.join(ROOT, "sources", "cicids2018")
FINGERPRINT = ['Fwd Seg Size Min', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes']
ROBUST_EXTRA = ['Protocol']
INFIL = {228, 301}
FOLDS = {221: '2/21 DDoS', 223: '2/23 Web', 302: '3/2 Bot'}
BUDGETS = [20, 50, 100]
CAP, TREES, EPS = 20000, 300, 1e-6


def day_of(p): return os.path.basename(p).split('_')[0]
def order_of(d): q = d.split('-'); return int(q[-2]) * 100 + int(q[-3])
def safe_logit(p): p = np.clip(p, EPS, 1 - EPS); return np.log(p / (1 - p))


def read_day(path, cap=None, seed=42):
    df = pd.read_parquet(path); df.columns = [c.strip() for c in df.columns]
    if cap:
        df = pd.concat([g.sample(cap, random_state=seed) if len(g) > cap else g
                        for _, g in df.groupby('Label', sort=False)], ignore_index=True)
    return df


def to_Xy(df):
    y = (df['Label'].astype(str).str.strip().str.lower() != 'benign').astype(int).values
    X = df.drop(columns=['Label'])
    X = X.drop(columns=[c for c in FINGERPRINT + ROBUST_EXTRA if c in X.columns], errors='ignore')  # F2
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    return X, y


def xgb(ytr):
    pos = max(int(ytr.sum()), 1); neg = len(ytr) - pos
    return XGBClassifier(n_estimators=TREES, max_depth=8, learning_rate=0.2, tree_method='hist',
                         n_jobs=-1, random_state=42, scale_pos_weight=neg / pos, eval_metric='logloss')


def ece(y, p, bins=10):
    q = np.quantile(p, np.linspace(0, 1, bins + 1))
    q[0], q[-1] = -np.inf, np.inf
    e = 0.0
    for i in range(bins):
        m = (p > q[i]) & (p <= q[i + 1])
        if m.sum():
            e += m.mean() * abs(p[m].mean() - y[m].mean())
    return round(float(e), 4)


def recall_fp_at_thr(y, p, thr):
    atk = p[y == 1]; ben = p[y == 0]
    rec = float((atk >= thr).mean()) if len(atk) else None
    fp = float((ben >= thr).mean() * 1e5) if len(ben) else None
    return (round(rec, 3) if rec is not None else None,
            round(fp, 0) if fp is not None else None)


def main():
    t0 = time.time()
    paths = {order_of(day_of(f)): f for f in glob.glob(os.path.join(DATA, "*.parquet"))}
    clean = sorted(o for o in paths if o not in INFIL)
    out = []

    for d, lbl in FOLDS.items():
        train_days = [o for o in clean if o < d]
        # 컬럼 고정: 전체 학습셋 기준 상수 제거
        full_tr = pd.concat([read_day(paths[o], cap=CAP) for o in train_days], ignore_index=True)
        Xtr_full, ytr_full = to_Xy(full_tr)
        cols = list(Xtr_full.columns[Xtr_full.nunique() > 1])

        # --- forward-only OOF (과거 일자만 학습 → 다음 일자 풀 자연분포 예측) ---
        oof_p, oof_y, oof_day = [], [], []
        for k in range(1, len(train_days)):
            v = train_days[k]
            sub = pd.concat([read_day(paths[o], cap=CAP) for o in train_days[:k]], ignore_index=True)
            Xs, ys = to_Xy(sub)
            if len(np.unique(ys)) < 2:
                continue
            val = read_day(paths[v], cap=None)         # 풀 자연분포
            Xv, yv = to_Xy(val); Xv = Xv.reindex(columns=cols, fill_value=0)
            m = xgb(ys).fit(Xs[cols], ys)
            oof_p.append(m.predict_proba(Xv[cols])[:, 1]); oof_y.append(yv); oof_day.append(np.full(len(yv), v))
        oof_p = np.concatenate(oof_p); oof_y = np.concatenate(oof_y); oof_day = np.concatenate(oof_day)

        # --- sigmoid(Platt) 보정: OOF(자연분포)로 학습 ---
        platt = LogisticRegression(C=1.0, solver='lbfgs', max_iter=1000)
        platt.fit(safe_logit(oof_p).reshape(-1, 1), oof_y)
        oof_cal = platt.predict_proba(safe_logit(oof_p).reshape(-1, 1))[:, 1]

        # --- 과거기반 임계값: 최악 날짜 FP/100k 예산 ---
        thr = {}
        for b in BUDGETS:
            a = b / 1e5
            per_day = []
            for v in np.unique(oof_day):
                ben = oof_cal[(oof_day == v) & (oof_y == 0)]
                if len(ben):
                    per_day.append(np.nextafter(np.quantile(ben, 1 - a, method='higher'), np.inf))
            thr[b] = float(max(per_day)) if per_day else 1.0

        # --- 최종 모델(전체 학습일) → 테스트 풀 자연분포 ---
        mf = xgb(ytr_full).fit(Xtr_full[cols], ytr_full)
        te = read_day(paths[d], cap=None)
        Xte, yte = to_Xy(te); Xte = Xte.reindex(columns=cols, fill_value=0)
        praw = mf.predict_proba(Xte[cols])[:, 1]
        pcal = platt.predict_proba(safe_logit(praw).reshape(-1, 1))[:, 1]
        risk = np.rint(100 * pcal).astype(int)

        rec = {'fold': lbl, 'n_test': int(len(yte)), 'prev': round(float(yte.mean()), 5),
               'AP': round(average_precision_score(yte, pcal), 4),
               'brier_raw': round(brier_score_loss(yte, praw), 4),
               'brier_cal': round(brier_score_loss(yte, pcal), 4),
               'ece_cal': ece(yte, pcal),
               'risk_mean_atk': int(risk[yte == 1].mean()) if (yte == 1).any() else None,
               'risk_mean_ben': int(risk[yte == 0].mean()), 'ops': {}}
        for b in BUDGETS:
            r_past, fp_past = recall_fp_at_thr(yte, pcal, thr[b])              # 과거기반(운영)
            # 오라클: 테스트 benign 분위 임계값
            ben = pcal[yte == 0]; othr = np.quantile(ben, 1 - b / 1e5, method='higher')
            r_or, _ = recall_fp_at_thr(yte, pcal, othr)
            rec['ops'][b] = {'thr_past': round(thr[b], 4), 'recall_past': r_past,
                             'fp_test_actual': fp_past, 'recall_oracle': r_or}
        out.append(rec)
        print(f"  {lbl} done ({time.time()-t0:.0f}s)")

    with open(os.path.join(ROOT, 'output', 'metrics_v04.json'), 'w', encoding='utf-8') as f:
        json.dump({'model': 'XGB/F2', 'cap': CAP, 'budgets': BUDGETS, 'results': out},
                  f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 116)
    for r in out:
        print(f"\n[{r['fold']}]  n={r['n_test']:,}  prev={r['prev']}  AP={r['AP']}  "
              f"Brier raw→cal {r['brier_raw']}→{r['brier_cal']}  ECE={r['ece_cal']}  "
              f"위험점수 평균(공격/정상)={r['risk_mean_atk']}/{r['risk_mean_ben']}")
        print(f"   {'budget':>8}{'thr_past':>10}{'recall_운영':>12}{'fp_실제':>10}{'recall_오라클':>13}")
        for b in BUDGETS:
            o = r['ops'][b]
            print(f"   {b:>8}{o['thr_past']:>10}{str(o['recall_past']):>12}{str(o['fp_test_actual']):>10}{str(o['recall_oracle']):>13}")
    print("=" * 116)


if __name__ == '__main__':
    main()
