# -*- coding: utf-8 -*-
"""Top1 진단 — '임계값 전이 문제' vs '표현 문제' 분리 + benign 점수 시프트 감사.

각 공격일 fold:
- oracle recall@FP (테스트 benign으로 임계값) = 표현 상한
- past recall@FP (과거 benign으로 임계값) = 실제 운영
- gap = oracle - past  → 크면 '임계값 전이 문제'(고칠 수 있음), oracle도 0이면 '표현 문제'(Deep SAD 필요)
- benign 점수 분위: 과거 vs 테스트일 → Hulk FP폭발이 domain shift인지
- 임계값 정책 비교: all-past / last-1 / last-2 (어느 게 운영 recall 최대인지)
출력: output/metrics_diagnose.json
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
CAP, TREES = 60000, 300
FOLDS = {215: 'DoS-GE/Slow(2/15)', 216: 'DoS-Hulk(2/16)', 220: 'DDoS-LOIC(2/20)',
         221: 'DDoS-HOIC(2/21)', 222: 'Web(2/22)', 223: 'Web(2/23)', 302: 'Bot(3/2)'}
INFIL = {228, 301}
BUDGET = 100  # FP/100k


def day_of(p): return os.path.basename(p).split('_')[0]
def order_of(d): q = d.split('-'); return int(q[-2]) * 100 + int(q[-3])


def read_day(path, cap=None, seed=42):
    df = pd.read_parquet(path); df.columns = [c.strip() for c in df.columns]
    if cap:
        df = pd.concat([g.sample(cap, random_state=seed) if len(g) > cap else g
                        for _, g in df.groupby('Label', sort=False)], ignore_index=True)
    return df


def to_Xy(df):
    y = (df['Label'].astype(str).str.strip().str.lower() != 'benign').astype(int).values
    X = df.drop(columns=['Label']).drop(columns=[c for c in DROP], errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    return X, y


def xgb(ytr):
    pos = max(int(ytr.sum()), 1); neg = len(ytr) - pos
    return XGBClassifier(n_estimators=TREES, max_depth=8, learning_rate=0.2, tree_method='hist',
                         n_jobs=-1, random_state=42, scale_pos_weight=neg / pos, eval_metric='logloss')


def recall_at_thr(atk, thr): return float((atk >= thr).mean()) if len(atk) else None
def thr_at_fp(benign, fp): return float(np.quantile(benign, 1 - fp / 1e5, method='higher'))


def main():
    t0 = time.time()
    paths = {order_of(day_of(f)): f for f in glob.glob(os.path.join(DATA, "*.parquet"))}
    clean = sorted(o for o in paths if o not in INFIL)
    out = []
    # 모델은 margin(raw)로 평가 — 임계값 더 안정
    for d, lbl in FOLDS.items():
        train_days = [o for o in clean if o < d]
        if not train_days: continue
        tr = pd.concat([read_day(paths[o], cap=CAP) for o in train_days], ignore_index=True)
        Xtr, ytr = to_Xy(tr); cols = list(Xtr.columns[Xtr.nunique() > 1])
        m = xgb(ytr).fit(Xtr[cols], ytr)

        def margin(df):
            X, y = to_Xy(df); X = X.reindex(columns=cols, fill_value=0)
            return m.predict(X[cols], output_margin=True), y

        # 테스트
        te = read_day(paths[d]); s_te, y_te = margin(te)
        atk = s_te[y_te == 1]; ben_te = s_te[y_te == 0]
        # 과거 benign 점수 (정책별)
        def past_benign(days):
            dfs = [read_day(paths[o]) for o in days]
            b = pd.concat([x[x['Label'].astype(str).str.strip().str.lower() == 'benign'] for x in dfs], ignore_index=True)
            if len(b) > 200000: b = b.sample(200000, random_state=1)
            sb, _ = margin(b); return sb

        ben_all = past_benign(train_days)
        ben_l1 = past_benign(train_days[-1:])
        ben_l2 = past_benign(train_days[-2:]) if len(train_days) >= 2 else ben_l1

        # oracle vs 정책별 운영 recall (실제 FP도)
        thr_or = thr_at_fp(ben_te, BUDGET)
        rec_or = recall_at_thr(atk, thr_or)
        def policy(ben_ref):
            thr = thr_at_fp(ben_ref, BUDGET)
            return recall_at_thr(atk, thr), round(float((ben_te >= thr).mean() * 1e5), 0)
        r_all, fp_all = policy(ben_all)
        r_l1, fp_l1 = policy(ben_l1)
        r_l2, fp_l2 = policy(ben_l2)

        # benign 시프트: 과거 99.9% vs 테스트 benign median
        q999_past = float(np.quantile(ben_all, 0.999))
        med_te = float(np.median(ben_te))
        shift = med_te > q999_past  # 테스트 정상 중앙값이 과거 정상 99.9%보다 높다=심각 시프트

        diag = ('표현 문제(oracle도 낮음→Deep SAD 필요)' if (rec_or or 0) < 0.1
                else ('임계값 전이 문제(oracle 높은데 운영 낮음→정책으로 회복 가능)'
                      if (rec_or or 0) - max(r_all or 0, r_l1 or 0, r_l2 or 0) > 0.15
                      else 'benign 시프트/오탐' if shift else '대체로 OK'))
        out.append({'fold': lbl, 'oracle_rec': round(rec_or, 3) if rec_or is not None else None,
                    'rec_allpast': round(r_all, 3) if r_all is not None else None, 'fp_allpast': fp_all,
                    'rec_last1': round(r_l1, 3) if r_l1 is not None else None, 'fp_last1': fp_l1,
                    'rec_last2': round(r_l2, 3) if r_l2 is not None else None, 'fp_last2': fp_l2,
                    'benign_shift': bool(shift), 'diagnosis': diag})
        print(f"  {lbl} ({time.time()-t0:.0f}s)")

    json.dump({'budget_fp_per_100k': BUDGET, 'results': out},
              open(os.path.join(ROOT, 'output', 'metrics_diagnose.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print("\n" + "=" * 120)
    print(f"{'fold':<18}{'oracle':>8}{'all-past':>10}{'(fp)':>7}{'last-1':>9}{'(fp)':>8}{'last-2':>9}{'(fp)':>8}{'shift':>7}  진단")
    for r in out:
        print(f"{r['fold']:<18}{str(r['oracle_rec']):>8}{str(r['rec_allpast']):>10}{str(r['fp_allpast']):>7}"
              f"{str(r['rec_last1']):>9}{str(r['fp_last1']):>8}{str(r['rec_last2']):>9}{str(r['fp_last2']):>8}"
              f"{str(r['benign_shift']):>7}  {r['diagnosis']}")
    print("=" * 120)


if __name__ == '__main__':
    main()
