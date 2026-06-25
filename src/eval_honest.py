# -*- coding: utf-8 -*-
"""v0.2 정직한 평가 (corrected) — 학습만 cap, 테스트는 풀 자연분포.

GPT 검증 반영: 테스트/평가에 cap 금지(자연 prevalence 유지). prevalence-robust 지표(AP)와
오라클 Recall@고정 FP/100k 병기. 날짜교차는 "테스트 이전 clean 일자로만 학습"(시간순).
Infiltration(2/28·3/1)은 라벨 불확실로 헤드라인 제외. robust 피처셋(F2).
※ 현재는 exploratory round (테스트를 이미 관측 → blind 아님). seed/full-data 재실행만 허용.
"""
import argparse, glob, os, re, json, time
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import average_precision_score, recall_score, confusion_matrix, brier_score_loss

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DATA = os.path.join(ROOT, "sources", "cicids2018")
FINGERPRINT = ['Fwd Seg Size Min', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes']
ROBUST_EXTRA = ['Protocol']
INFIL = {228, 301}
FOLDS = {221: '2/21 DDoS변형전이', 223: '2/23 Web(희소·동일군)', 302: '3/2 Bot(unseen-family)'}


def day_of(p): return os.path.basename(p).split('_')[0]
def order_of(d): q = d.split('-'); return int(q[-2]) * 100 + int(q[-3])


def read_day(path, cap=None, seed=42):
    df = pd.read_parquet(path)
    df.columns = [c.strip() for c in df.columns]
    if cap:   # 학습용: 일자×라벨 cap (희소 클래스는 자동 전체 유지)
        df = pd.concat([g.sample(cap, random_state=seed) if len(g) > cap else g
                        for _, g in df.groupby('Label', sort=False)], ignore_index=True)
    return df


def to_Xy(df, featureset):
    y = (df['Label'].astype(str).str.strip().str.lower() != 'benign').astype(int).values
    X = df.drop(columns=[c for c in ['Label'] if c in df.columns])
    if featureset in ('F1', 'F2'):
        X = X.drop(columns=[c for c in FINGERPRINT if c in X.columns], errors='ignore')
    if featureset == 'F2':
        X = X.drop(columns=[c for c in ROBUST_EXTRA if c in X.columns], errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    return X, y


def model(kind, ytr, trees):
    if kind == 'RF':
        return RandomForestClassifier(n_estimators=trees, class_weight='balanced', n_jobs=-1, random_state=42)
    from xgboost import XGBClassifier
    pos = max(int(ytr.sum()), 1); neg = len(ytr) - pos
    return XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.2, tree_method='hist',
                         n_jobs=-1, random_state=42, scale_pos_weight=neg / pos, eval_metric='logloss')


def orec(y, p, fp):       # 오라클 Recall@고정 FP/100k (테스트 benign 분위 → 진단 상한)
    bs = p[y == 0]
    if len(bs) == 0 or (y == 1).sum() == 0:
        return None
    thr = np.quantile(bs, 1 - fp / 1e5, method='higher')
    return round(float((p[y == 1] >= thr).mean()), 3)


def metrics(name, m, Xte, yte):
    p = m.predict_proba(Xte)[:, 1]; yp = (p >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(yte, yp, labels=[0, 1]).ravel()
    benign = tn + fp
    return {'exp': name, 'n_test': int(len(yte)), 'prev': round(float(yte.mean()), 5),
            'AP': round(average_precision_score(yte, p), 4),
            'recall@.5': round(recall_score(yte, yp, zero_division=0), 4),
            'fp/100k@.5': round(fp / benign * 1e5, 0) if benign else 0,
            'oR@20': orec(yte, p, 20), 'oR@50': orec(yte, p, 50), 'oR@100': orec(yte, p, 100),
            'brier': round(brier_score_loss(yte, p), 4)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cap', type=int, default=20000); ap.add_argument('--trees', type=int, default=120)
    ap.add_argument('--featureset', default='F2')
    a = ap.parse_args()
    t0 = time.time()

    paths = {order_of(day_of(f)): f for f in glob.glob(os.path.join(DATA, "*.parquet"))}
    clean = sorted(o for o in paths if o not in INFIL)
    results = []

    for kind in ['RF', 'XGB']:
        # 무작위(샘플 상한): clean 일자 cap 표본
        pool = pd.concat([read_day(paths[o], cap=a.cap) for o in clean], ignore_index=True)
        X, y = to_Xy(pool, a.featureset)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42)
        keep = Xtr.columns[Xtr.nunique() > 1]
        results.append(metrics(f'{kind}|random*(sampled)', model(kind, ytr, a.trees).fit(Xtr[keep], ytr), Xte[keep], yte))
        print(f"  {kind}|random ({time.time()-t0:.0f}s)")
        # 날짜교차: 학습=과거 clean(cap), 테스트=해당일 풀 자연분포
        for d, lbl in FOLDS.items():
            tr = pd.concat([read_day(paths[o], cap=a.cap) for o in clean if o < d], ignore_index=True)
            te = read_day(paths[d], cap=None)
            Xtr, ytr = to_Xy(tr, a.featureset)
            Xte, yte = to_Xy(te, a.featureset)
            keep = Xtr.columns[Xtr.nunique() > 1]
            Xte = Xte.reindex(columns=keep, fill_value=0)
            results.append(metrics(f'{kind}|{lbl}', model(kind, ytr, a.trees).fit(Xtr[keep], ytr), Xte, yte))
            print(f"  {kind}|{lbl} ({time.time()-t0:.0f}s)")

    with open(os.path.join(ROOT, 'output', 'metrics_v02.json'), 'w', encoding='utf-8') as f:
        json.dump({'cap': a.cap, 'trees': a.trees, 'featureset': a.featureset,
                   'note': 'train-only cap; test=full natural; oR=oracle recall@FP/100k', 'results': results},
                  f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 120)
    print(f"{'exp':<26}{'n_test':>9}{'prev':>8}{'AP':>7}{'rec@.5':>8}{'fp/100k':>9}{'oR@20':>7}{'oR@50':>7}{'oR@100':>7}{'brier':>7}")
    for r in results:
        print(f"{r['exp']:<26}{r['n_test']:>9}{r['prev']:>8}{r['AP']:>7}{r['recall@.5']:>8}"
              f"{r['fp/100k@.5']:>9}{str(r['oR@20']):>7}{str(r['oR@50']):>7}{str(r['oR@100']):>7}{r['brier']:>7}")
    print("=" * 120)


if __name__ == '__main__':
    main()
