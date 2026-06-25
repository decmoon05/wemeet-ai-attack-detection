# -*- coding: utf-8 -*-
"""CSE-CIC-IDS2018 v0.1 베이스라인 — 정상/공격 이진 분류 (RandomForest + XGBoost).

사용법:
  python src/train_baseline.py --csv sources/Wednesday-14-02-2018.csv
  python src/train_baseline.py --csv sources/Wednesday-14-02-2018.csv --sample 200000
"""
import argparse, json, os, re, time
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (classification_report, confusion_matrix,
                             precision_score, recall_score, f1_score)

# 식별자/시간 컬럼은 학습에서 제외(누수·무의미). Dst Port·Protocol 등은 피처로 유지.
DROP_COLS = ['Flow ID', 'Src IP', 'Source IP', 'Src Port', 'Source Port',
             'Dst IP', 'Destination IP', 'Timestamp']


def load_clean(csv_path, sample=None, seed=42):
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    label_col = 'Label' if 'Label' in df.columns else df.columns[-1]

    # 중간에 섞인 중복 헤더 행 제거 (Label 칸에 'Label' 문자열이 들어간 행)
    df = df[df[label_col].astype(str) != label_col]

    # 이진 라벨: Benign=0, 그 외=1(공격)
    y = (df[label_col].astype(str).str.strip().str.lower() != 'benign').astype(int).values

    drop = [c for c in DROP_COLS if c in df.columns]
    feats = df.drop(columns=drop + [label_col])

    # 숫자 변환 → Inf를 NaN으로 → 전부 NaN인 컬럼 제거 → 나머지 NaN은 0
    X = feats.apply(pd.to_numeric, errors='coerce')
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.dropna(axis=1, how='all')
    X = X.fillna(0)

    # XGBoost가 싫어하는 특수문자 컬럼명 정리
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]

    if sample and sample < len(X):
        idx = np.random.RandomState(seed).choice(len(X), size=sample, replace=False)
        X, y = X.iloc[idx].reset_index(drop=True), y[idx]
    return X, y, label_col


def evaluate(name, model, Xte, yte):
    yp = model.predict(Xte)
    rep = classification_report(yte, yp, target_names=['Benign(정상)', 'Attack(공격)'], digits=4)
    cm = confusion_matrix(yte, yp)
    print(f"\n===== {name} =====")
    print(rep)
    print("혼동행렬 [[TN FP] [FN TP]]:\n", cm)
    return {'model': name,
            'precision_attack': float(precision_score(yte, yp, zero_division=0)),
            'recall_attack': float(recall_score(yte, yp, zero_division=0)),
            'f1_attack': float(f1_score(yte, yp, zero_division=0)),
            'confusion_matrix': cm.tolist()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', required=True)
    ap.add_argument('--sample', type=int, default=None, help='속도용 행 샘플 수')
    ap.add_argument('--out', default='output')
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    t0 = time.time()
    X, y, label_col = load_clean(args.csv, sample=args.sample)
    print(f"로드 완료: X={X.shape}, 공격비율={y.mean():.4f}, 피처수={X.shape[1]}  ({time.time()-t0:.1f}s)")

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42)
    results = []

    # RandomForest (불균형 보정: class_weight='balanced')
    t = time.time()
    rf = RandomForestClassifier(n_estimators=200, class_weight='balanced',
                                n_jobs=-1, random_state=42)
    rf.fit(Xtr, ytr)
    print(f"[RF] 학습 {time.time()-t:.1f}s")
    results.append(evaluate('RandomForest', rf, Xte, yte))

    # XGBoost (설치돼 있으면; 불균형 보정: scale_pos_weight)
    xgb = None
    try:
        from xgboost import XGBClassifier
        pos = max(int(ytr.sum()), 1); neg = len(ytr) - pos
        t = time.time()
        xgb = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.2,
                            tree_method='hist', n_jobs=-1, random_state=42,
                            scale_pos_weight=neg / pos, eval_metric='logloss')
        xgb.fit(Xtr, ytr)
        print(f"[XGB] 학습 {time.time()-t:.1f}s")
        results.append(evaluate('XGBoost', xgb, Xte, yte))
    except Exception as e:
        print(f"[XGB] 건너뜀: {e}")

    import joblib
    best = max(results, key=lambda r: r['f1_attack'])
    with open(os.path.join(args.out, 'metrics_v01.json'), 'w', encoding='utf-8') as f:
        json.dump({'csv': os.path.basename(args.csv), 'n_features': int(X.shape[1]),
                   'attack_ratio': float(y.mean()), 'results': results,
                   'best': best['model']}, f, ensure_ascii=False, indent=2)
    model_obj = rf if best['model'] == 'RandomForest' else xgb
    joblib.dump({'model': model_obj, 'features': list(X.columns)},
                os.path.join(args.out, 'model_v01.joblib'))
    print(f"\n★ BEST: {best['model']} (공격 F1={best['f1_attack']:.4f}) → {args.out}/ 저장 완료")


if __name__ == '__main__':
    main()
