# -*- coding: utf-8 -*-
"""갭3 — 공격 유형 다중분류 (XGB/F2). '공격이다'를 넘어 '어떤 공격인지'.

두 평가: (A) 무작위분할(상한) (B) 시간순(앞 절반 일자 학습→뒤 테스트) — 일반화 확인.
공격군을 대표 클래스로 매핑(정상 포함). per-class recall/precision/F1 + 혼동.
"""
import glob, os, re, json, time, sys
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from xgboost import XGBClassifier

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
DATA = os.path.join(ROOT, "sources", "cicids2018")
DROP = ['Fwd Seg Size Min', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Protocol']
CAP = 40000  # 일자×라벨


def day_of(p): return os.path.basename(p).split('_')[0]
def order_of(d): q = d.split('-'); return int(q[-2]) * 100 + int(q[-3])


# 원 라벨 → 대표 클래스
def fam(lbl):
    l = lbl.lower()
    if l == 'benign': return 'Benign'
    if 'ddos' in l: return 'DDoS'                       # DDoS 먼저(dos 포함 방지)
    if 'bot' in l: return 'Bot'
    if 'infil' in l: return 'Infiltration'
    if 'web' in l or 'xss' in l or 'sql' in l: return 'Web'
    if 'ftp' in l or 'ssh' in l or ('brute' in l): return 'BruteForce'
    if 'dos' in l: return 'DoS'
    return 'Other'


def read_day(path, cap=None, seed=42):
    df = pd.read_parquet(path); df.columns = [c.strip() for c in df.columns]
    if cap:
        df = pd.concat([g.sample(cap, random_state=seed) if len(g) > cap else g
                        for _, g in df.groupby('Label', sort=False)], ignore_index=True)
    df['order'] = order_of(day_of(path))
    return df


def to_X(df):
    X = df.drop(columns=['Label', 'order'], errors='ignore').drop(columns=[c for c in DROP], errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    X.columns = [re.sub(r'[\[\]<>]', '_', str(c)) for c in X.columns]
    return X


def main():
    t0 = time.time()
    full = pd.concat([read_day(f, cap=CAP) for f in glob.glob(os.path.join(DATA, "*.parquet"))], ignore_index=True)
    full = full[~full['Label'].astype(str).str.lower().str.contains('infil')]  # 라벨불신 제외
    famcol = full['Label'].astype(str).map(fam)
    classes = sorted(famcol.unique())
    cls2i = {c: i for i, c in enumerate(classes)}
    y = famcol.map(cls2i).values
    X = to_X(full); cols = list(X.columns[X.nunique() > 1])
    order = full['order'].values
    print(f"클래스 {classes} · {len(full):,}행 · ({time.time()-t0:.0f}s)")

    def model():
        return XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.2, tree_method='hist',
                             n_jobs=-1, random_state=42, eval_metric='mlogloss')

    res = {}
    # (A) 무작위분할 상한
    Xtr, Xte, ytr, yte = train_test_split(X[cols], y, test_size=0.25, stratify=y, random_state=42)
    m = model().fit(Xtr, ytr); yp = m.predict(Xte)
    rep = classification_report(yte, yp, target_names=classes, output_dict=True, zero_division=0)
    res['random'] = {c: {'recall': round(rep[c]['recall'], 3), 'precision': round(rep[c]['precision'], 3),
                         'f1': round(rep[c]['f1-score'], 3), 'support': int(rep[c]['support'])} for c in classes}
    res['random_macroF1'] = round(rep['macro avg']['f1-score'], 4)
    print(f"  [A 무작위] macro-F1 {res['random_macroF1']} ({time.time()-t0:.0f}s)")
    cmA = confusion_matrix(yte, yp)

    # (B) 시간순: 앞 절반 일자 학습 → 뒤 절반 테스트. XGB는 0..K-1 연속 라벨 필요 → train 기준 재매핑.
    cut = np.median(np.unique(order))
    tr = order <= cut; te = order > cut
    tr_labels = sorted(set(y[tr]))                       # 학습에 등장한 클래스만
    remap = {orig: i for i, orig in enumerate(tr_labels)}
    ytr_r = np.array([remap[v] for v in y[tr]])
    m2 = model().fit(X[cols][tr], ytr_r)
    # 테스트: 학습에 없던 클래스는 예측 불가 → '미학습'으로 분류해 recall 0 기록
    pred_r = m2.predict(X[cols][te])
    inv = {i: orig for orig, i in remap.items()}
    yp2 = np.array([inv[v] for v in pred_r])
    tr_names = [classes[i] for i in tr_labels]
    rep2 = classification_report(y[te], yp2, labels=tr_labels, target_names=tr_names,
                                 output_dict=True, zero_division=0)
    res['temporal_trained_classes'] = tr_names
    res['temporal'] = {c: {'recall': round(rep2[c]['recall'], 3), 'precision': round(rep2[c]['precision'], 3),
                           'f1': round(rep2[c]['f1-score'], 3), 'support': int(rep2[c]['support'])}
                       for c in tr_names if c in rep2}
    res['temporal_macroF1'] = round(rep2['macro avg']['f1-score'], 4)
    print(f"  [B 시간순] macro-F1 {res['temporal_macroF1']} ({time.time()-t0:.0f}s)")

    json.dump({'classes': classes, 'results': res}, open(os.path.join(ROOT, 'output', 'metrics_multiclass.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)

    print("\n=== (A) 무작위분할 상한 — per-class ===")
    print(f"{'class':<14}{'recall':>8}{'prec':>8}{'f1':>8}{'support':>10}")
    for c in classes:
        r = res['random'][c]; print(f"{c:<14}{r['recall']:>8}{r['precision']:>8}{r['f1']:>8}{r['support']:>10}")
    print(f"  → macro-F1 {res['random_macroF1']}")
    print("\n=== (B) 시간순(앞→뒤 일자) — per-class ===")
    print(f"{'class':<14}{'recall':>8}{'prec':>8}{'f1':>8}{'support':>10}")
    for c in classes:
        if c in res['temporal']:
            r = res['temporal'][c]; print(f"{c:<14}{r['recall']:>8}{r['precision']:>8}{r['f1']:>8}{r['support']:>10}")
    print(f"  → macro-F1 {res['temporal_macroF1']}")


if __name__ == '__main__':
    main()
