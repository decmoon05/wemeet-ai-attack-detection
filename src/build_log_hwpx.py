# -*- coding: utf-8 -*-
"""수행일지 1주차 hwpx — 운영계획안의 수행일지 안내(1·2·3 항목)만 남기고 그 아래 내용 추가.

방법: section2를 lxml로 파싱 → '프로젝트 수행 일지(안)'~'참고 1-3' 직전까지의 최상위 문단만 남김
+ 그 뒤에 우리 1주차 내용을 같은 단순문단 서식으로 append. 나머지 섹션은 빈 secPr 문단만.
표/그림 안 건드림.
"""
import os, sys, shutil, zipfile, copy
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
from lxml import etree

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
BASE = os.path.join(ROOT, "sources", "program", "[학생 안내자료] 260612_하기 계절학기 지산학교과 운영계획(안).hwpx")
OUT = os.path.join(ROOT, "output", "제출물", "사이버보안 WE-Meet 팀과제3 수행일지 1주차.hwpx")
WORK = os.path.join(ROOT, "scratch", "log_build")
HP = '{http://www.hancom.co.kr/hwpml/2011/paragraph}'

CONTENT = [
    "",
    "■ 교과목: 사이버보안 WE-Meet   /   과제: AI 기반 공격탐지 에이전트 (네트워크 침입 탐지 및 보안로그 분석)",
    "■ 팀: 팀장(팀장, (학번 비공개)) · 팀원((학번 비공개))   /   기간: 2026-06-22 ~ 06-29 (1주차)   /   작성일: 2026-06-28",
    "■ ※ 6.26 온/오프라인 소집 멘토링은 운영 여건상 미진행 → 멘토 과제(#1 PPT, #2 어려운점) 수행 및 비대면 멘토링 요청으로 대체",
    "",
    "1. 주요 논의 내용",
    " - 주제 구체화: 'AI 기반 공격탐지 에이전트'를 네트워크 침입 탐지(NDR) + 보안로그 분석으로 구체화. 데이터셋 CSE-CIC-IDS2018 확정.",
    " - 시스템 설계: 데이터 → RF/XGBoost 이진 탐지 → 0~100 위험점수 → SHAP 근거 → LLM 자연어 설명 → Streamlit 대시보드. (탐지·점수는 ML, LLM은 설명만)",
    " - 정직한 평가 체계 수립: 무작위 분할의 고정확도 함정을 발견하고 날짜 교차(과거→미래) 평가로 전환.",
    " - 멘토 요청(과제 #2 연계): ①벤치마크 artifact 식별법 ②미관측 공격 일반화의 현실적 목표 ③IP/payload 부재 데이터의 대안 ④SOC 위험도·alert budget 실무 ⑤학부 프로젝트 적정 범위.",
    "",
    "2. 검토 피드백 및 후속 조치 계획",
    " (자체 검토)",
    " - 1일치 베이스라인 F1 1.000 → 단일 피처가 모델 중요도 99%를 차지하는 지름길 허상 확인 → 평가 설계 전면 재설계(다중 일자·누수 피처 제거·날짜 교차).",
    " - 미관측 공격 탐지율 붕괴 → 원인이 '전이(분포 변화)'임을 진단 → 시간맥락 피처 추가로 봇넷 0.009→0.49 등 개선.",
    " (후속 조치 — 차주)",
    " - 멘토님 비대면 피드백(과제 #2 답변) 반영 → 평가·범위 방향 조정",
    " - 위험점수·임계값 운영 검증 마무리 및 대시보드 시연 자료화",
    " - 결과보고서 본문 정리(양식 채움 완료, 멘토 피드백 반영 예정)",
    " - (여건 시) 원본 데이터 재처리로 호스트 기반 피처 추가 검토",
    "",
    "3. 증빙 자료 (온/오프라인 진행 근거 첨부)",
    " - 팀 과제 #1: 멘토 소개용 PPT (사이버보안 WE-Meet 팀과제1 PPT.pptx, 9매)",
    " - 팀 과제 #2: 진행간 어려운 점 정리 문서",
    " - 코드·실험 산출물: 탐지·평가·위험점수·SHAP·LLM 설명·대시보드·로그 분석 (지표 JSON, SHAP 플롯, 대시보드 화면)",
    " - ※ 6.26 소집 멘토링 미진행으로 대면 회의 사진 증빙은 없으며, 비대면 메일 송부 내역으로 갈음.",
]


def simple_para(tpl, text):
    p = copy.deepcopy(tpl)
    for r in p.findall(HP + 'run')[1:]:
        p.remove(r)
    run = p.find(HP + 'run')
    for ch in list(run):
        if ch.tag != HP + 't': run.remove(ch)
    ts = run.findall(HP + 't')
    if not ts:
        ts = [etree.SubElement(run, HP + 't')]
    ts[0].text = text
    for ex in ts[1:]: run.remove(ex)
    for ls in p.findall(HP + 'linesegarray'): p.remove(ls)
    return p


def main():
    if os.path.exists(WORK): shutil.rmtree(WORK)
    os.makedirs(WORK)
    with zipfile.ZipFile(BASE) as z: z.extractall(WORK)
    parser = etree.XMLParser()

    sec_path = os.path.join(WORK, "Contents", "section2.xml")
    tree = etree.parse(sec_path, parser); root = tree.getroot()
    top = [c for c in root if c.tag == HP + 'p']
    head = top[0]  # secPr 문단

    def is_simple(p):
        return (p.find('.//' + HP + 'secPr') is None and p.find('.//' + HP + 'tbl') is None
                and p.find('.//' + HP + 'pic') is None and p.find('.//' + HP + 't') is not None)
    tpl = next(p for p in top if is_simple(p))

    def ptext(p):
        return ''.join(t.text or '' for t in p.findall('.//' + HP + 't'))

    # 수행일지 안내 문단 범위: '프로젝트 수행 일지(안)' 포함 문단 ~ '참고 1' (다음 -3) 직전
    start_p = next(i for i, p in enumerate(top) if '수행 일지' in ptext(p) or '수행일지' in ptext(p))
    # 끝: start 이후 '결과 보고서' 또는 '참고 1-3' 나오는 문단 직전
    end_p = next((i for i in range(start_p + 1, len(top))
                  if '결과 보고서' in ptext(top[i]) or '결과보고서' in ptext(top[i]) or '-3' in ptext(top[i])), len(top))
    keep = top[start_p:end_p]  # 수행일지 안내 문단들

    # head(secPr) 정리: 표/그림/헤더 제거, secPr만
    for run in head.findall(HP + 'run'):
        if run.find(HP + 'secPr') is None: head.remove(run)
    secrun = head.find(HP + 'run')
    for ch in list(secrun):
        if ch.tag not in (HP + 'secPr', HP + 'ctrl'): secrun.remove(ch)
    if secrun.find(HP + 't') is None: etree.SubElement(secrun, HP + 't').text = ''
    for ls in head.findall(HP + 'linesegarray'): head.remove(ls)

    # 기존 top 전부 제거 → head + 안내문단 + 우리 내용
    for p in top: root.remove(p)
    root.append(head)
    for p in keep: root.append(copy.deepcopy(p))
    for line in CONTENT: root.append(simple_para(tpl, line))
    tree.write(sec_path, xml_declaration=True, encoding='UTF-8', standalone=True)

    # section0, section1 비우기(secPr 문단만)
    for s in ("section0.xml", "section1.xml"):
        sp = os.path.join(WORK, "Contents", s)
        if not os.path.exists(sp): continue
        t2 = etree.parse(sp, parser); r2 = t2.getroot()
        tp = [c for c in r2 if c.tag == HP + 'p']
        k = next((p for p in tp if p.find('.//' + HP + 'secPr') is not None), tp[0] if tp else None)
        for p in tp:
            if p is not k: r2.remove(p)
        if k is not None:
            for run in k.findall(HP + 'run'):
                if run.find(HP + 'secPr') is None and (run.find('.//' + HP + 'tbl') is not None or run.find('.//' + HP + 'pic') is not None):
                    k.remove(run)
        t2.write(sp, xml_declaration=True, encoding='UTF-8', standalone=True)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    if os.path.exists(OUT): os.remove(OUT)
    with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as z:
        mt = os.path.join(WORK, 'mimetype')
        if os.path.exists(mt):
            zi = zipfile.ZipInfo('mimetype'); zi.compress_type = zipfile.ZIP_STORED
            z.writestr(zi, open(mt, 'rb').read())
        for r, _, files in os.walk(WORK):
            for fn in files:
                fp = os.path.join(r, fn); arc = os.path.relpath(fp, WORK).replace(os.sep, '/')
                if arc == 'mimetype': continue
                z.write(fp, arc)
    print("생성:", OUT, "(", round(os.path.getsize(OUT) / 1024), "KB )")


if __name__ == '__main__':
    main()
