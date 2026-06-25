# -*- coding: utf-8 -*-
"""결과보고서 hwpx 생성 (v2, XML 파서 기반 — 정규식 수술 금지).

깨짐 방지: lxml로 section0을 실제 파싱 → secPr이 든 첫 문단만 보존하고,
표/헤더 등 복잡 요소는 그 문단에서 제거 → 그 뒤에 '순수 텍스트 문단'만 새로 append.
문단 템플릿은 헤더 내부에 중첩되지 않은 '최상위 단순 hp:p'에서 추출.
"""
import os, sys, shutil, zipfile, copy
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
from lxml import etree

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
BASE = os.path.join(ROOT, "sources", "program", "팀장_사이버보안WE-MEET_팀개인수행계획서.hwpx")
OUT = os.path.join(ROOT, "output", "결과보고서_사이버보안WE-MEET.hwpx")
WORK = os.path.join(ROOT, "scratch", "report_build2")
NS = {'hp': 'http://www.hancom.co.kr/hwpml/2011/paragraph',
      'hs': 'http://www.hancom.co.kr/hwpml/2011/section'}
P = '{%s}' % NS['hp']

LINES = [
    "하기 계절학기 사이버보안 WE-Meet 프로젝트 결과 보고서 (팀)",
    "[ 수강 교과목 ]  교과목명 : 사이버보안 WE-Meet",
    "[ 팀 구성 및 담당업무 ]",
    "과제명 : AI 기반 공격탐지 에이전트 — 네트워크 침입 탐지 및 보안로그 분석",
    "팀장 팀장(컴퓨터융합학부, 20220****) : 데이터 전처리·탐지모델·평가·conformal triage·보고서",
    "팀원 팀원(컴퓨터융합학부, 20230****) : 에이전트 구조·SHAP·LLM 설명·대시보드·통합 테스트",
    "",
    "1. 프로젝트 개요",
    "▢ 과제 선정 배경 및 필요성",
    "❍ 포트스캔·DoS/DDoS·브루트포스·봇넷 등 공격이 다양화되는데 규칙 기반 탐지는 신규·변형 공격에 약하고, 사람이 로그를 직접 보기엔 양이 방대하다.",
    "❍ ML 기반 탐지가 대안이나 공개 벤치마크(CSE-CIC-IDS2018)는 라벨오류·지름길(shortcut) 특징이 있어 무작위 평가의 고정확도가 실제 성능을 과대평가한다. 정직한 평가와 해석 가능한 결과가 필요하다.",
    "",
    "2. 목표 및 수행 내용",
    "▢ 목표 설정",
    "❍ 정상/공격 이진 분류 + 0~100 위험점수 + SHAP 근거 + LLM 자연어 설명을 하나의 시스템으로 통합한다.",
    "❍ 원칙: 탐지·점수는 ML이 결정하고 LLM은 판정을 바꾸지 않고 설명만 한다(재현성·프롬프트 인젝션 방지).",
    "▢ 문제 해결 과정",
    "❍ (발견) 1일치 베이스라인 F1 1.000 → 단일 피처가 중요도 99.2%를 차지하는 지름길 허수임을 발견하고 평가 설계를 전면 재설계했다.",
    "❍ (정직한 평가) 다중 일자 결합 + 누수/지름길 피처 제거 + 날짜 교차 평가(과거→미래)로, 무작위 0.99 대 날짜교차 대부분 0(미관측 공격 일반화 붕괴)을 확인했다.",
    "❍ (병목 규명) 같은 날 데이터 내부에서는 Bot도 0.996으로 구분되어, 문제는 표현 부족이 아니라 과거→미래 전이(분포 변화)임을 입증했다. 임계값은 conformal + Neyman-Pearson으로 분포무관 오탐 제어를 적용했다.",
    "❍ (극복) 시간맥락(temporal) 피처(Dst Port별 causal 시간창·반복 규칙성·연결 실패율)를 추가하여 미관측 공격 탐지율을 크게 끌어올렸다.",
    "▢ 수행 결과 및 검증",
    "❍ 미관측 공격 운영 탐지율(오탐 약 15~18/10만 flow 기준): Bot 0.009→0.49, DoS 0.51→0.62, DDoS 0.38→0.50, BruteForce 0.74→0.98. (Web은 0으로 구조적 한계)",
    "❍ SHAP 근거 + 자연어 5섹션 설명 + Streamlit 위험순 triage 대시보드로 분석가가 근거와 함께 의심 이벤트를 우선 처리할 수 있다.",
    "❍ Windows 이벤트로그 분석 보조 레이어로 봇넷 지속성 흔적(서비스 설치/변경 이벤트) 등 호스트 내부 이상징후를 제시하여 다층 방어 개념을 실증했다.",
    "",
    "3. 활용 방안 및 기대 효과",
    "▢ 기존 방식과의 차별성",
    "❍ 무작위 분할 고정확도 보고 ⇨ 날짜 교차 + shortcut 감사로 과대평가 제거.",
    "❍ 시간 맥락 없는 flow 단독 ⇨ causal temporal 피처로 미관측 공격을 0에서 0.49까지 향상.",
    "❍ LLM이 탐지 판정 ⇨ LLM은 설명만(비권한·인젝션 면역).",
    "❍ 단일 ML의 한계를 실증하여 현업 다층 방어(SIEM+NDR+EDR)의 필요성을 데이터로 이해했다.",
    "▢ 향후 보완할 사항",
    "❍ Web(XSS/SQLi)은 flow에 payload 정보가 없어 구조적으로 미탐 → 패킷/HTTP 레이어가 필요하다.",
    "❍ 공개 데이터가 IP를 제거하여 host/edge(봇넷 beaconing) 피처가 불가 → 원본 재처리 시 추가 상승이 기대된다. NDR+로그+EDR 다층화 및 LLM 에이전트 오케스트레이션이 다음 단계다.",
    "",
    "4. 진행 소감 및 종합 의견",
    "[작성 예정] 성능 숫자보다 정직한 측정이 보안에서 더 중요함을 체감했고, 단일 모델로 다 잡을 수 없기에 현업이 다층 방어를 쓴다는 것을 데이터로 이해했다.",
    "",
    "5. 활동 사진",
    "[작성 예정] 팀 활동 사진 / 완성품: Streamlit triage 대시보드 화면, SHAP 근거 플롯.",
]


def simple_text_para(template_p, text):
    """template_p(단순 hp:p) 복제 → 모든 hp:t를 text 하나로, 나머지 run 제거, linesegarray 제거."""
    p = copy.deepcopy(template_p)
    runs = p.findall(P + 'run')
    # 첫 run만 남기고 제거
    for r in runs[1:]:
        p.remove(r)
    run = p.find(P + 'run')
    # run 안에서 hp:t만 남기고 ctrl/기타 자식 제거
    for child in list(run):
        if child.tag != P + 't':
            run.remove(child)
    ts = run.findall(P + 't')
    if not ts:
        t = etree.SubElement(run, P + 't'); ts = [t]
    ts[0].text = text
    for extra in ts[1:]:
        run.remove(extra)
    # 문단 직속 linesegarray 제거(한글이 재계산)
    for ls in p.findall(P + 'linesegarray'):
        p.remove(ls)
    return p


def main():
    if os.path.exists(WORK): shutil.rmtree(WORK)
    os.makedirs(WORK)
    with zipfile.ZipFile(BASE) as z:
        z.extractall(WORK)

    sec_path = os.path.join(WORK, "Contents", "section0.xml")
    parser = etree.XMLParser(remove_blank_text=False)
    tree = etree.parse(sec_path, parser)
    sec = tree.getroot()

    # 최상위 직속 hp:p들만 (표/헤더 내부 중첩 제외)
    top_paras = [c for c in sec if c.tag == P + 'p']
    head_p = top_paras[0]  # secPr 보유 문단

    # 단순 문단 템플릿: 직속 hp:p 중 hp:t가 있고 표/secPr 없는 것
    def is_simple(p):
        if p.find('.//' + P + 'secPr') is not None: return False
        if p.find('.//' + P + 'tbl') is not None: return False
        if p.find('.//' + P + 'pic') is not None: return False
        return p.find('.//' + P + 't') is not None
    tpl = next((p for p in top_paras if is_simple(p)), None)
    if tpl is None:
        # 없으면 head 다음 자식 중 단순한 것 못 찾음 → 최소 문단 직접 구성
        raise SystemExit("단순 문단 템플릿을 찾지 못함")

    # head_p에서 표/헤더/그림 제거하고 텍스트를 제목으로 (secPr은 유지)
    # → head_p 안의 hp:run 중 secPr 든 run만 남기고 나머지 제거, 그리고 별도 제목문단을 뒤에 추가
    # 안전하게: head_p는 secPr만 담는 빈 문단으로 만들고, 제목은 새 문단으로.
    for run in head_p.findall(P + 'run'):
        # secPr 보유 run은 유지, 그 외(표·헤더 포함) 제거
        if run.find(P + 'secPr') is None:
            head_p.remove(run)
    # head_p에 남은 secPr-run의 hp:t/ctrl 외 잡요소 정리: secPr 다음에 빈 hp:t 보장
    secrun = head_p.find(P + 'run')
    for child in list(secrun):
        if child.tag not in (P + 'secPr', P + 'ctrl'):
            secrun.remove(child)
    if secrun.find(P + 't') is None:
        etree.SubElement(secrun, P + 't').text = ''
    for ls in head_p.findall(P + 'linesegarray'):
        head_p.remove(ls)

    # 기존 top 문단 전부 제거 후, head_p + 텍스트 문단들 재구성
    for p in top_paras:
        sec.remove(p)
    sec.append(head_p)
    for line in LINES:
        sec.append(simple_text_para(tpl, line))

    tree.write(sec_path, xml_declaration=True, encoding='UTF-8', standalone=True)

    # section1,2 비우기: 최상위 hp:p 중 secPr 보유 1개만 남김
    for s in ("section1.xml", "section2.xml"):
        sp = os.path.join(WORK, "Contents", s)
        if not os.path.exists(sp): continue
        t2 = etree.parse(sp, parser); r2 = t2.getroot()
        tp = [c for c in r2 if c.tag == P + 'p']
        keep = next((p for p in tp if p.find('.//' + P + 'secPr') is not None), tp[0] if tp else None)
        for p in tp:
            if p is not keep: r2.remove(p)
        # keep 안의 표/그림 제거
        if keep is not None:
            for run in keep.findall(P + 'run'):
                if run.find(P + 'secPr') is None and (run.find('.//' + P + 'tbl') is not None or run.find('.//' + P + 'pic') is not None):
                    keep.remove(run)
        t2.write(sp, xml_declaration=True, encoding='UTF-8', standalone=True)

    # 재압축: mimetype 먼저(비압축), 나머지 압축
    if os.path.exists(OUT): os.remove(OUT)
    with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as z:
        mt = os.path.join(WORK, 'mimetype')
        if os.path.exists(mt):
            zi = zipfile.ZipInfo('mimetype'); zi.compress_type = zipfile.ZIP_STORED
            z.writestr(zi, open(mt, 'rb').read())
        for root, _, files in os.walk(WORK):
            for fn in files:
                fp = os.path.join(root, fn)
                arc = os.path.relpath(fp, WORK).replace(os.sep, '/')
                if arc == 'mimetype': continue
                z.write(fp, arc)
    print("생성:", OUT, "(", round(os.path.getsize(OUT) / 1024), "KB )")


if __name__ == '__main__':
    main()
