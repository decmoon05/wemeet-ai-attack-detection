# -*- coding: utf-8 -*-
"""멘토 과제 #2·#3 docx 생성. #3은 운영계획안 수행일지 3항목 구조(주요 논의/피드백·조치/증빙)를 따름."""
import os, sys
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
from docx import Document
from docx.shared import Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
OUTDIR = os.path.join(ROOT, "output", "제출물")
os.makedirs(OUTDIR, exist_ok=True)
FONT = "맑은 고딕"
NAVY = RGBColor(0x18, 0x29, 0x4C)
TEAL = RGBColor(0x0C, 0x8A, 0x80)


def base_doc():
    d = Document()
    st = d.styles['Normal']; st.font.name = FONT; st.font.size = Pt(10.5)
    st._element.rPr.rFonts.set(__import__('docx').oxml.ns.qn('w:eastAsia'), FONT)
    return d


def H(d, text, size=15, color=NAVY, space_before=10, space_after=4):
    p = d.add_paragraph(); p.paragraph_format.space_before = Pt(space_before); p.paragraph_format.space_after = Pt(space_after)
    r = p.add_run(text); r.bold = True; r.font.size = Pt(size); r.font.color.rgb = color
    r.font.name = FONT; r._element.rPr.rFonts.set(__import__('docx').oxml.ns.qn('w:eastAsia'), FONT)
    return p


def P(d, text, bullet=False, size=10.5, indent=0):
    p = d.add_paragraph(); p.paragraph_format.space_after = Pt(3); p.paragraph_format.line_spacing = 1.25
    if indent: p.paragraph_format.left_indent = Pt(indent)
    r = p.add_run(("• " if bullet else "") + text); r.font.size = Pt(size)
    r.font.name = FONT; r._element.rPr.rFonts.set(__import__('docx').oxml.ns.qn('w:eastAsia'), FONT)
    return p


def meta_line(d, text):
    p = d.add_paragraph(); p.paragraph_format.space_after = Pt(2)
    r = p.add_run(text); r.font.size = Pt(9.5); r.font.color.rgb = RGBColor(0x5C, 0x6B, 0x82)
    r.font.name = FONT; r._element.rPr.rFonts.set(__import__('docx').oxml.ns.qn('w:eastAsia'), FONT)


# ========== #2 진행간 어려운 점 (자유 양식) ==========
def build_q2():
    d = base_doc()
    t = d.add_paragraph(); t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = t.add_run("사이버보안 WE-Meet — 팀 과제 #2 : 진행간 어려운 점 (멘토링 요청)")
    r.bold = True; r.font.size = Pt(15); r.font.color.rgb = NAVY
    r.font.name = FONT; r._element.rPr.rFonts.set(__import__('docx').oxml.ns.qn('w:eastAsia'), FONT)
    meta_line(d, "교과목: 사이버보안 WE-Meet   |   과제: AI 기반 공격탐지 에이전트 (CSE-CIC-IDS2018)")
    meta_line(d, "팀: 팀장(팀장) · 팀원   |   작성일: 2026-06-26")
    P(d, "계획 단계를 넘어 실제 구현·평가까지 진행하면서 부딪힌 어려움과, 멘토님께 여쭙고 싶은 점을 정리했습니다.", size=10.5)

    items = [
        ("1. 벤치마크 데이터의 ‘고정확도 함정’",
         ["단일 일자로 학습/평가하면 F1 1.000이 나오지만, 단일 피처(Fwd Seg Size Min)가 모델 중요도의 99%를 차지하는 ‘지름길(shortcut)’이었습니다. 실제 공격 행위가 아니라 데이터 생성 특성을 학습한 허상이었습니다.",
          "[질문] 실무에서 공개 벤치마크의 이런 artifact를 어떻게 식별·배제하시는지, 신뢰할 수 있는 평가 셋업의 기준이 궁금합니다."]),
        ("2. 미관측(신규) 공격에 대한 일반화",
         ["과거 공격으로 학습 → 미래의 새 공격군을 탐지(날짜 교차)하면 탐지율이 0에 가깝게 떨어졌습니다. 무작위 분할의 높은 성능은 환상이었습니다.",
          "진단 결과 ‘표현 부족이 아니라 전이(분포 변화) 문제’임을 확인했고, 시간맥락(temporal) 피처를 추가해 미관측 공격 탐지율을 끌어올렸습니다(예: 봇넷 0.009 → 0.49).",
          "[질문] zero-day/미관측 공격을 단일 모델로 기대하는 것이 현실적인지? 현업에서 목표 수준과, 다층 방어(SIEM/NDR/EDR)에서 ML 탐지의 실제 비중이 궁금합니다."]),
        ("3. 데이터 한계 (IP·payload 부재)",
         ["공개 정제판이 출발지/목적지 IP를 제거해, 봇넷의 핵심인 ‘동일 호스트 반복 통신(beaconing)’ 피처를 만들 수 없었습니다. 원본 PCAP은 일자당 36~55GB(전체 약 440GB)라 재처리가 부담입니다.",
          "Web 공격(XSS/SQLi)은 flow 통계에 요청 내용(payload)이 없어 일반 HTTP와 구분이 어려워 현재 구조에서 미탐(0)입니다.",
          "[질문] 제한된 자원에서 IP/payload 없이 접근할 현실적 대안이 있는지, 아니면 이 한계를 명확히 명시하는 방향이 맞는지?"]),
        ("4. 위험점수·임계값의 운영 신뢰성",
         ["위험점수(0~100)와 우선순위 임계값을 테스트 데이터가 아니라 과거 데이터 기반으로 정해야 운영에 가깝다고 보고, conformal + Neyman-Pearson 방식으로 오탐을 분포무관하게 제어했습니다.",
          "[질문] SOC 분석가가 실제로 신뢰하는 위험도·우선순위(P1~P3) 제시 방식과, 하루 오탐 허용량(alert budget)의 실무 감각이 궁금합니다."]),
        ("5. 일정·범위 (계절학기 4주)",
         ["AI 보조 개발로 구현 속도는 확보했으나 ‘어디까지가 적정 범위인가’ 결정이 어렵습니다. 현재는 네트워크 탐지(NDR) 한 층 + 보안로그 분석 보조 레이어로 1차 완성했습니다.",
          "[질문] 학부 산학 프로젝트로서 ‘탐지기 완성’보다 ‘정직한 평가와 한계 규명’에 무게를 두는 현재 방향이 적절한지 의견을 듣고 싶습니다."]),
    ]
    for h, lines in items:
        H(d, h, size=12)
        for ln in lines:
            P(d, ln, bullet=True, indent=10)
    H(d, "요약", size=12)
    P(d, "단순 정확도 경쟁이 아니라 ‘정직하게 측정하고 어디까지 신뢰 가능한지’를 규명하는 방향으로 진행 중입니다. 위 5가지에 대한 실무 관점 피드백을 부탁드립니다. 감사합니다.")
    out = os.path.join(OUTDIR, "사이버보안 WE-Meet 팀과제2 진행간 어려운점.docx")
    d.save(out); return out


# ========== #3 수행일지 1주차 (참고 1-2 양식: 3항목 구조) ==========
def build_q3():
    d = base_doc()
    t = d.add_paragraph(); t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = t.add_run("하기 계절학기 프로젝트 수행일지 (1주차)")
    r.bold = True; r.font.size = Pt(16); r.font.color.rgb = NAVY
    r.font.name = FONT; r._element.rPr.rFonts.set(__import__('docx').oxml.ns.qn('w:eastAsia'), FONT)
    meta_line(d, "교과목: 사이버보안 WE-Meet   |   과제: AI 기반 공격탐지 에이전트 (네트워크 침입 탐지 및 보안로그 분석)")
    meta_line(d, "팀: 팀장(팀장, (학번 비공개)) · 팀원((학번 비공개))   |   기간: 2026-06-22 ~ 06-29   |   작성일: 2026-06-28")
    meta_line(d, "※ 6.26 온/오프라인 소집 멘토링은 운영 여건상 미진행 → 멘토 과제(#1 PPT, #2 어려운점) 수행 및 비대면 멘토링 요청으로 대체")

    H(d, "1. 주요 논의 주제", size=13)
    for ln in [
        "주제 구체화: ‘AI 기반 공격탐지 에이전트’를 네트워크 침입 탐지(NDR) + 보안로그 분석으로 구체화. 데이터셋 CSE-CIC-IDS2018 확정.",
        "시스템 설계: 데이터 → RF/XGBoost 이진 탐지 → 0~100 위험점수 → SHAP 근거 → LLM 자연어 설명 → Streamlit 대시보드. (탐지·점수는 ML, LLM은 설명만)",
        "정직한 평가 체계 수립: 무작위 분할의 고정확도 함정을 발견하고 날짜 교차(과거→미래) 평가로 전환.",
        "멘토 요청(과제 #2 연계): ①벤치마크 artifact 식별법 ②미관측 공격 일반화의 현실적 목표 ③IP/payload 부재 데이터의 대안 ④SOC 위험도·alert budget 실무 ⑤학부 프로젝트 적정 범위.",
    ]:
        P(d, ln, bullet=True, indent=10)

    H(d, "2. 검토 피드백 및 후속 조치 계획", size=13)
    P(d, "(자체 검토)", size=10.5)
    for ln in [
        "1일치 베이스라인 F1 1.000 → 단일 피처 99% 지름길 허상 확인 → 평가 설계 전면 재설계(다중 일자·누수 피처 제거·날짜 교차).",
        "미관측 공격 탐지율 붕괴 → 원인이 ‘전이(분포 변화)’임을 진단 → 시간맥락 피처 추가로 봇넷 0.009→0.49 등 개선.",
    ]:
        P(d, ln, bullet=True, indent=10)
    P(d, "(후속 조치 — 차주)", size=10.5)
    for ln in [
        "멘토님 비대면 피드백(과제 #2 답변) 반영 → 평가·범위 방향 조정",
        "위험점수·임계값 운영 검증 마무리 및 대시보드 시연 자료화",
        "결과보고서 본문 정리(양식 채움 완료, 멘토 피드백 반영 예정)",
        "(여건 시) 원본 데이터 재처리로 호스트 기반 피처 추가 검토",
    ]:
        P(d, ln, bullet=True, indent=10)

    H(d, "3. 증빙 자료", size=13)
    for ln in [
        "팀 과제 #1: 멘토 소개용 PPT (사이버보안 WE-Meet 팀과제1 PPT.pptx, 9매)",
        "팀 과제 #2: 진행간 어려운 점 정리 (사이버보안 WE-Meet 팀과제2 진행간 어려운점.docx)",
        "코드·실험 산출물: 탐지·평가·위험점수·SHAP·LLM 설명·대시보드·로그 분석 (지표 JSON, SHAP 플롯, 대시보드 화면)",
        "※ 6.26 소집 멘토링 미진행으로 대면 회의 사진 증빙은 없으며, 비대면 메일 송부 내역으로 갈음.",
    ]:
        P(d, ln, bullet=True, indent=10)

    out = os.path.join(OUTDIR, "사이버보안 WE-Meet 팀과제3 수행일지 1주차.docx")
    d.save(out); return out


if __name__ == "__main__":
    print("저장:", build_q2())
    print("저장:", build_q3())
