# -*- coding: utf-8 -*-
"""결과보고서 채우기 (올바른 방법) — 운영계획안 양식 그대로 두고 빈칸 hp:t에만 텍스트 삽입.

양식 구조(표·문단·서식) 1바이트도 안 건드림. section2의 '결과 보고서'~'개인정보 동의서' 범위에서
hp:t 노드를 순서대로 세어, 지정 인덱스에만 텍스트 채움(append 방식: 기존 라벨 보존).
"""
import os, sys, shutil, zipfile
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
from lxml import etree

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
BASE = os.path.join(ROOT, "sources", "program", "[학생 안내자료] 260612_하기 계절학기 지산학교과 운영계획(안).hwpx")
OUT = os.path.join(ROOT, "output", "결과보고서_사이버보안WE-MEET.hwpx")
WORK = os.path.join(ROOT, "scratch", "report_fill")
HP = '{http://www.hancom.co.kr/hwpml/2011/paragraph}'

# 라벨 기반 매핑(인덱스 밀림에 안전): 양식의 특정 라벨 노드 '다음의 빈 hp:t/❍ 노드들'을 순서대로 채움.
# (label_substring, [채울 텍스트들]) — 라벨 노드를 찾고 그 뒤의 빈칸/❍ 노드에 차례로 set.
SECTIONS = [
    ("교과목명", ["사이버보안 WE-Meet"]),
    ("과 제 명", ["AI 기반 공격탐지 에이전트 — 네트워크 침입 탐지 및 보안로그 분석"]),
    ("과제 선정 배경 및 필요성", [
        "포트스캔·DoS/DDoS·브루트포스·봇넷 등 공격이 다양화되는데 규칙 기반 탐지는 신규·변형 공격에 약하고, 사람이 로그를 직접 보기엔 양이 방대하다.",
        "공개 벤치마크(CSE-CIC-IDS2018)는 라벨오류·지름길 특징이 있어 무작위 평가 고정확도가 실제 성능을 과대평가한다 → 정직한 평가와 해석 가능한 결과가 필요하다."]),
    ("팀 구성", ["2인(팀장: 데이터·모델·평가·문서 / 팀원: 에이전트·시각화·통합). AI 보조 개발 + 검증 라이브러리 활용."]),
    ("해결할 문제도출 및 사용자 정의", [
        "보안관제 분석가가 대량 트래픽 중 의심 이벤트를 우선 처리해야 하나, 근거 없는 단순 알림은 판단이 어렵다.",
        "신규(미관측) 공격은 기존 ML이 거의 못 잡는다 → '어디까지 신뢰 가능한가'를 정량화해야 한다."]),
    ("목표설정", [
        "정상/공격 이진 분류 + 0~100 위험점수 + SHAP 근거 + LLM 자연어 설명을 한 시스템으로 통합.",
        "원칙: 탐지·점수는 ML이 결정, LLM은 판정 변경 없이 설명만(재현성·프롬프트 인젝션 방지)."]),
    ("문제해결과정", [
        "(발견) 1일치 베이스라인 F1 1.000 → 단일 피처가 중요도 99.2% 차지하는 지름길 허수임을 발견, 평가 설계 재설계.",
        "(정직한 평가) 다중 일자 결합·누수 피처 제거·날짜 교차 평가로 무작위 0.99 대 날짜교차 대부분 0(미관측 공격 일반화 붕괴) 확인.",
        "(병목 규명·극복) 같은 날 내부 Bot 0.996 → 표현이 아니라 전이 문제임을 입증. 시간맥락 피처 추가로 미관측 공격 탐지율 급상승."]),
    ("수행결과 및 사용자 검증", [
        "미관측 공격 운영 탐지율(오탐 약 15~18/10만): Bot 0.009→0.49, DoS 0.51→0.62, DDoS 0.38→0.50, BruteForce 0.74→0.98 (Web은 구조적 한계).",
        "SHAP 근거 + 자연어 5섹션 설명 + Streamlit 위험순 triage 대시보드로 분석가가 근거와 함께 우선 처리 가능.",
        "Windows 이벤트로그 분석 보조 레이어로 봇넷 지속성 흔적 등 호스트 내부 이상징후 제시 → 다층 방어 실증."]),
    ("향후 보완할 사항", [
        "Web(XSS/SQLi)은 flow에 payload 없어 구조적 미탐 → 패킷/HTTP 레이어 필요.",
        "공개 데이터 IP 제거로 host/edge(봇넷 beaconing) 피처 불가 → 원본 재처리 시 추가 상승 기대. NDR+로그+EDR 다층화·LLM 에이전트가 다음 단계."]),
]


def main():
    if os.path.exists(WORK): shutil.rmtree(WORK)
    os.makedirs(WORK)
    with zipfile.ZipFile(BASE) as z:
        z.extractall(WORK)

    sec = os.path.join(WORK, "Contents", "section2.xml")
    parser = etree.XMLParser()
    tree = etree.parse(sec, parser); root = tree.getroot()

    all_t = root.findall('.//' + HP + 't')
    def txt(e): return (e.text or '')
    start_i = next(i for i, e in enumerate(all_t) if '결과 보고서' in txt(e))
    end_i = next((i for i, e in enumerate(all_t) if '개인정보' in txt(e) and i > start_i), len(all_t))

    def is_blank(e):
        t = (e.text or '').strip()
        return t == '' or t == '❍' or t == '❍'  # 빈칸 또는 ❍만 있는 항목

    filled = 0
    cursor = start_i
    for label, values in SECTIONS:
        # label 노드를 cursor 이후에서 찾음
        li = next((i for i in range(cursor, end_i) if label in txt(all_t[i])), None)
        if li is None:
            print(f"  [경고] 라벨 못찾음: {label}")
            continue
        # label 다음의 빈 노드들에 values 차례로 채움
        vi = 0; j = li + 1
        while vi < len(values) and j < end_i:
            if is_blank(all_t[j]):
                cur = (all_t[j].text or '')
                # ❍ 기호 보존하고 뒤에 붙임
                if cur.strip() == '❍':
                    all_t[j].text = cur.rstrip() + ' ' + values[vi]
                else:
                    all_t[j].text = values[vi]
                vi += 1; filled += 1
            elif label in txt(all_t[j]):
                pass  # 같은 라벨 반복 영역 — 통과
            j += 1
        cursor = li + 1
    print(f"채운 항목 수: {filled}")

    tree.write(sec, xml_declaration=True, encoding='UTF-8', standalone=True)

    # 재압축 (mimetype 먼저 비압축)
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
    print("※ 양식(표·서식) 그대로, 빈칸 hp:t에만 텍스트 삽입. 다른 섹션(운영계획 본문)도 그대로 포함됨.")


if __name__ == '__main__':
    main()
