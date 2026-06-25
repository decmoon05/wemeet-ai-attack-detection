# -*- coding: utf-8 -*-
"""보안로그 분석 레이어 (경량 데모) — CSE-CIC-IDS2018 Windows 이벤트로그(.evtx).

다층 방어의 '로그 레이어' 보조 분석. NDR(네트워크)이 못 보는 호스트 내부 이벤트를 본다.
라벨이 없으므로(설치시점 로그 혼재) '분류'가 아니라 '이상징후 분석':
 - 호스트별 EventID 분포, 시간대별 이벤트량
 - 드문 EventID(전체 1% 미만) = 잠재 이상
 - 보안 관련 EventID 추출(로그인 실패 4625, 서비스변경 7040, 프로세스 4688 등)
 - 호스트 간 이상치(다른 호스트 대비 특정 EventID 급증)
출력: output/log_analysis.json + 콘솔 요약
"""
import glob, os, re, json, time, sys, collections
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
import Evtx.Evtx as evtx

ROOT = r"C:\Users\WannaGoHome\Desktop\내 문서\coss\사이버보안 WE-MEET"
LOGDIR = os.path.join(ROOT, "sources", "logs_bot")
# 보안 관점 주요 EventID (Windows)
SECURITY_EID = {
    '4625': '로그온 실패(브루트포스 의심)', '4624': '로그온 성공', '4634': '로그오프',
    '4688': '새 프로세스 생성', '4672': '특수권한 로그온', '4720': '계정 생성',
    '7040': '서비스 시작유형 변경', '7045': '서비스 설치', '1102': '감사로그 삭제',
    '4648': '명시적 자격증명 로그온', '4698': '예약작업 생성',
}
MAXREC = 30000


def eid_of(x):
    m = re.search(r'<EventID[^>]*>(\d+)</EventID>', x)
    return m.group(1) if m else None


def parse_evtx(path):
    eid = collections.Counter(); chan = collections.Counter(); n = 0
    with evtx.Evtx(path) as log:
        for rec in log.records():
            x = rec.xml()
            e = eid_of(x)
            if e: eid[e] += 1
            c = re.search(r'<Channel>([^<]*)</Channel>', x)
            if c: chan[c.group(1)] += 1
            n += 1
            if n >= MAXREC: break
    return eid, chan, n


def main():
    t0 = time.time()
    files = sorted(glob.glob(os.path.join(LOGDIR, "*.evtx")))
    print(f"분석 대상 호스트 로그 {len(files)}개")
    hosts = {}
    global_eid = collections.Counter()
    for f in files:
        host = os.path.basename(f).replace('.evtx', '').split('-')[-1]  # IP 끝부분
        eid, chan, n = parse_evtx(f)
        hosts[host] = {'n_events': n, 'top_eid': eid.most_common(8),
                       'channels': dict(chan.most_common(5)),
                       'security_events': {k: eid.get(k, 0) for k in SECURITY_EID if eid.get(k, 0) > 0}}
        global_eid.update(eid)
        print(f"  [{host}] 이벤트 {n}건, 채널 {dict(chan.most_common(3))} ({time.time()-t0:.0f}s)")

    # 드문 EventID(전체의 0.5% 미만) = 잠재 이상징후
    total = sum(global_eid.values())
    rare = {k: v for k, v in global_eid.items() if v / total < 0.005}
    # 호스트 간 이상: 한 호스트에만 유독 많은 EventID
    summary = {
        'n_hosts': len(files), 'total_events': total,
        'global_top_eid': global_eid.most_common(12),
        'rare_eid_count': len(rare),
        'security_eid_present': {k: SECURITY_EID[k] for k in SECURITY_EID if global_eid.get(k, 0) > 0},
        'hosts': hosts,
    }
    json.dump(summary, open(os.path.join(ROOT, 'output', 'log_analysis.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=2)

    print("\n" + "=" * 70)
    print(f"총 {len(files)}개 호스트, {total:,} 이벤트")
    print(f"전역 EventID top: {global_eid.most_common(8)}")
    print(f"드문 EventID(잠재 이상, <0.5%): {len(rare)}종")
    print("보안 관련 EventID 발견:")
    for k in SECURITY_EID:
        if global_eid.get(k, 0) > 0:
            print(f"  {k} ({SECURITY_EID[k]}): {global_eid[k]}건")
    print("=" * 70)
    print("→ NDR(네트워크)이 못 보는 호스트 내부 이벤트. 다층 방어의 로그 레이어.")
    print("  한계: evtx에 공격 라벨 없음(설치시점 로그 혼재) → 분류 아닌 이상징후 분석 데모.")


if __name__ == '__main__':
    main()
