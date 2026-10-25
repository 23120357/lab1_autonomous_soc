#!/usr/bin/env python3
"""CHẤM TỰ ĐỘNG — LAB 1.   Chạy:  python check_lab1.py

Script chấm từng phần độc lập: phần nào chưa làm sẽ báo 0 điểm nhưng KHÔNG
làm dừng các phần còn lại. Chạy lại nhiều lần tuỳ thích.
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
DATA = Path(__file__).parent / "data"

try:
    import starter as S
except Exception:
    print("LỖI: không import được starter.py\n")
    traceback.print_exc()
    raise SystemExit(1)

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; D = "\033[90m"; B = "\033[1m"; X = "\033[0m"
results: list[tuple[str, float, float, str]] = []


def task(name: str, maxpt: float):
    def deco(fn):
        try:
            pt, msg = fn()
        except NotImplementedError:
            pt, msg = 0.0, "chưa cài đặt"
        except Exception as e:
            pt, msg = 0.0, f"lỗi khi chạy: {type(e).__name__}: {e}"
        results.append((name, pt, maxpt, msg))
        col = G if pt == maxpt else (Y if pt > 0 else R)
        print(f"  {col}{pt:>4.1f}/{maxpt:<4}{X} {name:<44}{D}{msg}{X}")
        return fn
    return deco


ctx = S.load_context()
SM = ctx["source_map"]
nmap_txt = (DATA / "nmap.xml").read_text(encoding="utf-8")
nuclei_txt = (DATA / "nuclei.jsonl").read_text(encoding="utf-8")
trivy_txt = (DATA / "trivy.json").read_text(encoding="utf-8")

print(f"\n{B}══ CHẤM LAB 1 — CHUẨN HOÁ & ƯU TIÊN HOÁ LỖ HỔNG ══{X}\n")
print(f"{B}PHẦN 1 — Phân tích kết quả scanner{X}")


@task("1.1 parse_nmap: chỉ lấy cổng open", 1.0)
def t11():
    f = S.parse_nmap(nmap_txt, SM)
    if not f:
        return 0.0, "chưa trả về finding nào"
    if len(f) != 3:
        return 0.3, f"cần 3 cổng open, nhận {len(f)} (cổng 9200 là closed — phải bỏ)"
    return 1.0, "3 cổng open, đã loại cổng closed"


@task("1.2 parse_nmap: định dạng id và trường", 1.0)
def t12():
    f = S.parse_nmap(nmap_txt, SM)
    if not f:
        return 0.0, "chưa có dữ liệu"
    pt, notes = 0.0, []
    if f[0].id == "NMAP-001":
        pt += 0.4
    else:
        notes.append(f"id='{f[0].id}' (cần 'NMAP-001')")
    if f[0].cvss == 4.0 and f[0].cwe == "CWE-668" and f[0].source == "nmap":
        pt += 0.3
    else:
        notes.append("cvss/cwe/source chưa đúng")
    if any("3000" in x.title and "Express" in x.title for x in f):
        pt += 0.3
    else:
        notes.append("title chưa ghép service+product")
    return pt, ("đạt" if pt == 1.0 else "; ".join(notes))


@task("1.3 parse_nuclei: đọc 5 dòng JSONL", 1.0)
def t13():
    f = S.parse_nuclei(nuclei_txt, SM)
    if len(f) != 5:
        return 0.0 if not f else 0.4, f"cần 5 finding, nhận {len(f)}"
    return 1.0, "đủ 5 finding"


@task("1.4 parse_nuclei: cve/cwe/cvss suy luận", 1.5)
def t14():
    f = S.parse_nuclei(nuclei_txt, SM)
    if not f:
        return 0.0, "chưa có dữ liệu"
    by = {x.title: x for x in f}
    pt, notes = 0.0, []
    sp = next((v for k, v in by.items() if "Spring4Shell" in k), None)
    if sp and sp.cve == "CVE-2022-22965":
        pt += 0.5
    else:
        notes.append("chưa lấy được cve-id")
    csp = next((v for k, v in by.items() if "Content-Security-Policy" in k), None)
    if csp and abs(csp.cvss - 3.0) < 0.01:
        pt += 0.6
    else:
        notes.append("CSP thiếu cvss-score → phải suy ra 3.0 từ severity=low")
    if csp and csp.cwe == "CWE-693":
        pt += 0.4
    else:
        notes.append("cwe chưa viết hoa đúng dạng CWE-693")
    return pt, ("đạt" if pt == 1.5 else "; ".join(notes))


@task("1.5 parse_nuclei: chịu được dòng hỏng", 0.5)
def t15():
    broken = nuclei_txt + "\n{ dòng JSON hỏng \n\n"
    try:
        f = S.parse_nuclei(broken, SM)
    except Exception as e:
        return 0.0, f"bị sập khi gặp dòng hỏng: {type(e).__name__}"
    return (0.5, "bỏ qua dòng hỏng đúng cách") if len(f) == 5 else (0.2, f"nhận {len(f)}, cần 5")


@task("1.6 parse_trivy: 5 vuln + CVSS lớn nhất", 1.0)
def t16():
    f = S.parse_trivy(trivy_txt, SM)
    if len(f) != 5:
        return 0.0 if not f else 0.3, f"cần 5 vuln, nhận {len(f)}"
    log4j = next((x for x in f if x.cve == "CVE-2021-44228"), None)
    if not log4j:
        return 0.5, "không thấy CVE-2021-44228"
    if abs(log4j.cvss - 10.0) > 0.01:
        return 0.7, f"cvss={log4j.cvss}, cần 10.0"
    if log4j.exploitability != "poc":
        return 0.85, "CRITICAL phải cho exploitability='poc'"
    return 1.0, "đủ 5 vuln, cvss và exploitability đúng"


print(f"\n{B}PHẦN 2 — Làm giàu ngữ cảnh{X}")


@task("2.1 enrich_kev: đánh dấu CVE trong KEV", 1.0)
def t21():
    f = S.parse_trivy(trivy_txt, SM) + S.parse_nuclei(nuclei_txt, SM)
    if not f:
        return 0.0, "chưa có dữ liệu"
    f = S.enrich_kev(f, ctx["kev_catalog"])
    kevs = {x.cve for x in f if x.kev}
    if kevs != {"CVE-2021-44228", "CVE-2022-22965"}:
        return 0.3, f"KEV nhận diện được: {kevs or 'không có'}"
    bad = [x.cve for x in f if x.kev and x.exploitability != "in_the_wild"]
    if bad:
        return 0.7, "KEV phải kèm exploitability='in_the_wild'"
    return 1.0, "2 CVE trong KEV, exploitability đúng"


print(f"\n{B}PHẦN 3 — Chấm điểm rủi ro{X}")


@task("3.1 score_finding: công thức đúng", 1.5)
def t31():
    f = S.Finding(id="T", source="trivy", asset_id="demo-image", title="t",
                  cvss=10.0, kev=True, exploitability="in_the_wild", control="none")
    asset = {"id": "demo-image", "criticality": "medium", "exposure": "internal_lab"}
    f = S.score_finding(f, asset)
    want = 0.35 * 1.0 + 0.20 * 0.5 + 0.15 * 0.25 + 0.15 * 1.0 + 0.10 * 1.0 + 0.05 * 0.5 - 0.0
    if abs(f.score - want) > 0.001:
        return 0.3, f"score={f.score:.4f}, đáp án={want:.4f}"
    if f.band != "P2":
        return 1.0, f"band='{f.band}', cần 'P2' (0.7 ≤ {want:.3f} < 0.85)"
    return 1.5, f"score={f.score:.3f} band=P2 chính xác"


@task("3.2 score_finding: breakdown đủ 7 khoá", 0.5)
def t32():
    f = S.Finding(id="T", source="nmap", asset_id="sandbox", title="t", cvss=5.0)
    f = S.score_finding(f, {"id": "sandbox", "criticality": "low", "exposure": "internal_lab"})
    need = {"cvss", "asset", "exposure", "kev", "exploitability", "business", "control"}
    miss = need - set(f.breakdown or {})
    if miss:
        return 0.0, f"thiếu khoá: {sorted(miss)}"
    if abs(sum(f.breakdown.values()) - f.score) > 0.001:
        return 0.3, "tổng breakdown phải bằng score"
    return 0.5, "đủ 7 khoá, tổng khớp score"


@task("3.3 score_finding: control làm GIẢM điểm", 0.5)
def t33():
    a = {"id": "web-shop", "criticality": "high", "exposure": "public"}
    f1 = S.score_finding(S.Finding(id="A", source="nuclei", asset_id="web-shop",
                                   title="t", cvss=7.0, control="none"), a)
    f2 = S.score_finding(S.Finding(id="B", source="nuclei", asset_id="web-shop",
                                   title="t", cvss=7.0, control="waf"), a)
    if f2.score >= f1.score:
        return 0.0, "có WAF phải cho điểm THẤP hơn (trọng số âm)"
    return 0.5, f"none={f1.score:.3f} > waf={f2.score:.3f}"


@task("3.4 rank: sắp xếp giảm dần + ngữ cảnh thắng CVSS", 1.5)
def t34():
    f = (S.parse_nmap(nmap_txt, SM) + S.parse_nuclei(nuclei_txt, SM)
         + S.parse_trivy(trivy_txt, SM))
    if not f:
        return 0.0, "chưa có dữ liệu"
    f = S.enrich_kev(f, ctx["kev_catalog"])
    f = S.rank(f, ctx)
    sc = [x.score for x in f]
    if sc != sorted(sc, reverse=True):
        return 0.4, "chưa sắp xếp giảm dần theo score"
    top = f[0]
    if "Spring4Shell" not in top.title:
        return 0.9, (f"top hiện là '{top.title[:34]}'. Đáp án: Spring4Shell — "
                     "vì nằm trên Jenkins (critical) dù CVSS 9.8 < Log4Shell 10.0")
    log4j = next((x for x in f if x.cve == "CVE-2021-44228"), None)
    if log4j and f.index(log4j) == 0:
        return 1.2, "Log4Shell không được đứng đầu"
    return 1.5, "Spring4Shell (9.8) vượt Log4Shell (10.0) nhờ ngữ cảnh tài sản"


print(f"\n{B}PHẦN 4 — Đánh giá đối chứng{X}")


@task("4.1 ndcg: công thức đúng", 1.0)
def t41():
    if abs(S.ndcg([3, 2, 1, 0]) - 1.0) > 0.001:
        return 0.0, "thứ tự lý tưởng phải cho nDCG = 1.0"
    v = S.ndcg([0, 1, 2, 3])
    if not (0.0 < v < 0.8):
        return 0.4, f"thứ tự ngược cho {v:.4f} — có vẻ sai công thức"
    if abs(S.ndcg([0, 0, 0]) - 0.0) > 1e-9:
        return 0.7, "toàn số 0 phải trả 0.0 (tránh chia cho 0)"
    if abs(S.ndcg([3, 2, 1, 0], 2) - 1.0) > 0.001:
        return 0.8, "chưa xử lý tham số k"
    return 1.0, "nDCG đúng cả trường hợp biên"


@task("4.2 compare_with_cvss_baseline", 1.0)
def t42():
    f = (S.parse_nuclei(nuclei_txt, SM) + S.parse_trivy(trivy_txt, SM))
    if not f:
        return 0.0, "chưa có dữ liệu"
    f = S.enrich_kev(f, ctx["kev_catalog"])
    sp = next((x.id for x in f if "Spring4Shell" in x.title), None)
    lg = next((x.id for x in f if x.cve == "CVE-2021-44228"), None)
    expert = {sp: 3.0, lg: 2.0}
    r = S.compare_with_cvss_baseline(f, ctx, expert)
    need = {"system_ndcg", "cvss_ndcg", "delta", "system_order", "cvss_order"}
    miss = need - set(r or {})
    if miss:
        return 0.0, f"thiếu khoá: {sorted(miss)}"
    if r["system_order"][0] != sp:
        return 0.5, "hệ thống phải xếp Spring4Shell đầu"
    if r["cvss_order"][0] != lg:
        return 0.7, "baseline CVSS phải xếp Log4Shell đầu (CVSS 10.0)"
    if r["delta"] <= 0:
        return 0.8, f"delta={r['delta']} — hệ thống phải vượt baseline"
    return 1.0, f"delta = +{r['delta']} (hệ thống thắng baseline CVSS)"


total = sum(r[1] for r in results)
mx = sum(r[2] for r in results)
print(f"\n{B}{'─' * 74}{X}")
col = G if total >= mx * 0.8 else (Y if total >= mx * 0.5 else R)
print(f"{B}  TỔNG ĐIỂM: {col}{total:.1f}/{mx:.0f}{X}  ({total / mx:.0%})")
done = sum(1 for r in results if r[1] == r[2])
print(f"  Hoàn thành trọn vẹn: {done}/{len(results)} mục")
if total < mx:
    print(f"\n{Y}  Các mục cần làm tiếp:{X}")
    for n, p, m, msg in results:
        if p < m:
            print(f"    • {n} — {msg}")
print()
