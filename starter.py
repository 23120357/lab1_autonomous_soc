#!/usr/bin/env python3
"""LAB 1 — CHUẨN HOÁ VÀ ƯU TIÊN HOÁ LỖ HỔNG
================================================================
Sinh viên hoàn thiện các hàm có đánh dấu  ### TODO ###
Kiểm tra bài làm bất cứ lúc nào bằng:

    python check_lab1.py

KHÔNG sửa tên hàm và kiểu dữ liệu trả về — script chấm dựa vào chúng.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DATA = Path(__file__).parent / "data"


# ==================================================================
# PHẦN 0 — Cấu trúc dữ liệu chuẩn (đã cho sẵn, không cần sửa)
# ==================================================================
@dataclass
class Finding:
    id: str
    source: str                      # nmap | nuclei | trivy
    asset_id: str
    title: str
    cve: str | None = None
    cwe: str | None = None
    cvss: float = 0.0
    kev: bool = False
    exploitability: str = "none"     # none | poc | in_the_wild
    control: str = "none"            # none | waf | edr
    score: float = 0.0
    band: str = "P4"
    breakdown: dict = field(default_factory=dict)


def load_context() -> dict:
    """Nạp assets.yaml — đã cho sẵn."""
    return yaml.safe_load((DATA / "assets.yaml").read_text(encoding="utf-8"))


# ==================================================================
# PHẦN 1 — Bộ phân tích kết quả scanner  (3 hàm)
# ==================================================================
def parse_nmap(xml_text: str, source_map: dict) -> list[Finding]:
    """Đọc nmap XML, trả về danh sách Finding cho các cổng đang MỞ.

    Yêu cầu:
      - CHỈ lấy port có <state state="open">, bỏ qua closed/filtered.
      - id đặt theo mẫu  "NMAP-001", "NMAP-002", ...
      - title dạng:  "Cổng 3000/tcp mở — http Node.js Express framework"
        (ghép: portid/protocol + tên service + product, bỏ khoảng trắng thừa)
      - cwe = "CWE-668", cvss = 4.0, source = "nmap"
      - asset_id: tra source_map theo địa chỉ IP của host (thẻ <address addr=...>)

    Gợi ý: ET.fromstring(xml_text), rồi root.iter("host") / host.iter("port").
    """
    findings: list[Finding] = []
    root = ET.fromstring(xml_text)
    for host in root.iter("host"):
        address = host.find("address")
        if address is None:
            continue
        asset_id = source_map.get(address.get("addr", ""), "")
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            details = [port.get("portid", "") + "/" + port.get("protocol", "")]
            if service is not None:
                details.extend((service.get("name", ""), service.get("product", "")))
            title = "Cổng " + details[0] + " mở — " + " ".join(
                part.strip() for part in details[1:] if part.strip()
            )
            findings.append(Finding(
                id=f"NMAP-{len(findings) + 1:03d}", source="nmap",
                asset_id=asset_id, title=title.rstrip(), cwe="CWE-668", cvss=4.0,
            ))
    return findings


def parse_nuclei(jsonl_text: str, source_map: dict) -> list[Finding]:
    """Đọc nuclei JSONL (mỗi dòng 1 JSON), trả về danh sách Finding.

    Yêu cầu:
      - Bỏ qua dòng rỗng / JSON hỏng (KHÔNG được để chương trình sập).
      - id theo mẫu "NUCLEI-001", ...
      - title lấy từ info.name
      - cve  lấy phần tử đầu của info.classification["cve-id"] nếu có, không thì None
      - cwe  lấy phần tử đầu của info.classification["cwe-id"], VIẾT HOA (vd "CWE-693")
      - cvss lấy info.classification["cvss-score"]; nếu THIẾU thì suy ra từ
             info.severity theo bảng: info=1.0 low=3.0 medium=5.5 high=7.5 critical=9.3
      - asset_id: tra source_map theo trường "host"
    """
    findings: list[Finding] = []
    severity_scores = {
        "info": 1.0, "low": 3.0, "medium": 5.5,
        "high": 7.5, "critical": 9.3,
    }
    for line in jsonl_text.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = entry.get("info", {})
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or []
        cwes = classification.get("cwe-id") or []
        cvss = classification.get("cvss-score")
        findings.append(Finding(
            id=f"NUCLEI-{len(findings) + 1:03d}",
            source="nuclei",
            asset_id=source_map.get(entry.get("host", ""), ""),
            title=info.get("name", ""),
            cve=cves[0] if cves else None,
            cwe=cwes[0].upper() if cwes else None,
            cvss=float(cvss) if cvss is not None else severity_scores.get(
                info.get("severity", "").lower(), 0.0
            ),
        ))
    return findings


def parse_trivy(json_text: str, source_map: dict) -> list[Finding]:
    """Đọc trivy JSON, trả về danh sách Finding.

    Yêu cầu:
      - Duyệt Results[].Vulnerabilities[]
      - id theo mẫu "TRIVY-001", ...
      - title dạng:  "log4j-core: Log4Shell: remote code execution via JNDI lookup"
        (ghép PkgName + ": " + Title)
      - cvss lấy giá trị V3Score LỚN NHẤT trong các nguồn của trường CVSS
      - exploitability = "poc" nếu Severity là CRITICAL hoặc HIGH, ngược lại "none"
      - asset_id: tra source_map theo ArtifactName
    """
    findings: list[Finding] = []
    report = json.loads(json_text)
    asset_id = source_map.get(report.get("ArtifactName", ""), "")
    for result in report.get("Results", []):
        for vulnerability in result.get("Vulnerabilities") or []:
            scores = [source["V3Score"] for source in (vulnerability.get("CVSS") or {}).values()
                      if source.get("V3Score") is not None]
            cwes = vulnerability.get("CweIDs") or []
            severity = vulnerability.get("Severity", "").upper()
            findings.append(Finding(
                id=f"TRIVY-{len(findings) + 1:03d}",
                source="trivy",
                asset_id=asset_id,
                title=f"{vulnerability.get('PkgName', '')}: {vulnerability.get('Title', '')}",
                cve=vulnerability.get("VulnerabilityID"),
                cwe=cwes[0] if cwes else None,
                cvss=float(max(scores, default=0.0)),
                exploitability="poc" if severity in {"CRITICAL", "HIGH"} else "none",
            ))
    return findings


# ==================================================================
# PHẦN 2 — Làm giàu ngữ cảnh
# ==================================================================
def enrich_kev(findings: list[Finding], kev_catalog: list[str]) -> list[Finding]:
    """Đánh dấu kev=True cho finding có CVE nằm trong danh mục KEV.

    Với finding đã ở trong KEV, đặt luôn exploitability = "in_the_wild"
    (vì KEV nghĩa là đã bị khai thác trong thực tế).
    """
    kev_cves = set(kev_catalog)
    for finding in findings:
        if finding.cve in kev_cves:
            finding.kev = True
            finding.exploitability = "in_the_wild"
    return findings


# ==================================================================
# PHẦN 3 — Chấm điểm rủi ro (Risk Priority Score)
# ==================================================================
W = {"cvss": 0.35, "asset": 0.20, "exposure": 0.15, "kev": 0.15,
     "exploit": 0.10, "business": 0.05, "control": -0.10}
MAP_CRIT = {"low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.0}
MAP_EXPO = {"internal_lab": 0.25, "vpn": 0.50, "public": 1.0}
MAP_EXPL = {"none": 0.25, "poc": 0.60, "in_the_wild": 1.0}
MAP_CTRL = {"none": 0.0, "waf": 0.4, "edr": 0.6}


def score_finding(f: Finding, asset: dict, business: float = 0.5) -> Finding:
    """Tính điểm rủi ro và gán f.score, f.band, f.breakdown.

    Công thức:
      score = 0.35*(cvss/10) + 0.20*Asset + 0.15*Exposure + 0.15*KEV
            + 0.10*Exploitability + 0.05*Business − 0.10*Control
    Điểm không được âm (dùng max(0.0, ...)).

    Phân băng:  >=0.85 → P1 | >=0.70 → P2 | >=0.50 → P3 | còn lại → P4

    f.breakdown là dict gồm 7 khoá: cvss, asset, exposure, kev,
    exploitability, business, control — mỗi khoá là ĐÓNG GÓP đã nhân trọng số.

    CÂU HỎI SUY NGẪM: vì sao phần này phải viết bằng code mà KHÔNG giao cho LLM?
    """
    ### TODO ### — viết code của bạn ở đây
    return f


def rank(findings: list[Finding], ctx: dict) -> list[Finding]:
    """Chấm điểm toàn bộ và sắp xếp GIẢM DẦN theo score."""
    by_id = {a["id"]: a for a in ctx["assets"]}
    ### TODO ### — chấm điểm từng finding rồi sắp xếp
    return findings


# ==================================================================
# PHẦN 4 — Đánh giá so với đường cơ sở
# ==================================================================
def ndcg(relevances: list[float], k: int | None = None) -> float:
    """nDCG của một thứ tự xếp hạng.

    DCG  = Σ (2^rel_i − 1) / log2(i + 2)      với i tính từ 0
    IDCG = DCG của thứ tự lý tưởng (relevances sắp xếp giảm dần)
    nDCG = DCG / IDCG   (trả 0.0 nếu IDCG == 0)
    """
    ### TODO ### — viết code của bạn ở đây
    return 0.0


def compare_with_cvss_baseline(findings: list[Finding], ctx: dict,
                               expert: dict[str, float]) -> dict:
    """So sánh thứ hạng của HỆ THỐNG với baseline chỉ dùng CVSS.

    expert: {finding_id: mức quan trọng theo chuyên gia (0..3)}

    Trả về dict:
      {"system_ndcg": float, "cvss_ndcg": float, "delta": float,
       "system_order": [id...], "cvss_order": [id...]}
    """
    ### TODO ### — viết code của bạn ở đây
    return {}


# ==================================================================
# CHẠY THỬ
# ==================================================================
def main() -> None:
    ctx = load_context()
    sm = ctx["source_map"]

    findings = (parse_nmap((DATA / "nmap.xml").read_text(encoding="utf-8"), sm)
                + parse_nuclei((DATA / "nuclei.jsonl").read_text(encoding="utf-8"), sm)
                + parse_trivy((DATA / "trivy.json").read_text(encoding="utf-8"), sm))
    print(f"Đã phân tích {len(findings)} findings")

    findings = enrich_kev(findings, ctx["kev_catalog"])
    findings = rank(findings, ctx)

    print(f"\n{'ID':<12}{'ĐIỂM':>7}  {'BĂNG':<5}{'CVSS':>6}  {'KEV':<5}TIÊU ĐỀ")
    print("-" * 92)
    for f in findings[:12]:
        print(f"{f.id:<12}{f.score:>7.3f}  {f.band:<5}{f.cvss:>6.1f}  "
              f"{'⚠' if f.kev else ' ':<5}{f.title[:44]}")


if __name__ == "__main__":
    main()
