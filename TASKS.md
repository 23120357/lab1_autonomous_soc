# Phân công Lab 1 — Chuẩn hoá và ưu tiên hoá lỗ hổng

**Thời gian dự kiến:** 2–3 ngày  
**Mục tiêu:** Hoàn thiện `starter.py`, chạy `check_lab1.py` đạt ít nhất 10/13 điểm (cố gắng 13/13), nộp ảnh kết quả chấm và báo cáo 1–2 trang trả lời đủ ba câu hỏi ở mục 9 của đề.

## Việc chung trước khi bắt đầu

- [ ] Cùng đọc mục 1, 2, 7–9 của đề và lướt `starter.py`, `data/assets.yaml`.
- [ ] Cài PyYAML: `pip install pyyaml`.
- [ ] Trong thư mục `lab1`, chạy `python check_lab1.py` để xem trạng thái ban đầu.
- [ ] Thống nhất chỉ sửa các hàm được phân công trong `starter.py`; không sửa `check_lab1.py` hoặc dữ liệu gốc trong `data/`.

## Thành — Chuẩn hoá dữ liệu và làm giàu KEV

Phụ trách **Phần 1 và Phần 2**, khoảng **7/13 điểm** tự chấm.

- [ ] `parse_nmap`: chỉ lấy cổng `open`; tạo ID `NMAP-001`…; ghép tiêu đề từ cổng, giao thức và service; ánh xạ IP sang `asset_id`.
- [ ] `parse_nuclei`: đọc từng dòng JSONL; bỏ qua dòng rỗng hoặc JSON hỏng; lấy CVE/CWE; viết hoa CWE; suy ra CVSS từ severity khi thiếu điểm.
- [ ] `parse_trivy`: duyệt `Results[].Vulnerabilities[]`; ghép tên package với tiêu đề; lấy `V3Score` lớn nhất; gán `exploitability` theo severity.
- [ ] `enrich_kev`: đánh dấu CVE trong `kev_catalog` và chuyển `exploitability` thành `in_the_wild`.
- [ ] Chạy `python check_lab1.py` sau mỗi hàm; sửa đến khi các mục **1.1–2.1** đạt tối đa.
- [ ] Ghi chú ngắn cách xử lý dữ liệu thiếu/hỏng để dùng khi giải thích bài.

## Huyền — Chấm điểm, xếp hạng và đánh giá

Phụ trách **Phần 3 và Phần 4**, khoảng **6/13 điểm** tự chấm. Có thể bắt đầu `score_finding` và `ndcg` song song với lúc Thành viết parser, bằng các `Finding` mẫu trong script chấm.

- [ ] `score_finding`: áp dụng đúng các trọng số và bảng ánh xạ có sẵn; điểm không âm; gán băng P1–P4; điền đủ 7 đóng góp vào `breakdown`.
- [ ] `rank`: tìm ngữ cảnh tài sản theo `asset_id`, chấm mọi finding và sắp xếp điểm giảm dần.
- [ ] `ndcg`: tính DCG/IDCG, xử lý `k` và trường hợp IDCG bằng 0.
- [ ] `compare_with_cvss_baseline`: tạo thứ tự theo hệ thống và theo CVSS; tính hai giá trị nDCG và `delta`; trả về đủ 5 trường đề yêu cầu.
- [ ] Chạy `python check_lab1.py`; sửa đến khi các mục **3.1–4.2** đạt tối đa.
- [ ] Chuẩn bị bảng so sánh Spring4Shell và Log4Shell từ `breakdown` thực tế sau khi ghép code.

## Tiến độ 2–3 ngày

| Thời điểm | Thành | Huyền | Mốc chung |
| --- | --- | --- | --- |
| Ngày 1 | Hoàn thành 3 parser, bắt đầu KEV | Hoàn thành công thức điểm và nDCG, bắt đầu rank/baseline | Chạy tự chấm từng phần, báo nhau nếu vướng định dạng `Finding` |
| Ngày 2 | Hoàn tất KEV, rà kết quả parser, hỗ trợ giải thích dữ liệu | Hoàn tất rank/baseline, trích `breakdown` và nDCG | Ghép code, chạy `starter.py` và `check_lab1.py`, viết báo cáo |
| Ngày 3 nếu cần | Sửa lỗi còn lại | Sửa lỗi còn lại | Chụp màn hình điểm, rà đủ tệp và nộp |

## Checklist ghép bài và nộp

- [ ] Chạy `python starter.py`: Spring4Shell đứng trên Log4Shell; thứ hạng đầu khớp kỳ vọng trong đề.
- [ ] Chạy `python check_lab1.py`: tối thiểu **10/13**, mục tiêu **13/13**. Chụp màn hình kết quả cuối.
- [ ] Báo cáo 1–2 trang trả lời đủ ba câu hỏi:
  1. Ít nhất ba lý do phải tính điểm bằng code thay vì giao LLM tính.
  2. Dùng **số đóng góp thực tế trong `breakdown`** để giải thích vì sao Spring4Shell xếp trên Log4Shell.
  3. Dự đoán `delta` khi cả bốn tài sản có cùng `criticality=medium` và `exposure=internal_lab`, giải thích tác động đến thứ hạng. Nếu muốn thử nghiệm, tạo bản sao dữ liệu để chạy; giữ nguyên `data/assets.yaml` khi nộp.
- [ ] Tệp nộp gồm `starter.py` hoàn thiện, ảnh kết quả chấm và báo cáo.

> Lưu ý: README ghi Lab 1 dự kiến 6–8 giờ làm việc; lịch 2–3 ngày ở đây có thời gian dự phòng để hai bạn ghép bài và rà báo cáo.
