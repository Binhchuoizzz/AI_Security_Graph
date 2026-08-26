# 📌 BẢNG ĐỐI CHIẾU NHANH: SCRIPT PYTHON ⇄ TỆP KẾT QUẢ JSON

> Thư mục này chứa **bản sao 10 tệp Python cốt lõi** sinh ra 9 tệp kết quả JSON trong thư mục `Main/`.
> Dùng để đối chiếu trực tiếp code đo đạc với số liệu thực tế.

---

## 🎯 BẢNG ÁNH XẠ 1:1

| # | Tệp Python Trong Thư Mục Này | Tệp Kết Quả JSON Tương Ứng (Thư Mục Cha) | Lệnh Chạy Thực Nghiệm | Chỉ Số Sinh Ra |
| :-: | :--- | :--- | :--- | :--- |
| **1** | [`measure_latency_baseline.py`](measure_latency_baseline.py) | `../latency_benchmark.json` | `.venv/bin/python experiments/measure_latency_baseline.py` | **`0,88 ms`** độ trễ trung vị (P95 25.8s). |
| **2** | [`measure_offload_vs_baserate.py`](measure_offload_vs_baserate.py) | `../offload_vs_baserate_stream.json` | `.venv/bin/python experiments/measure_offload_vs_baserate.py` | **`97,5%`** xả tải ở base-rate 9.8%. |
| **3** | [`evaluate_tier2_decision.py`](evaluate_tier2_decision.py) | `../tier2_decision_results.json` | `.venv/bin/python experiments/evaluate_tier2_decision.py` | **`84,24%`** giảm tải SOC, **`95,0%`** bắt đe dọa. |
| **4** | [`evaluate_adversarial.py`](evaluate_adversarial.py) | `../adversarial_pipeline_results.json` | `.venv/bin/python experiments/evaluate_adversarial.py` | **`100.0%`** kháng Prompt Injection (678 mẫu). |
| **5** | [`score_evidence_grounding.py`](score_evidence_grounding.py) | `../evidence_grounding_results.json` | `.venv/bin/python experiments/score_evidence_grounding.py` | **`0.0%`** ảo giác, chặn 76 lệnh Block sai. |
| **6** | [`run_audit_tamper.py`](run_audit_tamper.py) | `../audit_tamper_results.json` | `.venv/bin/python experiments/run_audit_tamper.py` | **`100.0%`** phát hiện sửa log qua HMAC. |
| **7** | [`evaluate_ml_gate.py`](evaluate_ml_gate.py) | `../ml_gate_results.json` | `.venv/bin/python experiments/evaluate_ml_gate.py` | **`100.0%`** Auto-BLOCK, **`3.452 eps`**. |
| **8** | [`evaluate_reasoning.py`](evaluate_reasoning.py) | `../reasoning_eval_results.json` | `.venv/bin/python experiments/evaluate_reasoning.py` | **`3,78 / 5,0`** điểm chất lượng (Llama-3). |
| **9** | [`audit_thesis_numbers.py`](audit_thesis_numbers.py) | `../thesis_number_audit.json` | `.venv/bin/python scripts/audit_thesis_numbers.py` | **106 đúng · 0 token lệch EN↔VI**. |
| **10** | [`unified_dataset.py`](unified_dataset.py) | *(Module điều phối dữ liệu chung)* | *(Được import tự động bởi 9 script trên)* | Chuẩn hóa 5 nguồn data thành 1 luồng duy nhất. |

---

*Lưu ý: Các file trong thư mục này là bản sao độc lập phục vụ việc đọc hiểu và đối chiếu code khi demo/bảo vệ.*
