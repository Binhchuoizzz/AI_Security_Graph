# Kết quả mapper LỖI THỜI — không trích vào luận văn

Bốn tệp trong thư mục này chạy **trước** đợt vá 2026-08 và **mâu thuẫn với nhau**.
Giữ lại để lưu vết, KHÔNG dùng để bảo vệ.

| tệp | tag | mode | n | exact match |
| :-- | :-- | :-- | --: | --: |
| `attack_mapper_eval_baseline.json` | baseline | e2e | 500 | 4,8% |
| `attack_mapper_eval_e2e_clean_rag.json` | e2e_clean_rag | e2e | 500 | **68,4%** |
| `attack_mapper_eval_csic_payload_e2e.json` | csic_payload_e2e | e2e | 550 | **2,33%** |
| `attack_mapper_eval_csic_payload_rrf.json` | csic_payload_rrf | rrf | 550 | 67,33% |

## Hai lý do loại bỏ

**1. Hai con số e2e trái ngược cùng tồn tại.** 68,4% và 2,33% cho cùng một chế độ.
`scripts/export_final_report.py` khi đó đọc cặp `csic_payload_*` ⇒ báo cáo chốt in **2,33%**,
trong khi tài liệu trích **68,4%** từ tệp mà bộ sinh báo cáo **không hề đọc**.

**2. Cả bốn đều chạy trước `drop_authored()`.** n ∈ {500, 550}, không tệp nào bằng **250** —
số mẫu tầng payload sau khi loại 50 mẫu do tác giả biên soạn. 50 mẫu ấy **cùng đáp án
`T1190`**, nên chúng kéo tỉ lệ khớp kỹ thuật lên một cách giả tạo.

## Quy ước thay thế

`eval_attack_mapper.py` nay tự đặt tag `{mode}_{evidence-layer}` khi không truyền `--tag`:

```text
attack_mapper_eval_rrf_payload.json    attack_mapper_eval_e2e_payload.json
attack_mapper_eval_rrf_flow.json       attack_mapper_eval_e2e_flow.json
attack_mapper_eval_rrf_all.json        attack_mapper_eval_e2e_all.json
```

Tên tệp tự nói lên nó đo cấu hình nào, nên không còn sinh được cặp số mâu thuẫn mà
không ai biết tệp nào là thật.
