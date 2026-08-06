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

## `latency_benchmark_PRE_OFFLOAD_FIX.json` — loại 04/08/2026

Đo bằng `measure_latency_baseline.py` **trước** khi vá cách đếm xả tải. Bản cũ coi Tier-1 "xong
việc" chỉ khi hành động là `DROP`/`WHITELIST_DROP`:

```python
if result.get("tier1_action") in ("DROP", "WHITELIST_DROP"):   # dòng 130, SAI
```

Nhưng `subscriber.py:511` bọc toàn bộ nhánh Cổng ML/LLM trong `if action == "ESCALATE"` — nghĩa là
`BLOCK_IP`, `ALERT`, `AWAIT_HITL` cũng **kết thúc tại Tier-1**. Hậu quả kép:

1. **Xả tải bị hạ thấp**: ghi 74,0%, trong khi cùng luồng cùng engine đếm đúng là **90,6%**.
2. **Độ trễ hai tầng bị thổi phồng**: những ca Tier-1 ĐÃ CHẶN vẫn bị gửi lên LLM trong phép đo,
   nên mỗi ca như vậy cộng thêm ~23 giây không có thật vào `two_tier_mean_ms`.

Cùng họ với lỗi đã vá ở `evaluate_feedback_loop` (`BLOCK_IP` bị đếm là *leo thang*). **Không trích
bất kỳ số nào trong tệp này.** Giữ lại chỉ để đối chiếu mức chênh trước/sau khi vá.
