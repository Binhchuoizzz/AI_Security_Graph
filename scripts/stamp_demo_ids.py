"""SENTINEL — Đóng dấu KHOÁ NỐI `gt_id` lên luồng demo + tách nhãn ra SIDECAR.

VÌ SAO CẦN FILE NÀY (lỗi thật, chặn toàn bộ việc đo lường)
-----------------------------------------------------------------------------
`src/agent/trace.py`, `src/streaming/subscriber.py` và `scripts/push_flow.py` đều ĐỌC
`gt_id`, và `subscriber._LABEL_KEY_ALLOW` cố ý cho khoá này đi qua bộ tước nhãn để phục vụ
đối chiếu hậu kiểm. Nhưng **không builder nào GHI nó**: đo trên `data/demo_small.json` được
0/5.000 sự kiện có `gt_id`. Hệ quả: `batch.gt_ids` rỗng ở cả 708 bản ghi tracer, tức là
**không một con số nào của lượt chạy sống có thể đối chiếu với sự thật** — không thể tính
độ chính xác kỹ thuật, không thể chấm quyết định, không thể benchmark.

CÁCH LÀM — hai nguyên tắc bất di bất dịch
-----------------------------------------------------------------------------
1. **ID phải MỜ.** `gt_id` đi qua pipeline nên nó tuyệt đối không được nói gì về đáp án.
   Ta băm chỉ số sự kiện với một muối cố định -> `EV-<hex8>`: duy nhất (nhờ chỉ số), ổn
   định giữa các lần chạy (nhờ muối cố định), và KHÔNG lộ thứ tự (nhờ băm). Không dùng băm
   NỘI DUNG: luồng có các bản ghi NetFlow trùng khít từng byte nhưng khác nhãn (đo được
   58/684), băm nội dung sẽ đụng độ và gán nhầm nhãn.
2. **Đáp án sống NGOÀI luồng.** Mọi khoá nhãn được rút sang tệp sidecar `*.labels.json`
   theo ánh xạ `gt_id -> {nhãn}`. Sidecar KHÔNG bao giờ được `src/` đọc, không vào Redis,
   không vào prompt. Đây là cách giữ cho việc chấm điểm trung thực: hệ thống chạy mù, người
   chấm nối kết quả với đáp án sau.

Ta KHÔNG dựng lại `demo.json` từ CICIDS: tệp hiện tại là luồng người dùng đã chốt để demo
trước hội đồng, dựng lại sẽ đổi phân bổ. Ta chỉ ĐÓNG DẤU thêm một trường vào bản ghi sẵn có.
`build_demo_small.py` hoàn toàn tất định (không random, chỉ cắt lát theo bước) nên chạy lại
sau khi đóng dấu sẽ cho ĐÚNG tập con cũ, chỉ khác là đã có `gt_id`.

Chạy:  .venv/bin/python scripts/stamp_demo_ids.py
"""

import argparse
import hashlib
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Muối CỐ ĐỊNH: giữ `gt_id` ổn định giữa các lần đóng dấu, để bản ghi tracer của lượt chạy
# cũ vẫn nối được với sidecar mới. Đây KHÔNG phải bí mật bảo mật — chỉ là hằng số làm mờ
# thứ tự, nên để nguyên trong mã là đúng chỗ.
_SALT = b"sentinel-demo-eventid-v1"

# Khoá NHÃN — rút hết sang sidecar. Danh sách này phải là SIÊU TẬP của những gì
# `subscriber._is_dataset_label_key` coi là nhãn, cộng thêm các khoá mang đáp án gián tiếp.
_LABEL_PREFIXES = ("gt_", "zd_", "adv_", "gz_", "apt_", "wa_")
_LABEL_EXACT = frozenset({"expected_threat", "unified_source", "dataset_source", "label", "Label"})
# `gt_id` là KHOÁ NỐI, không phải nhãn -> không rút, không xoá khỏi sự kiện.
_KEEP_IN_EVENT = frozenset({"gt_id"})


def _is_label(key: str) -> bool:
    if key in _KEEP_IN_EVENT:
        return False
    return key in _LABEL_EXACT or key.startswith(_LABEL_PREFIXES)


# Độ rộng băm. 8 ký tự hex = 32 bit: với ~100k sự kiện, xác suất đụng độ sinh nhật là
# 1 - exp(-n²/2·2³²) ≈ 68% — và đã đụng thật ngay lần chạy đầu. 16 ký tự = 64 bit đưa
# xác suất về ~3e-10. Cái giá là 8 ký tự dài hơn trong một trường máy đọc: không đáng kể.
_ID_HEX = 16


def mint_event_id(index: int) -> str:
    """ID mờ, tất định, duy nhất theo chỉ số. Xem nguyên tắc (1) ở docstring module."""
    h = hashlib.sha256(_SALT + str(index).encode()).hexdigest()[:_ID_HEX]
    return f"EV-{h}"


def stamp(path: str, *, write: bool = True, remint: bool = False) -> tuple[int, str]:
    """Đóng dấu `gt_id` vào từng sự kiện của `path`, ghi sidecar nhãn cạnh nó.

    Trả (số sự kiện, đường dẫn sidecar). Idempotent: sự kiện đã có `gt_id` thì giữ nguyên,
    nên chạy lại nhiều lần không làm lệch khoá nối của các lượt chạy trước. `remint=True`
    cấp lại toàn bộ ID (cần khi bộ ID cũ hỏng — vd đụng độ do băm quá ngắn).
    """
    with open(path) as f:
        events = json.load(f)

    labels: dict[str, dict] = {}
    minted = 0
    for i, ev in enumerate(events):
        eid = None if remint else ev.get("gt_id")
        if not eid:
            eid = mint_event_id(i)
            ev["gt_id"] = eid
            minted += 1
        # Sidecar giữ BẢN SAO của nhãn; sự kiện vẫn giữ nhãn như cũ vì `_strip_dataset_labels`
        # ở subscriber mới là nơi chịu trách nhiệm tước chúng trước khi vào prompt. Ta không
        # đổi hành vi đó — chỉ thêm một bản sao ngoài luồng để chấm điểm.
        labels[eid] = {k: v for k, v in ev.items() if _is_label(k)}

    # KIỂM TRƯỚC KHI GHI. Bản đầu tiên của hàm này assert SAU khi ghi, nên lần chạy đầu đã
    # kịp ghi đè `demo.json` bằng bộ ID đụng độ rồi mới báo lỗi — đúng loại lỗi mà thứ tự
    # "validate → commit" sinh ra để chặn.
    ids = [e["gt_id"] for e in events]
    if len(set(ids)) != len(ids):
        dup = len(ids) - len(set(ids))
        raise SystemExit(
            f"[!] {os.path.basename(path)}: {dup} `gt_id` TRÙNG — khoá nối hỏng, KHÔNG ghi. "
            f"Chạy lại với --remint để cấp lại toàn bộ ID."
        )
    if len(labels) != len(events):
        raise SystemExit(f"[!] sidecar phủ {len(labels)}/{len(events)} sự kiện — KHÔNG ghi.")

    side = os.path.splitext(path)[0] + ".labels.json"
    if write:
        with open(path, "w") as f:
            json.dump(events, f, separators=(",", ":"))
        with open(side, "w") as f:
            json.dump(labels, f, separators=(",", ":"))

    print(f"[+] {os.path.basename(path)}: {len(events):,} sự kiện (đóng dấu mới {minted:,})")
    print(f"    sidecar -> {os.path.basename(side)}  ({len(labels):,} mục)")
    return len(events), side


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--files",
        nargs="*",
        default=["data/demo.json", "data/demo_small.json"],
        help="các luồng cần đóng dấu (mặc định: demo + demo_small)",
    )
    ap.add_argument("--dry-run", action="store_true", help="chỉ in, không ghi")
    ap.add_argument("--remint", action="store_true", help="cấp lại TOÀN BỘ gt_id (ghi đè)")
    args = ap.parse_args()

    for rel in args.files:
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            print(f"[!] bỏ qua (không tồn tại): {rel}")
            continue
        stamp(p, write=not args.dry_run, remint=args.remint)


if __name__ == "__main__":
    main()
