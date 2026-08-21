"""Backpressure dùng chung cho MỌI producer đẩy log vào Redis Stream.

MỘT NGUỒN CHÂN LÝ: trước đây `scripts/demo.py` và `src/streaming/publisher.py` mỗi nơi
tự viết một kiểu — demo.py sửa sang đo `lag` trước, publisher.py bị bỏ sót và còn đo
`xlen`, nên tái hiện y nguyên lỗi cũ. Nay CẢ HAI đều gọi `consumer_group_lag()` ở đây,
không còn chỗ nào tự viết lại.

TẠI SAO KHÔNG DÙNG xlen: subscriber tiêu thụ bằng `xreadgroup` + `xack`, hai thao tác
này KHÔNG xoá entry khỏi stream — `xlen` chỉ giảm khi bị `maxlen` cắt bớt. Producer nào
chờ theo `xlen` sẽ thấy nó dính ~maxlen vĩnh viễn dù subscriber đã xử lý xong sạch, và
tự treo mình mãi mãi. `lag` của consumer-group (Redis 7+) mới trả lời đúng câu hỏi
"consumer còn tụt lại bao nhiêu entry chưa nhận".
"""

from collections.abc import Iterable
from typing import Any

# PHẢI khớp consumer group mà subscriber.py tạo — đo nhầm group thì lag luôn bằng 0.
GROUP_NAME = "sentinel_group"

# "Không biết còn tồn bao nhiêu" — KHÔNG phải "không tồn". Producer thấy giá trị này thì
# phải CHỜ, vì mọi ngưỡng backpressure đều nhỏ hơn nó.
LAG_UNKNOWN = 1 << 30


def consumer_group_lag(redis_client: Any, queues: Iterable[str], group: str = GROUP_NAME) -> int:
    """Tổng số entry đã vào các stream nhưng consumer-group CHƯA nhận.

    ── HỎNG THEO HƯỚNG NÀO KHI KHÔNG BIẾT (sửa 17/08/2026) ──────────────────────────
    Bản trước suy biến MỌI lỗi về 0, kèm lý lẽ "để backpressure không bao giờ làm hỏng
    luồng đẩy". Với một cái VAN, hỏng-mở là hỏng sai chiều: 0 nghĩa là "consumer theo kịp,
    cứ đẩy hết tốc lực" — đúng điều nguy hiểm nhất khi ta thực ra KHÔNG BIẾT gì.

    SỰ CỐ ĐO ĐƯỢC 17/08/2026. `run_demo.sh` bật subscriber rồi đẩy luồng ngay, trong khi
    subscriber cần ~8 giây nạp mô hình nhúng + FAISS + LightGBM trước khi tạo consumer
    group. Suốt 8 giây đó `xinfo_groups` ném lỗi (nhóm chưa tồn tại) -> hàm này trả 0 ->
    van mở toang -> producer xả tối đa tốc độ Redis vào stream `maxlen=10.000`. Kết quả:
    **91.500/496.885 sự kiện (18,4%) bị MAXLEN huỷ trước khi có ai đọc.**

    Trước đó phanh cứng `sleep(0.3)` của producer che mất lỗi này: 8 giây chỉ rò ~1.300 sự
    kiện, dưới `maxlen` nên không mất gì. Bỏ phanh là lỗi lộ ra ngay.

    ── VÌ SAO `lag` KHÔNG BAO GIỜ TỰ TỐ CÁO ĐƯỢC ────────────────────────────────────
    `lag` chỉ đếm entry CÒN NẰM TRONG stream mà nhóm chưa nhận. Khi MAXLEN cắt entry chưa
    đọc, Redis DỜI LUÔN `entries-read` của nhóm cho khớp, nên cả `lag` lẫn `entries-read`
    đều nhìn như "không mất gì". Thí nghiệm: đẩy 700 entry vào stream `maxlen=200`, không
    ai đọc -> `lag=200`, `entries-added=700`, và `xreadgroup` chỉ nhận được 200. 500 bản
    ghi biến mất không để lại dấu vết nào trong hai chỉ số đó.

    Hệ quả: `lag` KHÔNG BAO GIỜ vượt quá `maxlen`, nên nó chỉ dùng được như van chặn
    TRƯỚC khi tràn — và chỉ đúng khi consumer-group đã tồn tại. Đó là lý do nhánh "chưa có
    nhóm" phải trả `LAG_UNKNOWN` thay vì 0.
    """
    total = 0
    for q in queues:
        try:
            groups = redis_client.xinfo_groups(q)
        except Exception:
            # Stream chưa tồn tại -> chưa có gì để tiêu thụ, không cần hãm. Nhưng nếu
            # stream CÓ dữ liệu mà ta không đọc nổi thông tin nhóm thì phải chờ.
            if _stream_has_data(redis_client, q):
                return LAG_UNKNOWN
            continue

        matched = [g for g in groups if g.get("name") == group]
        if not matched:
            # Stream đã có entry nhưng CHƯA có consumer group: không ai đang đọc, và mỗi
            # entry đẩy thêm đều là ứng viên bị MAXLEN huỷ. Đây chính là cửa sổ khởi động.
            if _stream_has_data(redis_client, q):
                return LAG_UNKNOWN
            continue

        for g in matched:
            lag = g.get("lag")
            if lag is None:
                # Redis không tính được lag (đã có cắt xén xen giữa) -> coi như không biết.
                return LAG_UNKNOWN
            total += int(lag)
    return total


def _stream_has_data(redis_client: Any, queue: str) -> bool:
    """Stream có entry nào đang nằm chờ không. Lỗi -> coi như CÓ (chọn phía an toàn)."""
    try:
        return int(redis_client.xlen(queue)) > 0
    except Exception:
        return True
