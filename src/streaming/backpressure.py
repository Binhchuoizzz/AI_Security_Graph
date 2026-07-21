"""Backpressure dùng chung cho MỌI producer đẩy log vào Redis Stream.

MỘT NGUỒN CHÂN LÝ: trước đây `scripts/demo.py` và `src/streaming/publisher.py` mỗi nơi
tự viết một kiểu — demo.py đã sửa sang đo `lag`, publisher.py thì BỎ SÓT và vẫn đo
`xlen`, nên tái hiện y nguyên lỗi cũ. Gom về đây để không còn chỗ nào lệch.

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


def consumer_group_lag(redis_client: Any, queues: Iterable[str], group: str = GROUP_NAME) -> int:
    """Tổng số entry đã vào các stream nhưng consumer-group CHƯA nhận.

    Mọi lỗi (stream chưa tồn tại, Redis cũ không có trường `lag`) đều suy biến an toàn về
    "không tụt hậu" để backpressure KHÔNG bao giờ làm hỏng luồng đẩy.
    """
    total = 0
    for q in queues:
        try:
            groups = redis_client.xinfo_groups(q)
        except Exception:
            continue  # stream chưa tồn tại / lỗi -> bỏ qua queue này
        for g in groups:
            if g.get("name") != group:
                continue
            lag = g.get("lag")
            if lag is None:
                # Redis cũ / lag không xác định -> fallback: số entry đang chờ ack.
                try:
                    lag = int((redis_client.xpending(q, group) or {}).get("pending", 0))
                except Exception:
                    lag = 0
            total += int(lag or 0)
    return total
