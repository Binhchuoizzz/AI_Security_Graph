"""Van backpressure phải hỏng theo hướng ĐÓNG, không phải hướng MỞ.

SỰ CỐ ĐO ĐƯỢC 17/08/2026. `run_demo.sh` bật subscriber rồi đẩy luồng ngay, trong khi
subscriber cần ~8 giây nạp mô hình nhúng + FAISS + LightGBM mới tạo được consumer group.
Suốt cửa sổ đó `xinfo_groups` ném lỗi, và bản cũ suy biến MỌI lỗi về `0` với lý lẽ "để
backpressure không bao giờ làm hỏng luồng đẩy". Nhưng `0` có nghĩa là "consumer theo kịp,
cứ đẩy hết tốc lực" — nên van mở toang đúng lúc không có ai đọc:

    91.500 / 496.885 sự kiện (18,4%) bị `MAXLEN=10.000` huỷ trước khi ai kịp đọc.

Không một dòng lỗi nào. Và không chỉ số Redis nào tố cáo được: khi MAXLEN cắt entry chưa
đọc, Redis DỜI LUÔN `entries-read` của nhóm cho khớp, nên `lag` về 0 và
`entries-added == entries-read` — nhìn y hệt "đã giao đủ".
"""

from src.streaming import backpressure as bp


class _FakeRedis:
    """Redis giả đủ dùng cho `consumer_group_lag`: xinfo_groups + xlen."""

    def __init__(self, groups: dict, lengths: dict, raise_on: tuple = ()):
        self._groups = groups
        self._lengths = lengths
        self._raise_on = raise_on

    def xinfo_groups(self, q):
        if q in self._raise_on:
            raise RuntimeError("ERR no such key")
        return self._groups.get(q, [])

    def xlen(self, q):
        return self._lengths.get(q, 0)


QS = ("queue_firewall", "queue_waf")


def test_lag_is_summed_when_group_exists():
    r = _FakeRedis(
        groups={
            "queue_firewall": [{"name": "sentinel_group", "lag": 120}],
            "queue_waf": [{"name": "sentinel_group", "lag": 30}],
        },
        lengths={"queue_firewall": 500, "queue_waf": 500},
    )
    assert bp.consumer_group_lag(r, QS) == 150


def test_stream_with_data_but_no_group_blocks_the_producer():
    """CỬA SỔ KHỞI ĐỘNG — đây là ca đã gây mất 18,4% luồng.

    Stream đã có log, nhưng subscriber chưa tạo nhóm nên không ai đọc. Mỗi entry đẩy thêm
    đều là ứng viên bị MAXLEN huỷ. Van PHẢI đóng.
    """
    r = _FakeRedis(groups={"queue_firewall": []}, lengths={"queue_firewall": 4_000})
    assert bp.consumer_group_lag(r, ("queue_firewall",)) >= bp.LAG_UNKNOWN


def test_missing_stream_entirely_does_not_block():
    """Stream chưa tồn tại và chưa có gì trong đó -> không có gì để mất, không hãm.

    Thiếu nhánh này thì lượt chạy sạch không bao giờ khởi động được: producer sẽ chờ một
    consumer-group trên một stream mà chính nó chưa tạo ra.
    """
    r = _FakeRedis(groups={}, lengths={}, raise_on=("queue_firewall", "queue_waf"))
    assert bp.consumer_group_lag(r, QS) == 0


def test_unknown_lag_value_blocks_instead_of_reading_as_zero():
    """`lag=None` nghĩa là Redis KHÔNG TÍNH ĐƯỢC (đã có cắt xén xen giữa) — không phải 0.

    Bản cũ rơi về `xpending` (số entry đã giao mà chưa ack), một đại lượng KHÁC HẲN và
    thường xấp xỉ 0 khi consumer ack đều -> van mở đúng lúc dữ liệu đang bị cắt mất.
    """
    r = _FakeRedis(
        groups={"queue_firewall": [{"name": "sentinel_group", "lag": None}]},
        lengths={"queue_firewall": 10_000},
    )
    assert bp.consumer_group_lag(r, ("queue_firewall",)) >= bp.LAG_UNKNOWN


def test_wrong_group_name_is_not_silently_counted_as_caught_up():
    """Đo nhầm tên nhóm mà trả 0 thì van mở vĩnh viễn — phải đóng."""
    r = _FakeRedis(
        groups={"queue_firewall": [{"name": "some_other_group", "lag": 0}]},
        lengths={"queue_firewall": 7_000},
    )
    assert bp.consumer_group_lag(r, ("queue_firewall",)) >= bp.LAG_UNKNOWN


def test_unknown_beats_every_configured_threshold():
    """Bất biến: ngưỡng backpressure nào cũng phải NHỎ HƠN `LAG_UNKNOWN`.

    Nếu ai đó nâng `UNIFIED_STREAM_MAX_LAG` lên quá tay, van "không biết" phải vẫn đóng.
    """
    assert bp.LAG_UNKNOWN > 10_000_000
