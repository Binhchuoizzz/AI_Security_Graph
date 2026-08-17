"""Vệ sinh khâu DỰNG dữ liệu CSIC — tín hiệu tấn công phải đến từ payload, không từ vỏ.

Hai lỗi dựng dữ liệu đo được ngày 17/08/2026, cả hai đều bơm tín hiệu GIẢ vào phép đo:

1. `Destination Port` đóng cứng 8080 cho CẢ 36.000 bản ghi, benign lẫn tấn công. Tier-1
   coi 8080 là cổng bất thường -> mọi yêu cầu CSIC đều được cộng điểm rủi ro rồi leo thang
   lên Tier-2. Đo trên lượt chạy hôm đó: 68/90 lô Tier-2 là loại này, tất cả điểm Tier-1
   đúng 20, không chữ ký nào, và LLM buộc phải đoán T1571 "Non-Standard Port". Trong hàng
   đợi HITL có cả phiếu cho `/tienda1/imagenes/nuestratierra.jpg` — một lượt tải ảnh.

2. IP nguồn dùng một TOÁN TỬ BA NGÔI mà hai nhánh giống hệt nhau, nên benign và tấn công
   bốc từ CÙNG hồ 254 địa chỉ. Mỗi địa chỉ gánh ~142 sự kiện trộn lẫn -> danh tiếng IP
   nhiễm chéo, và mọi chỉ số tính theo IP mất nghĩa.

Test chạy trên HÀM DỰNG, không trên tệp đã dựng: tệp có thể cũ, hàm mới là nguồn sự thật.
"""

import importlib.util
import random
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / "scripts" / "build_csic_dataset.py"


@pytest.fixture(scope="module")
def builder():
    spec = importlib.util.spec_from_file_location("build_csic_dataset", _SRC)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _req(url="/tienda1/publico/productos.jsp", method="GET", body=""):
    return {"url": url, "method": method, "body": body, "headers": {"user-agent": "Mozilla/5.0"}}


def _events(builder, n=400):
    rnd = random.Random(7)
    return [builder.to_event(_req(), i % 2 == 0, i, rnd) for i in range(n)]


def test_csic_uses_standard_http_port(builder):
    """CSIC 2010 là HTTP cổng 80. Cổng lạ là TÍN HIỆU, không được phát cho toàn bộ corpus."""
    for ev in _events(builder, 50):
        assert ev["Destination Port"] == 80, (
            "cổng phi chuẩn dán lên mọi bản ghi -> Tier-1 leo thang cả lưu lượng lành "
            "và LLM bị ép quy kết T1571 do khâu dựng dữ liệu bịa ra"
        )


def test_benign_and_attack_never_share_a_source_ip(builder):
    """Hồ IP của benign và tấn công phải RỜI NHAU.

    Chung hồ thì chặn một IP vì payload độc của nó cũng chặn luôn lưu lượng lành của chính
    địa chỉ đó — mọi chỉ số theo IP (precision lệnh chặn, danh tiếng) đều nhiễm chéo.
    """
    evs = _events(builder, 600)
    benign = {e["Source IP"] for e in evs if not e["_label"]["expected_threat"]}
    attack = {e["Source IP"] for e in evs if e["_label"]["expected_threat"]}
    assert benign and attack
    assert not (benign & attack), f"{len(benign & attack)} địa chỉ dùng chung cho cả hai nhãn"


def test_benign_clients_are_spread_wide_enough_to_not_look_like_a_flood(builder):
    """Luật tần suất Tier-1 bắn từ sự kiện thứ BA của cùng một IP.

    Hồ IP hẹp biến lưu lượng LÀNH thành "flood" thuần tuý do khâu dựng dữ liệu: 18.000 yêu
    cầu benign chia cho 254 địa chỉ là ~71 yêu cầu/IP, nên gần như mọi địa chỉ đều vượt
    ngưỡng và leo thang lên Tier-2. Đo lượt chạy 17/08/2026: 68/90 lô Tier-2 đúng là loại
    này, và chúng chiếm trọn hàng đợi HITL.

    Ngưỡng dưới đây tính theo hình dạng lưu lượng thật: hàng nghìn client lành riêng biệt.
    """
    evs = _events(builder, 2000)
    benign = [e["Source IP"] for e in evs if not e["_label"]["expected_threat"]]
    unique = len(set(benign))
    assert unique / len(benign) > 0.9, (
        f"chỉ {unique} địa chỉ cho {len(benign)} yêu cầu lành — hồ quá hẹp, "
        "Tier-1 sẽ chấm lưu lượng lành là tần suất bất thường"
    )


def test_attackers_stay_concentrated_so_reputation_can_work(builder):
    """Ngược lại với benign: kẻ tấn công PHẢI dồn vào ít địa chỉ.

    Trải mỏng kẻ tấn công thì trí nhớ danh tiếng không bao giờ tích đủ điểm, và cơ chế
    chặn-theo-IP mất luôn thứ để đo.
    """
    evs = _events(builder, 2000)
    attack = [e["Source IP"] for e in evs if e["_label"]["expected_threat"]]
    assert len(set(attack)) < len(attack) / 4, "IP tấn công trải quá mỏng để đo danh tiếng"


def test_attack_signal_lives_in_the_payload_not_the_envelope(builder):
    """Bản ghi tấn công và bản ghi lành chỉ được khác nhau ở NỘI DUNG.

    Nếu vỏ bọc (cổng, service, protocol) khác nhau theo nhãn thì bộ phân loại học được
    nhãn từ vỏ — rò rỉ nhãn, và mọi con số sau đó là ảo.
    """
    rnd = random.Random(11)
    envelope = ("Destination Port", "Protocol", "service")
    a = builder.to_event(_req(), True, 0, rnd)
    b = builder.to_event(_req(), False, 1, rnd)
    for k in envelope:
        assert a[k] == b[k], f"trường vỏ {k!r} khác nhau theo nhãn -> rò rỉ nhãn"
