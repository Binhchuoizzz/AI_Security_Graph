"""
Unit test cho src/agent/token_monitor.py — Quan sát ngân sách ngữ cảnh LLM.

Phủ 4 hành vi cốt lõi:
  - estimate_tokens: ước lượng chars/3.5
  - preflight_check: cảnh báo + đếm khi prompt sát/ vượt trần ngân sách input
  - record_usage: ghi token THẬT (prompt/completion) -> mean/p95/max/utilization
  - get_stats: đọc lại số liệu đã bền vững; record_usage(None) là no-op an toàn

Test CÔ LẬP: ghi vào file tạm (monkeypatch STATS_PATH) và reset _state để KHÔNG
đụng config/llm_token_stats.json thật.
"""

import os
import sys
from types import SimpleNamespace

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.agent import token_monitor  # noqa: E402


@pytest.fixture(autouse=True)
def isolate_state(tmp_path, monkeypatch):
    """Cô lập STATS_PATH + reset _state trước mỗi test (không đụng file thật)."""
    monkeypatch.setattr(token_monitor, "STATS_PATH", str(tmp_path / "stats.json"))
    # Dùng _new_state() (nguồn schema duy nhất) — KHÔNG chép tay các khoá, nếu không
    # mỗi lần module thêm khoá là toàn bộ test vỡ bằng KeyError.
    monkeypatch.setattr(token_monitor, "_state", token_monitor._new_state())
    yield


def test_estimate_tokens_uses_default_ratio_before_calibration():
    # Chưa có mẫu thật -> dùng hằng khởi điểm _CHARS_PER_TOKEN (4.0): 40/4.0 = 10 token
    msgs = [{"role": "user", "content": "x" * 40}]
    assert token_monitor.estimate_tokens(msgs) == 10
    # Nhiều message cộng dồn: 16/4.0 = 4
    msgs2 = [{"role": "system", "content": "a" * 8}, {"role": "user", "content": "b" * 8}]
    assert token_monitor.estimate_tokens(msgs2) == 4


def test_estimate_self_calibrates_to_real_token_ratio():
    """CONTEXT GUARD phải bám tokenizer THẬT, không bám hằng số đoán trước.

    Bug thật đã gặp trong demo 100k: hằng 3.5 char/token thổi phồng ước lượng >21% nên
    báo động 'sát trần' 33/34 call, dù prompt thật (max 5.909) chưa từng chạm ngưỡng
    6.923 và server còn 16.384 ctx. Sau hiệu chuẩn, ước lượng phải khớp số thật.
    """

    class _Usage:
        prompt_tokens = 1000
        completion_tokens = 10

    msgs = [{"role": "user", "content": "x" * 4200}]  # 4200 ký tự <-> 1000 token => 4.2
    for _ in range(token_monitor._MIN_CALIB_SAMPLES + 5):
        token_monitor.preflight_check(msgs, max_output_tokens=256)
        token_monitor.record_usage(_Usage())

    stats = token_monitor.get_stats()  # đọc từ STATS_PATH đã _persist()
    assert stats is not None, "preflight/record_usage phải đã ghi được STATS_PATH"
    assert stats["chars_per_token_calibrated"] is True
    assert token_monitor._ratio() == pytest.approx(4.2, abs=0.05)
    # Ước lượng nay khớp token THẬT (sai số < 2%), hết báo động giả.
    assert token_monitor.estimate_tokens(msgs) == pytest.approx(1000, rel=0.02)


def test_estimate_tokens_empty():
    assert token_monitor.estimate_tokens([]) == 0
    assert token_monitor.estimate_tokens([{"role": "user"}]) == 0  # thiếu 'content'


def test_preflight_small_prompt_no_warning():
    before = token_monitor._state["overflow_warnings"]
    est = token_monitor.preflight_check(
        [{"role": "user", "content": "ping"}], max_output_tokens=512
    )
    assert est >= 0
    assert token_monitor._state["overflow_warnings"] == before  # KHÔNG cảnh báo


def test_preflight_huge_prompt_warns_and_counts():
    # Ngân sách input = N_CTX - max_output. Tạo prompt vượt 90% để kích hoạt cảnh báo.
    budget = max(token_monitor.N_CTX - 256, 1)
    huge_chars = int(budget * token_monitor._CHARS_PER_TOKEN * 1.5)  # chắc chắn > 90%
    msgs = [{"role": "user", "content": "x" * huge_chars}]
    token_monitor.preflight_check(msgs, max_output_tokens=256)
    assert token_monitor._state["overflow_warnings"] == 1
    # Đã bền vững ra file (đếm cảnh báo)
    stats = token_monitor.get_stats()
    assert stats is not None
    assert stats["overflow_warnings"] == 1


def test_record_usage_updates_stats():
    token_monitor.record_usage(SimpleNamespace(prompt_tokens=100, completion_tokens=20))
    token_monitor.record_usage(SimpleNamespace(prompt_tokens=300, completion_tokens=40))
    stats = token_monitor.get_stats()
    assert stats is not None
    assert stats["calls"] == 2
    assert stats["prompt_tokens_mean"] == 200.0  # (100+300)/2
    assert stats["prompt_tokens_max"] == 300
    assert stats["completion_tokens_mean"] == 30.0  # (20+40)/2
    assert stats["n_ctx"] == token_monitor.N_CTX
    # utilization_pct_max = 100 * 300 / N_CTX
    assert stats["utilization_pct_max"] == round(100 * 300 / token_monitor.N_CTX, 1)


def test_record_usage_none_is_noop():
    token_monitor.record_usage(None)
    token_monitor.record_usage(SimpleNamespace(prompt_tokens=0, completion_tokens=0))
    assert token_monitor._state["calls"] == 0  # cả hai đều bị bỏ qua an toàn


def test_persist_never_crashes_on_bad_path(monkeypatch):
    # Ghi vào đường dẫn không thể tạo -> nuốt lỗi êm, KHÔNG ném exception (không làm hỏng luồng LLM)
    monkeypatch.setattr(token_monitor, "STATS_PATH", "/nonexistent_dir/xx/stats.json")
    token_monitor.record_usage(SimpleNamespace(prompt_tokens=50, completion_tokens=5))
    assert token_monitor._state["calls"] == 1  # state vẫn cập nhật dù ghi file thất bại
