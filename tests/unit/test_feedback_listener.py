"""
Unit tests cho FeedbackListener — vòng phản hồi Tier-2 -> Tier-1 (dynamic rules).

Cô lập hoàn toàn: CONFIG_PATH + FileLock được monkeypatch sang file tạm,
KHÔNG đụng config/system_settings.yaml thật (vốn phải giữ dynamic_rules: []
sạch trước mỗi commit).
"""

import pytest  # type: ignore
import yaml  # type: ignore
from filelock import FileLock  # type: ignore

import src.tier1_filter.feedback_listener as fl


@pytest.fixture
def tmp_config(tmp_path, monkeypatch):
    cfg = tmp_path / "system_settings.yaml"
    cfg.write_text(yaml.dump({"tier1": {"dynamic_rules": []}}), encoding="utf-8")
    monkeypatch.setattr(fl, "CONFIG_PATH", str(cfg))
    monkeypatch.setattr(fl, "_lock", FileLock(str(cfg) + ".lock"))
    return cfg


def _rules(cfg):
    return yaml.safe_load(cfg.read_text())["tier1"]["dynamic_rules"]


class TestReceiveNewRule:
    def test_valid_rule_persisted_as_pending_approval(self, tmp_config):
        """Rule hợp lệ -> APPLIED, persist YAML với status PENDING_APPROVAL
        (state machine: PENDING_APPROVAL -> ACTIVE/REJECTED qua HITL)."""
        listener = fl.FeedbackListener()
        res = listener.receive_new_rule(
            field="Source IP",
            pattern="203.0.113.50",
            score=50,
            reason="Confirmed C2 beacon by LLM",
        )
        assert res["status"] == "APPLIED"
        rules = _rules(tmp_config)
        assert len(rules) == 1
        assert rules[0]["pattern"] == "203.0.113.50"
        assert rules[0]["status"] == "PENDING_APPROVAL"  # KHÔNG tự-ACTIVE
        assert listener.get_feedback_history()[0]["pattern"] == "203.0.113.50"

    def test_duplicate_rule_skipped(self, tmp_config):
        listener = fl.FeedbackListener()
        listener.receive_new_rule("Source IP", "203.0.113.50", score=50)
        res2 = listener.receive_new_rule("Source IP", "203.0.113.50", score=80)
        assert res2["status"] == "SKIPPED"
        assert len(_rules(tmp_config)) == 1  # không nhân bản

    def test_wildcard_rule_rejected_not_persisted(self, tmp_config):
        """Zero-Trust: rule wildcard chặn cả internet phải bị từ chối."""
        listener = fl.FeedbackListener()
        res = listener.receive_new_rule("Source IP", "*", score=50)
        assert res["status"] == "REJECTED"
        assert res["errors"]
        assert _rules(tmp_config) == []  # KHÔNG được ghi file

    def test_critical_infra_ip_rejected(self, tmp_config):
        """Self-DoS prevention: cấm rule nhắm vào IP hạ tầng (127.0.0.1...)."""
        listener = fl.FeedbackListener()
        res = listener.receive_new_rule("Source IP", "127.0.0.1", score=50)
        assert res["status"] == "REJECTED"
        assert _rules(tmp_config) == []

    def test_disallowed_field_rejected(self, tmp_config):
        listener = fl.FeedbackListener()
        res = listener.receive_new_rule("payload", "DROP TABLE", score=50)
        assert res["status"] == "REJECTED"
        assert _rules(tmp_config) == []


class TestBlockWhitelistMutualExclusion:
    """block ↔ whitelist LOẠI TRỪ LẪN NHAU: kích hoạt chặn 1 Source IP thì gỡ nó khỏi
    whitelist (nếu không whitelist ưu tiên cao nhất ở Tier-1 sẽ vô hiệu luật chặn)."""

    def _write(self, cfg, rules, whitelist):
        cfg.write_text(
            yaml.dump({"tier1": {"dynamic_rules": rules, "whitelist_ips": whitelist}}),
            encoding="utf-8",
        )

    def test_approve_source_ip_block_removes_from_whitelist(self, tmp_config):
        ip = "198.51.100.15"
        self._write(
            tmp_config,
            [{"field": "Source IP", "pattern": ip, "score": 100, "status": "PENDING_APPROVAL"}],
            ["127.0.0.1", ip],
        )
        listener = fl.FeedbackListener()
        assert listener.approve_rule(ip, "Source IP") is True
        cfg = yaml.safe_load(tmp_config.read_text())["tier1"]
        # Luật -> ACTIVE và IP KHÔNG còn trong whitelist.
        assert cfg["dynamic_rules"][0]["status"] == "ACTIVE"
        assert ip not in cfg["whitelist_ips"]
        assert "127.0.0.1" in cfg["whitelist_ips"]  # IP khác giữ nguyên

    def test_approve_non_source_ip_rule_keeps_whitelist(self, tmp_config):
        """Duyệt luật KHÔNG phải Source IP (vd URI) không đụng whitelist."""
        ip = "198.51.100.15"
        self._write(
            tmp_config,
            [{"field": "URI", "pattern": "/evil", "score": 50, "status": "PENDING_APPROVAL"}],
            [ip],
        )
        listener = fl.FeedbackListener()
        assert listener.approve_rule("/evil", "URI") is True
        cfg = yaml.safe_load(tmp_config.read_text())["tier1"]
        assert ip in cfg["whitelist_ips"]  # whitelist không bị đụng


class TestActiveRules:
    def test_get_active_filters_out_pending(self, tmp_config):
        """Chỉ rule status ACTIVE được nạp vào Tier-1; PENDING chờ HITL duyệt."""
        tmp_config.write_text(
            yaml.dump(
                {
                    "tier1": {
                        "dynamic_rules": [
                            {"field": "URI", "pattern": "/evil", "score": 50, "status": "ACTIVE"},
                            {
                                "field": "URI",
                                "pattern": "/maybe",
                                "score": 50,
                                "status": "PENDING_APPROVAL",
                            },
                            {"field": "URI", "pattern": "/no", "score": 50, "status": "REJECTED"},
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )
        listener = fl.FeedbackListener()
        active = listener.get_active_dynamic_rules()
        assert [r["pattern"] for r in active] == ["/evil"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
