"""
Các component giao diện dùng lại cho Streamlit Dashboard.
NÂNG CẤP PREMIUM: Thiết kế chuẩn SOC/SIEM Glassmorphism hiện đại.
"""

import html as html_lib
import json
import re
from datetime import datetime

import pandas as pd  # type: ignore
import streamlit as st  # type: ignore


def is_valid_ip(ip_str: str) -> bool:
    """Kiểm tra chuỗi IP hợp lệ (IPv4 hoặc IPv6)."""
    ip_str = ip_str.strip()
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$"
    if re.match(ipv4_pattern, ip_str):
        parts = ip_str.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return bool(re.match(ipv6_pattern, ip_str))


def _derive_tier1_attack_type(reasons: list[str]) -> str:
    """Suy ra nhãn 'kiểu tấn công' ngắn gọn từ danh sách lý do Tier-1 (chữ ký/thống kê).

    Dùng cho thẻ Whitelist: IP whitelist vẫn được phân tích nên phải nêu được nó ĐANG
    làm kỹ thuật gì, dù không bị chặn. Trả nhãn tổng hợp (nối bằng ' + ').
    """
    labels: list[str] = []
    joined = " ".join(reasons)
    # WAF: "WAF: Phát hiện <loại> trong '<field>'"
    for m in re.finditer(r"WAF:\s*Phát hiện\s*([^']+?)\s*trong", joined):
        lbl = m.group(1).strip()
        if lbl and lbl not in labels:
            labels.append(lbl)
    if "Prompt Injection Pattern" in joined and "Prompt Injection" not in labels:
        labels.append("Prompt Injection")
    if "Jailbreak Pattern" in joined and "Jailbreak / Bypass" not in labels:
        labels.append("Jailbreak / Bypass")
    if ("Zero-day" in joined or "dị biệt thống kê" in joined) and (
        "Bất thường thống kê (nghi Zero-day)" not in labels
    ):
        labels.append("Bất thường thống kê (nghi Zero-day)")
    if "cổng nhạy cảm" in joined and "Truy cập cổng nhạy cảm" not in labels:
        labels.append("Truy cập cổng nhạy cảm")
    if "APT chain" in joined and "Chuỗi APT đa ngày" not in labels:
        labels.append("Chuỗi APT đa ngày")
    if not labels:
        return (
            "Không có dấu hiệu tấn công (truy cập thường)"
            if not reasons
            else "Hoạt động đáng chú ý"
        )
    return " + ".join(labels)


def render_alert_card(alert, is_l3_manager=False, on_whitelist=None, on_block=None, card_id=""):
    """Hiển thị một cảnh báo bảo mật từ audit_trail với giao diện SOC Premium."""
    timestamp = alert.get("timestamp", "")
    try:
        dt = datetime.fromisoformat(timestamp)
        formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        formatted_time = html_lib.escape(str(timestamp))

    action = str(alert.get("action", "UNKNOWN")).upper()
    target = html_lib.escape(str(alert.get("target", "N/A")))
    raw_reason = str(alert.get("reason", "N/A"))

    # ── Thẻ RIÊNG cho truy cập được WHITELIST cho qua ──────────────────────────
    # IP whitelist VẪN được Tier-1 phân tích đầy đủ (kiểu tấn công + suy luận) để
    # analyst QUAN SÁT — hiển thị bằng thẻ XANH "cho qua". Khác thẻ tấn công ở chỗ:
    # đã đặc cách nên KHÔNG bị chặn / không escalate LLM / không HITL. Nhờ vậy lần
    # chạy thứ 2 vẫn thấy được hành vi của IP whitelist thay vì bị nuốt lặng.
    if action == "WHITELIST":
        # Lấy phân tích Tier-1 từ raw_log (tier1_reasons/score) — nguồn "kiểu tấn công + suy luận".
        _wl_raw = alert.get("raw_log") if isinstance(alert, dict) else None
        _wl_reasons: list[str] = []
        _wl_score = None
        if _wl_raw:
            try:
                _wl_obj = json.loads(_wl_raw)
                _wl_reasons = [str(x) for x in (_wl_obj.get("tier1_reasons") or [])]
                _wl_score = _wl_obj.get("tier1_score")
            except Exception:
                _wl_reasons = []
        attack_type = _derive_tier1_attack_type(_wl_reasons)
        score_txt = f" · điểm Tier-1 {_wl_score}" if _wl_score is not None else ""

        reasons_html = (
            "".join(
                f'<li style="margin-bottom:3px;">{html_lib.escape(r)}</li>' for r in _wl_reasons
            )
            or '<li style="color:#95de64;">Không có dấu hiệu tấn công — truy cập thường.</li>'
        )

        wl_html = (
            '<div class="soc-card" style="border-left:4px solid #52c41a;'
            'background:rgba(82,196,26,0.06);">'
            '<div class="soc-card-header">'
            '<h4 class="soc-card-title">✅ [WHITELIST] Truy cập được CHO QUA (không chặn)</h4>'
            '<span class="soc-badge" style="background:rgba(82,196,26,0.2);color:#95de64;'
            "border:1px solid rgba(82,196,26,0.4);font-size:0.75rem;padding:2px 8px;"
            'border-radius:4px;margin-left:8px;">🟢 Tier-1 Filter</span>'
            f'<span class="soc-timestamp">{formatted_time}</span>'
            "</div>"
            '<div class="soc-detail-row">'
            '<span class="soc-label">IP nguồn:</span>'
            f'<span class="soc-value-code">{target}</span>'
            "</div>"
            '<div class="soc-detail-row">'
            '<span class="soc-label">Kiểu phát hiện (Tier-1):</span>'
            f'<span class="soc-value-code" style="color:#ffa940;">{html_lib.escape(attack_type)}</span>'
            f'<span style="color:#8c8c8c;font-size:0.8rem;">{html_lib.escape(score_txt)}</span>'
            "</div>"
            '<div class="soc-reasoning-box" style="margin-top:8px;">'
            '<div class="soc-reasoning-title">🔎 Suy luận Tier-1 (để giám sát, KHÔNG dùng LLM):</div>'
            f'<ul style="margin:6px 0 0 18px;font-size:0.85rem;color:#d9d9d9;">{reasons_html}</ul>'
            "</div>"
            '<div class="soc-detail-row" style="margin-top:8px;">'
            '<span class="soc-badge" style="background:rgba(82,196,26,0.15);'
            'color:#95de64;border:1px solid rgba(82,196,26,0.35);">'
            "✅ WHITELIST · đặc cách CHO QUA — không chặn / không escalate</span>"
            "</div>"
            "</div>"
        )
        st.markdown("".join(line.strip() for line in wl_html.split("\n")), unsafe_allow_html=True)
        with st.expander("🔍 Xem LOG THÔ (Raw Flow từ IP Whitelist)", expanded=False):
            if _wl_raw:
                try:
                    st.json(json.loads(_wl_raw))
                except Exception:
                    st.code(str(_wl_raw))
            else:
                st.caption("Không có log thô đính kèm.")
        return

    # Bóc tách Regex từ chuỗi Reason
    mitre_tech = "N/A"
    confidence = "Chưa rõ"

    # Lấy toàn bộ nội dung trong [MITRE: ...] bằng cách split hoặc regex không tham lam
    # Vì mitre_technique có thể chứa [Tự suy luận] (ngoặc vuông lồng nhau), regex sẽ hơi khác
    mitre_match = re.search(
        r"\[MITRE:\s*(.*?)(?:\]\s*\[Độ tin cậy|\]\s*$)", raw_reason, re.IGNORECASE
    )
    if mitre_match:
        mitre_tech = mitre_match.group(1).strip()
        # Đảm bảo xoá ngoặc vuông thừa ở cuối nếu regex chưa bắt hết
        if mitre_tech.endswith("]"):
            mitre_tech = mitre_tech[:-1].strip()
    elif t_match := re.search(r"(T\d{4}(?:\.\d{3})?)", raw_reason):
        mitre_tech = t_match.group(1)

    conf_match = re.search(
        r"(?:Confidence|Độ\s+tin\s+cậy):\s*([01]?\.\d+|1(?:\.0)?|\d+%)", raw_reason, re.IGNORECASE
    )
    if conf_match:
        try:
            val_str = conf_match.group(1)
            if val_str.endswith("%"):
                confidence = val_str
            else:
                val = float(val_str)
                confidence = f"{val * 100:.0f}%"
        except ValueError:
            pass

    # Xử lý chống Stored XSS cho các biến trích xuất động
    mitre_tech = html_lib.escape(mitre_tech)
    confidence = html_lib.escape(confidence)

    # Phân cấp mức độ nghiêm trọng (Severity) dựa trên Risk Score & Action
    severity_level = "INFO"
    css_class = "severity-info"
    icon = "ℹ️"

    if action == "BLOCK_IP" or action == "QUARANTINE":
        severity_level = "CRITICAL"
        css_class = "severity-critical"
        icon = "🛑"
    elif action == "ALERT":
        severity_level = "HIGH"
        css_class = "severity-high"
        icon = "⚠️"
    elif action == "AWAIT_HITL":
        severity_level = "MEDIUM"
        css_class = "severity-medium"
        icon = "🧑‍💻"

    # Việt hóa hành động
    action_translations = {
        "BLOCK_IP": "CHẶN IP (BLOCK)",
        "QUARANTINE": "CÁCH LY (QUARANTINE)",
        "ALERT": "CẢNH BÁO (ALERT)",
        "AWAIT_HITL": "ĐỀ XUẤT CHẶN (AWAIT_HITL)",
        "LOG": "GHI LOG (LOG)",
    }
    action_display = action_translations.get(action, action)

    # Kiểm tra xem AI có tự suy luận không
    is_self_inferred = "Tự suy luận" in raw_reason
    inference_badge = ""
    if is_self_inferred:
        inference_badge = '<span class="soc-badge" style="background:rgba(250, 173, 20, 0.15); color:#faad14; border:1px solid rgba(250, 173, 20, 0.35); margin-left:4px;">🤖 Tự Suy Đoán</span>'

    # Làm sạch chuỗi lý do phân tích (loại bỏ các thẻ tag [MITRE...] để hiển thị text sạch)
    clean_reason = html_lib.escape(raw_reason)
    clean_reason = re.sub(
        r"\[MITRE:\s*(.*?)(?:\]\s*\[Độ tin cậy|\]\s*$)", "", clean_reason, flags=re.IGNORECASE
    )
    clean_reason = re.sub(r"\[MITRE:.*?\]", "", clean_reason, flags=re.IGNORECASE)  # fallback
    clean_reason = re.sub(r"\[(?:Confidence|Độ\s+tin\s+cậy):\s*[^\]]*\]", "", clean_reason).strip()

    # Xoá ngoặc vuông đóng lẻ tẻ do regex không tham lam để lại
    if clean_reason.startswith("]"):
        clean_reason = clean_reason[1:].strip()

    # Phân nguồn phán quyết: Tier-1 (rule) / Tier-2 Cổng ML / Tier-2 LLM.
    # LƯU Ý detect theo MARKER đặc thù, KHÔNG dùng chữ "Tier-2"/"ML" trần — vì chuỗi
    # Tier-2 giờ xuất hiện ở cả nhánh LLM. Giữ "ML Tier 2" để nhận bản ghi CŨ trong DB.
    is_tier1 = "Tier-1" in raw_reason or "whitelist" in raw_reason.lower()
    is_ml_gate = (
        "Cổng ML" in raw_reason or "ML Tier 2" in raw_reason or "Decision Tree" in raw_reason
    )

    if is_tier1:
        tier_badge = (
            '<span class="soc-badge" style="background:rgba(82, 196, 26, 0.2);color:#95de64;'
            "border:1px solid rgba(82, 196, 26, 0.4);font-size:0.75rem;padding:2px 8px;"
            'border-radius:4px;margin-left:8px;">🟢 Tier-1 Filter</span>'
        )
        reasoning_title = "⚡ Lập luận tĩnh (Tier-1 Rule/Filter):"
        mitre_section_text = "🎯 Ánh xạ: Phân tích ban đầu từ Log thô"
    elif is_ml_gate:
        tier_badge = (
            '<span class="soc-badge" style="background:rgba(250, 173, 20, 0.2);color:#faad14;'
            "border:1px solid rgba(250, 173, 20, 0.4);font-size:0.75rem;padding:2px 8px;"
            'border-radius:4px;margin-left:8px;">⚡ Tier-2 · Cổng ML</span>'
        )
        reasoning_title = "⚡ Lập luận của Cổng ML Tier-2 (Decision Tree):"
        mitre_section_text = f"🎯 Phân loại MITRE ATT&CK: <code>{mitre_tech}</code>"
        if mitre_tech == "N/A":
            mitre_section_text = "🎯 Phân loại MITRE ATT&CK: <code>T1190 - Exploit Public-Facing Application</code> (Suy luận tự động)"
    else:
        tier_badge = (
            '<span class="soc-badge" style="background:rgba(24,144,255,0.2);color:#69c0ff;'
            "border:1px solid rgba(24,144,255,0.4);font-size:0.75rem;padding:2px 8px;"
            'border-radius:4px;margin-left:8px;">🧠 Tier-2 · LLM Agent</span>'
        )
        reasoning_title = "🤖 Lập luận của Tác tử LLM (Agentic Reasoning):"
        mitre_section_text = f"🎯 Phân loại MITRE ATT&CK: <code>{mitre_tech}</code>"
        if mitre_tech == "N/A":
            mitre_section_text = "🎯 Phân loại MITRE ATT&CK: <code>T1190 - Exploit Public-Facing Application</code> (Suy luận)"

    # Thiết lập playbook ứng phó NIST
    nist_playbook_text = (
        "🛡️ NIST Incident Response Playbook: Thực hiện ghi log và giám sát hành vi liên tục."
    )
    if severity_level == "CRITICAL":
        nist_playbook_text = "🛡️ NIST Incident Response Playbook (Section 3.2.1): Thực hiện ngăn chặn khẩn cấp (Containment) - Chặn IP nguồn tại Firewall để cô lập vùng tấn công."
    elif severity_level == "HIGH":
        nist_playbook_text = "🛡️ NIST Incident Response Playbook (Section 3.2.2): Cảnh báo khẩn cấp tới L1/L3 SOC Analyst, đưa IP vào danh sách theo dõi đặc biệt."
    elif severity_level == "MEDIUM":
        nist_playbook_text = "🛡️ NIST Incident Response Playbook (Section 3.2.3): Yêu cầu phê duyệt từ L3 Manager (Human-in-the-Loop) để kích hoạt luật chặn tự động."

    # Render HTML Card
    html_content = (
        f'<div class="soc-card {css_class}">'
        f'    <div class="soc-card-header">'
        f'        <h4 class="soc-card-title">{icon} [{severity_level}] {action_display}</h4>'
        f"        {tier_badge}"
        f'        <span class="soc-timestamp">{formatted_time}</span>'
        f"    </div>"
        f'    <div class="soc-detail-row">'
        f'        <span class="soc-label">IP Mục tiêu:</span>'
        f'        <span class="soc-value-code">{target}</span>'
        f"    </div>"
        f'    <div class="soc-detail-row">'
        f'        <span class="soc-label">Ngữ cảnh:</span>'
        f'        <span class="soc-badge soc-mitre-badge">MITRE: {mitre_tech}</span>'
        f'        <span class="soc-badge soc-conf-badge">Độ tin cậy: {confidence}</span>'
        f"        {inference_badge}"
        f"    </div>"
        f'    <div class="soc-reasoning-box">'
        f'        <div class="soc-reasoning-title">{reasoning_title}</div>'
        f'        <div style="margin-bottom: 8px;">{clean_reason}</div>'
        f'        <div class="soc-reasoning-section" style="color: #D3ADF7;">{mitre_section_text}</div>'
        f'        <div style="color: #98FB98; margin-top: 4px; font-size: 0.85rem; font-weight: 500;">{nist_playbook_text}</div>'
        f"    </div>"
        f"</div>"
    )

    # Nén HTML để tránh khoảng trắng dọc của Streamlit
    clean_html = "".join([line.strip() for line in html_content.split("\n")])
    st.markdown(clean_html, unsafe_allow_html=True)

    # Nút Whitelist và Block IP dành cho mọi alert có target là IP hợp lệ
    cleaned_target = target.strip()
    if is_valid_ip(cleaned_target):
        st.write("")
        col_btn1, col_btn2 = st.columns([1, 4])
        with col_btn1:
            if on_whitelist:
                # Nếu có truyền callback, hiển thị nút Whitelist
                if is_l3_manager:
                    if st.button(
                        f"🛡️ Whitelist IP: {cleaned_target}",
                        key=f"wl_btn_{cleaned_target}_{timestamp}_{card_id}",
                    ):
                        on_whitelist(cleaned_target)
                        st.success(f"IP {cleaned_target} đã được thêm vào Whitelist thành công!")
                        st.rerun()
                else:
                    st.button(
                        f"🛡️ Whitelist IP: {cleaned_target}",
                        key=f"wl_btn_dis_{cleaned_target}_{timestamp}_{card_id}",
                        disabled=True,
                        help="💡 Yêu cầu vai trò L3 Manager để whitelist IP này.",
                    )
        with col_btn2:
            if on_block and action != "BLOCK_IP":
                if is_l3_manager:
                    if st.button(
                        f"🛑 Block IP: {cleaned_target}",
                        key=f"blk_btn_{cleaned_target}_{timestamp}_{card_id}",
                    ):
                        on_block(cleaned_target)
                        st.success(f"IP {cleaned_target} đã được thêm vào Blocklist thành công!")
                        st.rerun()
                else:
                    st.button(
                        f"🛑 Block IP: {cleaned_target}",
                        key=f"blk_btn_dis_{cleaned_target}_{timestamp}_{card_id}",
                        disabled=True,
                        help="💡 Yêu cầu vai trò L3 Manager để Block IP này.",
                    )

    # LOG THÔ ĐẦU VÀO (đặc trưng luồng đã loại nhãn) — chính là dữ liệu đã đưa vào
    # Tier-1/LLM, KHÔNG phải bản ghi quyết định. Minh bạch "cái gì đã vào hệ thống".

    # Tạo tiêu đề động cho Expander chứa Log thô
    mitre_display_title = mitre_tech if mitre_tech != "N/A" else "Không xác định"
    expander_title = f"🔍 Xem LOG THÔ ĐẶC TRƯNG (Minh chứng cho {mitre_display_title})"

    with st.expander(expander_title, expanded=False):
        st.caption(
            "ℹ️ Đây là **log đặc trưng tiêu biểu** nhất được rút trích ra từ toàn bộ quá trình "
            f"của IP {cleaned_target}. Hệ thống chỉ lưu log đại diện này làm bằng chứng kỹ thuật gốc "
            "nhằm tiết kiệm DB. Đã LOẠI nhãn/đáp án chống lộ nhãn (Label Leakage)."
        )
        raw_log_str = alert.get("raw_log") if isinstance(alert, dict) else None
        if raw_log_str:
            try:
                st.json(json.loads(raw_log_str))
            except (ValueError, TypeError):
                st.code(str(raw_log_str), language="json")
        else:
            st.caption(
                "⚠️ Bản ghi này chưa đính kèm log thô (được tạo trước khi bật tính năng, "
                "hoặc là hành động thủ công). Hiển thị bản ghi quyết định thay thế:"
            )
            st.json(alert)


def render_ioc_table(iocs):
    """Hiển thị danh sách IOC trích xuất được."""
    if not iocs:
        st.info("Không có IOC nào được ghi nhận.")
        return

    df = pd.DataFrame(iocs)
    st.dataframe(df, width="stretch")


def render_metrics_header(
    total_alerts,
    pending_rules,
    active_rules,
    total_raw_logs=0,
    live_fpr=0.0,
    noise_reduction=None,
    pending_llm_count=0,
):
    """Hiển thị Header KPI chuẩn SOC SIEM bằng HTML Glassmorphism.

    noise_reduction = (log thô − cảnh báo gửi analyst) / log thô.

    ĐỌC CHO ĐÚNG: đây là mức giảm tải mà ANALYST cảm nhận, KHÔNG phải tỉ lệ lọc của
    Tier-1. Nó là tích của HAI cơ chế: (1) Tier-1 chặn phần lớn log, (2) Tier-2 GỘP
    nhiều log escalate thành 1 phán quyết. Ví dụ đo thật 2026-07-15 trên luồng gộp:
    4796 thô -> Tier 1 escalate 2034 (tức Tier 1 chỉ lọc 57.6%) -> gộp thành 218 cảnh
    báo -> hiển thị 95.5%. Muốn biết riêng tỉ lệ lọc Tier 1 thì lấy từ
    config/pipeline_stats.json (raw_logs_total vs số escalate), ĐỪNG suy từ số này.
    """
    if noise_reduction is None:
        noise_reduction = 0.0
        if total_raw_logs > 0:
            noise_reduction = ((total_raw_logs - total_alerts) / total_raw_logs) * 100

    # Xác định màu sắc cho live_fpr (dưới 10% xanh lá, dưới 25% vàng, ngược lại đỏ)
    fpr_color = "#52c41a"  # green
    if live_fpr > 25.0:
        fpr_color = "#ff4d4f"  # red
    elif live_fpr > 10.0:
        fpr_color = "#faad14"  # orange/yellow

    html_kpi = (
        f'<div class="kpi-container">'
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: #177ddc;">{total_raw_logs}</div>'
        f'    <div class="kpi-label">Logs thô đầu vào</div>'
        f"  </div>"
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: #ff4d4f;">{total_alerts}</div>'
        f'    <div class="kpi-label">Tổng Cảnh báo (T1+T2+T3)</div>'
        f"  </div>"
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: #d4b106;">{pending_llm_count}</div>'
        f'    <div class="kpi-label">Đang chờ LLM ⏳</div>'
        f"  </div>"
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: #52c41a;">{noise_reduction:.1f}%</div>'
        f'    <div class="kpi-label">Giảm tải Analyst (thô→cảnh báo)</div>'
        f"  </div>"
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: #faad14;">{pending_rules}</div>'
        f'    <div class="kpi-label">Phê duyệt (Tier-2 HITL)</div>'
        f"  </div>"
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: #13c2c2;">{active_rules}</div>'
        f'    <div class="kpi-label">Luật đang chặn (Active)</div>'
        f"  </div>"
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: {fpr_color};">{live_fpr:.1f}%</div>'
        f'    <div class="kpi-label">Tỷ lệ cảnh báo sai (Live FPR)</div>'
        f"  </div>"
        f"</div>"
    )
    st.markdown(html_kpi, unsafe_allow_html=True)


def render_threat_intel_tables(high_risk_ips):
    """Hiển thị bảng Threat Intelligence với màu sắc neon trực quan. Hỗ trợ chọn hàng để điều tra."""
    selected_ip = None

    st.subheader("🔴 Địa chỉ IP nguy cơ cao (Threat Actor)")
    if not high_risk_ips:
        st.info("Chưa ghi nhận Threat Actor nào.")
    else:
        df_high_risk = pd.DataFrame(
            high_risk_ips,
            columns=["Địa chỉ IP", "Điểm danh tiếng (Reputation)"],  # type: ignore
        )

        def color_score(val):
            color = "#ff4d4f" if val >= 70 else "#faad14" if val >= 40 else "#52c41a"
            return f"color: {color}; font-weight: bold; font-family: monospace;"

        from typing import Any, cast

        selection = st.dataframe(
            cast(
                Any,
                df_high_risk.style.map(color_score, subset=["Điểm danh tiếng (Reputation)"]).format(
                    {"Điểm danh tiếng (Reputation)": "{:.1f}"}
                ),
            ),
            on_select="rerun",
            selection_mode="single-row",
            key="threat_actor_table_select",
            use_container_width=True,
        )

        select_data = selection.get("selection", {}) if selection else {}
        rows = select_data.get("rows", [])
        if rows:
            row_idx = rows[0]
            selected_ip = df_high_risk.iloc[row_idx]["Địa chỉ IP"]

    return selected_ip


def render_apt_events_table(events):
    """Hiển thị bảng chuỗi tấn công APT từ DAPT2020. Hỗ trợ chọn hàng để điều tra."""
    st.subheader("🎯 Nhật ký chuỗi tấn công APT (DAPT2020 Tracker)")
    if not events:
        st.info("Chưa ghi nhận sự kiện chuỗi APT nào.")
        return None

    df = pd.DataFrame(events)
    df = df.rename(
        columns={
            "id": "ID",
            "src_ip": "IP Nguồn",
            "dst_ip": "IP Đích",
            "apt_phase": "Giai đoạn APT",
            "apt_day": "Ngày tấn công",
            "label": "Nhãn",
            "timestamp": "Thời gian xảy ra",
        }
    )

    from typing import Any, cast

    selection = st.dataframe(
        cast(Any, df), on_select="rerun", selection_mode="single-row", key="apt_events_table_select"
    )

    selected_ip = None
    select_data = selection.get("selection", {}) if selection else {}
    rows = select_data.get("rows", [])
    if rows:
        row_idx = rows[0]
        selected_ip = df.iloc[row_idx]["IP Nguồn"]
    return selected_ip
