import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

# enrich + build_stream dùng chung từ unified_dataset — KHÔNG copy tay (1 nguồn chân lý)
from experiments.unified_dataset import BENCHMARK_DAYS, build_stream, enrich
from src.tier1_filter.rule_engine import match_waf_family

# 10 ngày CICIDS2018 THẬT — phủ ĐỦ 15 loại tấn công + benign khắp nơi (nguồn khối lượng cho
# demo 100k). Mỗi ngày build_stream lấy ~25% tấn công / 75% benign (nhiều benign để drop).
#
# DÙNG CHUNG danh sách với benchmark thay vì chép tay: trước đây đúng danh sách này tồn tại
# ở BA nơi (đây, build_datatest.py, và mặc định của build_stream), nên sửa một chỗ là hai
# chỗ kia trôi lệch trong im lặng — demo và benchmark chạy trên hai nền dữ liệu khác nhau
# mà không có gì báo.
DEMO_DAYS = BENCHMARK_DAYS

# ─────────────────────────────────────────────────────────────────────────────
# NGÂN SÁCH TIER-2: hai lát dàn dựng dưới đây quyết định BAO NHIÊU LÔ tới LLM.
#
# ĐƠN VỊ LÀ LÔ, KHÔNG PHẢI SỰ KIỆN. Tier-2 gom 10 log cùng IP thành một lô và tốn MỘT lượt gọi
# LLM cho cả lô, nên `số lô ≈ số sự kiện / 10` — độc lập với việc rải trên bao nhiêu IP, miễn
# mỗi IP nhận bội số của 10. Mốc 1.000 lô vì thế cần ~10.000 sự kiện tới Tier-2.
#
# Chi phí: ~18,3 giây/lô, 2 khe song song -> 1.000 lô ≈ 2,5 giờ suy luận. Đây là ngân sách
# thời gian thật, không phải con số tuỳ thích.
#
# Cả hai lát chỉ đổi ĐÍCH ĐẾN (chặn -> leo thang) theo tiền tố IP. KHÔNG đụng payload, KHÔNG
# đụng nhãn, KHÔNG đụng mã kỹ thuật. Phần dữ liệu không dàn dựng vẫn để Tier-1 chặn bằng chữ
# ký, nên cả hai năng lực cùng diễn trong một lượt chạy.
# ─────────────────────────────────────────────────────────────────────────────

# CSIC 2010 — payload HTTP thật. Nguồn bằng chứng tầng ứng dụng chính, ~900 lô.
#
# Ưu tiên mẫu CÓ mã kỹ thuật (3.238 mẫu) rồi mới lấy tiếp phần còn lại. Phần không mã vẫn là
# tấn công web THẬT với payload thật — Tier-2 vẫn kết luận được là độc hại, chỉ trả `N/A` ở ô
# kỹ thuật thay vì đoán bừa. Kho CSIC có 18.000 mẫu bất thường nên dàn dựng 9.000 vẫn để lại
# một nửa cho Tier-1 chặn bằng chữ ký.
N_STAGED = 5_500
STAGED_IP_PREFIX = "198.19."
# 9.000 / 900 = ĐÚNG 10 mẫu mỗi IP -> đúng 1 lô đầy mỗi IP.
#
# VÌ SAO KHÔNG GOM ÍT IP HƠN. Có một TRẦN CỨNG không hiển nhiên: khi một IP xả lô, subscriber
# cắm cờ `pending_ai:{ip}` sống 60 giây và MỌI sự kiện tiếp theo của IP ấy bị nén thẳng, không
# vào bộ đệm. Nên số lô tối đa của một đợt dồn = SỐ IP, không phải số mẫu ÷ 10.
#
# Đo ở lượt chạy 11/08/2026 với 90 IP × 100 mẫu: chỉ ra 91 lô (không phải 900) và 8.166 mẫu bị
# nén im lặng. Cùng lượt đó, nhóm tiêm nhiễm 65 IP × đúng 10 mẫu ra trọn 64 lô, không mẫu nào
# bị nén — chính là công thức đúng, nay áp cho cả lát CSIC.
N_STAGED_IPS = 550

# Tiêm nhiễm câu lệnh / jailbreak — kho công khai deepset + jackhhao.
#
# VÌ SAO PHẢI DÀN DỰNG CẢ NHÓM NÀY. Luật Tier-1 kiểm chữ ký WAF TRƯỚC chữ ký tiêm nhiễm, mà
# payload jailbreak thường mang cả chuỗi giống SQL/script — nên chúng bị chặn ở Tier-1 và hàng
# rào chống tiêm nhiễm của Tier-2 không bao giờ được diễn. Đo ở lượt chạy 11/08/2026: chỉ 8/12
# IP tiêm nhiễm tới được Tier-2. Thêm tiền tố này vào `tier1.demo_escalate_waf_prefixes` thì
# cả nhóm leo thang, và AML.T0051 mới hiện lên bảng quy kết.
N_INJECTION_STAGED = 650
INJECTION_IP_PREFIX = "198.18."
N_INJECTION_IPS = 65  # 650 / 65 = 10 mẫu mỗi IP -> đúng 1 lô đầy mỗi IP

# Phần tiêm nhiễm KHÔNG dàn dựng đi dải riêng để Tier-1 xử theo đường mặc định — giữ được cả
# hai mặt: năng lực chặn sớm bằng chữ ký, và năng lực suy luận của Tier-2.
INJECTION_UNSTAGED_PREFIX = "198.20."
N_INJECTION_UNSTAGED_IPS = 8

# NGÂN SÁCH TỔNG, tính bằng LÔ:
#   CSIC dàn dựng      5.500 / 10 =  550 lô
#   Tiêm nhiễm dàn dựng  650 / 10 =   65 lô
#   Dư âm zero-day/DAPT           ≈  25 lô
#                                 ─────────
#                                 ≈  640 lô  ·  ~18 s/lô ÷ 2 khe ≈ 1,6 giờ
#
# VÌ SAO KHÔNG PHẢI 1.000. Trần không nằm ở ngân sách mà ở DỮ LIỆU: chỉ 5.510/18.000 bản ghi
# CSIC tấn công (30,6%) mang chữ ký WAF, và chỉ nhóm đó mới thật sự leo thang được lên Tier-2.
# Muốn cán 1.000 lô thì phải dàn dựng thêm ~3.500 bản ghi KHÔNG có bằng chứng — tức cố tình
# đẩy lưu lượng không quy kết được lên LLM, đúng thứ đã sinh ra 229 lệnh chặn nhầm ở lượt
# 11/08/2026. Con số lô là hệ quả của chất lượng bằng chứng, không phải mục tiêu tự thân.

# Phần khối benign dành làm ĐỆM THUẦN ở đầu luồng (không xen một sự kiện tấn công nào).
# 0,80 = 80% lượng benign chạy trước; 20% benign còn lại được trộn đều với TOÀN BỘ tấn công.
# Đặt 1,0 thì thành tách đôi cứng — xem chú thích khối sắp xếp bên dưới để biết vì sao không nên.
BENIGN_LEADIN_FRAC = 0.80


def main():
    print("[*] Dựng luồng demo ~500k sự kiện (data THẬT, đa-ngày CICIDS)...")
    # ------------------------------------------------------------------ #
    # PHÂN BỔ demo ~500.000 sự kiện, ĐÍCH: 95% benign / 5% tấn công.
    # ------------------------------------------------------------------ #
    # Nguyên tắc: nền benign phải dày như SOC thật để Tier-1 drop phần lớn, còn phần
    # tấn công thì DỒN vào nguồn mang BẰNG CHỨNG TẦNG ỨNG DỤNG (CSIC + tiêm nhiễm) —
    # đó mới là thứ bắt Tier-2 phải suy luận và làm sáng các panel MITRE/RAG/guardrail.
    #
    # Ngân sách tấn công 5% x 500.000 = ~25.000 ca, chia theo thứ tự ưu tiên:
    #   - CSIC 2010     36.000 sự kiện = 18.000 tấn công + 18.000 lành (bộ chia 50/50 cứng
    #     trong build_csic_dataset.py). Chiếm ~72% ngân sách tấn công — CHỦ Ý: payload HTTP
    #     là nguồn duy nhất chấm được QUY KẾT kỹ thuật. 36.000 là trần thực tế: kho thô
    #     còn 36.000 normal / 25.065 anomalous, muốn 50/50 thì 36.000 là mức cao nhất
    #     vẫn giữ được nguyên tắc cân bằng.
    #   - adv_llm          730 = TOÀN BỘ kho công khai (203 deepset + 527 jackhhao).
    #     `_build_adv_llm` cắt ở `min(limit, len(order))` và KHÔNG lặp lại mẫu, nên 730 là
    #     trần cứng; xin nhiều hơn cũng chỉ nhận về 730.
    #   - CICIDS       ~460.000 ở attack_ratio 0,012 -> ~5.500 tấn công trải đủ 15 lớp THẬT.
    #     Đây là khối benign chính (~454.000) mà Tier-1 sẽ drop — đúng vai "nền nhiễu".
    #   - DAPT           1.500 dòng khối lượng (giảm từ 6.000). Panel APT KHÔNG lấy từ đây
    #     mà từ chuỗi `dapt` THẬT, nên cắt sâu vẫn giữ nguyên kill-chain đa ngày.
    #   - zero-day    10 x 15 spec = 150 probe (giảm từ 900). Nhóm này gần như luôn bị
    #     Welford bắt ngay ở Tier-1 nên không cần khối lượng lớn.
    #
    # LƯU Ý TẢI LLM: chỉ dải ESCALATE (0,65 <= C < 0,85) mới chạm Tier-2. CSIC nhiều làm
    # tăng số ca leo thang so với luồng thuần NetFlow trước đây — dùng UNIFIED_STREAM_LIMIT
    # để đẩy từng lát khi cần soi UI nhanh, backpressure trong demo.py lo phần còn lại.
    warmup, main_stream, apt_truth, n_chains = build_stream(
        # Hai tham số dưới được HIỆU CHỈNH TỪ SỐ ĐO của lượt dựng trước (477.829 sự kiện,
        # 5,66% tấn công), KHÔNG phải ước lượng: tỉ lệ giữ lại đo được 437.793/640.000 =
        # 0,6841, và các nguồn ngoài `cicids_max` đóng góp cố định 40.036 sự kiện / 20.723
        # tấn công. Từ đó suy ngược ra mức cần cho đích 500.000 sự kiện / 5,00% tấn công.
        cicids_max_rows=672_000,  # 459.964 / 0,6841 -> CICIDS ~460k sự kiện
        cicids_max_days=DEMO_DAYS,
        cicids_attack_ratio=0.0093,  # 4.277/459.964 -> tổng tấn công về đúng ~25.000 (5,00%)
        dapt_max_rows=1_500,  # chỉ đủ hiển thị; chuỗi APT thật nằm ở nguồn `dapt`
        zeroday_repeat=10,  # 10 x 15 spec = 150 probe, chủ yếu bị Tier-1 bắt
        csic_max=36_000,  # trần cân bằng 50/50 của kho CSIC 2010 đã dựng lại
        adv_llm_max=730,  # TOÀN BỘ kho tiêm nhiễm/jailbreak công khai
    )
    stream = warmup + main_stream  # warmup giữ prefix; main đã sort theo thời gian

    # demo_signals=True: đính threat-intel THẬT (giai đoạn + TTP DAPT2020) cho DAPT tấn công
    # -> Tier-2 ánh xạ ĐA DẠNG kỹ thuật. CHỈ luồng demo, KHÔNG ảnh hưởng benchmark datatest.json.
    enriched_logs = [enrich(ev, demo_signals=True) for ev in stream]

    # ------------------------------------------------------------------ #
    # LÁT DÀN DỰNG — CHỈ ĐỂ DIỄN, PHẢI NÓI RÕ KHI TRÌNH BÀY
    # ------------------------------------------------------------------ #
    # VẤN ĐỀ ĐO ĐƯỢC (300 lô đầu, luồng 496.885 sự kiện): Tier-2 nhận 94% lô là NetFlow thuần
    # và trả AWAIT_HITL 88,3%, BLOCK_IP chỉ 3,9%. Lô có payload thì ngược lại — BLOCK_IP 38,9%.
    # Nguyên nhân: 3.238 mẫu CSIC mang mã kỹ thuật đều dính chữ ký WAF nên bị Tier-1 CHẶN
    # trước, Tier-2 không bao giờ thấy một ca payload nào nó quy kết nổi.
    #
    # Lát này đổi IP nguồn của N mẫu CSIC CÓ mã kỹ thuật sang dải 198.19.0.0/16 (RFC 2544,
    # dành riêng cho benchmark). Cùng `tier1.demo_escalate_waf_prefixes`, đúng dải đó được
    # LEO THANG thay vì chặn -> Tier-2 có bằng chứng tầng ứng dụng để neo RAG và ra phán quyết
    # tự tin. KHÔNG sửa payload, KHÔNG sửa nhãn, KHÔNG sửa mã kỹ thuật — chỉ đổi ĐÍCH ĐẾN.
    # Cờ `demo_staged=True` để hậu kiểm tách nhóm này ra khỏi mọi phép đo.
    #
    # Dải phải sạch với CẢ dữ liệu LẪN bộ test: bản đầu dùng 203.0.113.0/24 (TEST-NET-3) và
    # đụng `tests/test_tier1_filter.py`, làm demo ghi 202 luật động đè lên dải test -> 4 test
    # danh tiếng đổ. 198.19.x không xuất hiện ở đâu khác.
    # GOM VỀ MỘT NHÚM IP, KHÔNG RẢI MỖI MẪU MỘT IP.
    #
    # Tier-2 gộp lô THEO IP NGUỒN (`batch_size=10`, hoặc xả sớm sau 5 giây im lặng). Bản đầu
    # cấp cho mỗi mẫu dàn dựng một IP riêng, nên 1.500 mẫu thành 1.500 LÔ MỘT-PHẦN-TỬ: mỗi lô
    # một lượt gọi LLM ~13 giây, tức ~2,8 giờ GPU cho đúng cái lát này. Đo trên tệp đã dựng:
    # 2.385/2.647 IP mang bằng chứng ứng dụng chỉ có ĐÚNG một sự kiện.
    #
    # Gom vào `N_STAGED_IPS` IP thì cùng số mẫu ấy thành các lô đầy 10 — chi phí LLM giảm gần
    # 10 lần, và quan trọng hơn: một lô 10 request cùng nguồn mới đúng hình dạng dữ liệu mà
    # Tier-2 sinh ra để đọc (nhiều bằng chứng cùng một kẻ), thay vì bắt nó phán trên 1 dòng.
    # CHỌN THEO "CÓ CHỮ KÝ WAF", KHÔNG THEO "LÀ BẢN GHI TẤN CÔNG".
    #
    # LỖI ĐÃ SỬA 12/08/2026. Bản trước lấy mọi bản ghi CSIC mang nhãn tấn công. Nhưng nhóm
    # `Anomalous (unclassified)` phần lớn bất thường ở những chỗ KHÔNG nằm trong các trường đã
    # trích (header dị dạng, giá trị sai kiểu), nên Tier-1 chấm 0 điểm và DROP thẳng — chúng
    # không bao giờ tới được Tier-2. Đo trên luồng đã dựng: bản ghi dàn dựng
    # `198.19.1.70 /tienda1/publico/pagar.jsp` -> `match_waf_family` trả None -> DROP score 0.
    #
    # Hệ quả nếu cứ dàn dựng chúng: 70% ngân sách lô bốc hơi ở Tier-1, và phần LỌT lên Tier-2
    # lại là phần KHÔNG có bằng chứng quy kết — đúng nhóm sinh ra 229 lệnh chặn nhầm ở lượt
    # 11/08/2026 (xem `batch_attack_vocabulary`).
    #
    # Đo trên toàn kho: 5.510/18.000 bản ghi tấn công (30,6%) mang chữ ký, và chữ ký khớp
    # 0 bản ghi lành. Nên đây vừa là tiêu chí ĐÚNG (chỉ dàn dựng thứ Tier-1 thật sự leo thang
    # được), vừa là TRẦN THẬT của số lô chất lượng: 551 lô, không phải 900.
    _csic_atk = [
        e
        for e in enriched_logs
        if e.get("unified_source") == "csic"
        and str(e.get("gt_label") or "Benign") not in ("Benign", "None")
    ]
    _sig = [e for e in _csic_atk if match_waf_family(e)]
    # Trong nhóm có chữ ký, ưu tiên tiếp mẫu CÓ mã kỹ thuật để bảng quy kết giàu hơn.
    _with_tech = [e for e in _sig if str(e.get("wa_mitre") or "").strip()]
    _no_tech = [e for e in _sig if not str(e.get("wa_mitre") or "").strip()]

    # GOM THEO HỌ KỸ THUẬT TRƯỚC KHI CẮT LÔ.
    #
    # Tier-2 phát ĐÚNG MỘT kỹ thuật cho cả lô. Nếu lô chứa nhiều họ thì không tồn tại đáp án
    # đúng duy nhất, và phép đo quy kết mất nghĩa. Đo lượt chạy 12/08/2026 trên thứ tự cũ
    # (nguyên thứ tự tệp CSIC): 313/550 lô dàn dựng TRỘN 3–5 họ — ví dụ 198.19.0.1 gồm 3 dò
    # tệp + 3 SQLi + 2 XSS + 2 CRLF. Tệ hơn: 237 lô "thuần" còn lại đều là `Anomalous
    # (unclassified)`, tức KHÔNG có kỹ thuật thật, nên **không một lô nào chấm được theo luật
    # chặt**. Chấm nới ("kỹ thuật gán có nằm trong tập kỹ thuật của lô") cho 43/44 = 97,7%,
    # nhưng lô 4 họ thì luật ấy tặng sẵn 4 cơ hội — không dùng làm bằng chứng năng lực được.
    #
    # Gom theo `wa_mitre` cũng SÁT THỰC TẾ hơn: một IP tấn công thường chạy một chiến dịch,
    # không rải bốn họ khai thác khác nhau trong mười yêu cầu liên tiếp.
    _by_tech: dict[str, list] = {}
    for e in _with_tech:
        _by_tech.setdefault(str(e.get("wa_mitre")).strip(), []).append(e)
    # Họ đông xếp trước để lấp đầy ngân sách bằng các lô nguyên vẹn 10 log; phần dư < 10 của
    # mỗi họ bị bỏ chứ không dồn sang họ khác — dồn là tái tạo đúng lô trộn vừa loại bỏ.
    _grouped: list = []
    for _tech in sorted(_by_tech, key=lambda t: -len(_by_tech[t])):
        _evs = _by_tech[_tech]
        _grouped.extend(_evs[: len(_evs) // 10 * 10])
    _dropped = len(_with_tech) - len(_grouped)
    if _dropped:
        print(f"    [i] bỏ {_dropped} mẫu dư lẻ (< 10) để mọi lô dàn dựng THUẦN một họ kỹ thuật")
    staged = (_grouped + _no_tech)[:N_STAGED]
    if len(staged) < N_STAGED:
        print(
            f"    [!] chỉ có {len(staged):,} mẫu CSIC mang chữ ký (ngân sách {N_STAGED:,}) — "
            f"số lô dàn dựng sẽ là {len(staged) // 10}"
        )

    # DẢI LIÊN TIẾP, KHÔNG RẢI VÒNG TRÒN.
    #
    # Đây là điểm quyết định số LÔ. Bản trước dùng `k % N_IPS`, tức hai mẫu liền nhau đi hai IP
    # khác nhau — mỗi IP nhận nhỏ giọt, và bộ đệm bị timeout xả trước khi gom đủ 10. Đo lượt
    # 11/08/2026: 1.451 sự kiện tới Tier-2 mà thành **491 lô, trung bình 2,95 log/lô** — tức tốn
    # gấp hơn ba lần số lượt gọi LLM cần thiết cho cùng lượng bằng chứng.
    #
    # Chia theo `k // _per_ip` thì mỗi IP nhận một dải liên tiếp; sau khi trộn vào luồng, các
    # mẫu ấy vẫn nằm sát nhau về thời gian nên bộ đệm đầy 10 trước khi timeout kịp chạm.
    _per_ip = max(1, N_STAGED // N_STAGED_IPS)
    for k, ev in enumerate(staged):
        _slot = min(k // _per_ip, N_STAGED_IPS - 1)
        ev["Source IP"] = f"{STAGED_IP_PREFIX}{_slot // 254}.{_slot % 254 + 1}"
        ev["demo_staged"] = True

    # Tiêm nhiễm: chia HAI nhóm có chủ đích.
    #
    #   `198.18.` — DÀN DỰNG, leo thang lên Tier-2 để hàng rào chống tiêm nhiễm được diễn và
    #               AML.T0051 hiện lên bảng quy kết.
    #   `198.20.` — KHÔNG dàn dựng, để Tier-1 xử theo đường mặc định (chữ ký bắt sớm).
    #
    # Giữ cả hai vì mỗi nhóm chứng minh một năng lực khác nhau, và vì gộp hết vào Tier-2 thì
    # riêng nhóm này đã ngốn trọn ngân sách 1.000 sự kiện.
    _inj = [e for e in enriched_logs if e.get("unified_source") == "adv_llm"]
    _inj_per_ip = max(1, N_INJECTION_STAGED // N_INJECTION_IPS)
    for k, ev in enumerate(_inj):
        if k < N_INJECTION_STAGED:
            _slot = min(k // _inj_per_ip, N_INJECTION_IPS - 1)  # dải liên tiếp, xem trên
            ev["Source IP"] = f"{INJECTION_IP_PREFIX}{_slot // 254}.{_slot % 254 + 1}"
            ev["demo_staged"] = True
        else:
            _slot = (k - N_INJECTION_STAGED) % N_INJECTION_UNSTAGED_IPS
            ev["Source IP"] = f"{INJECTION_UNSTAGED_PREFIX}{_slot // 254}.{_slot % 254 + 1}"

    # ------------------------------------------------------------------ #
    # SẮP LẠI: NẠP ĐỆM BENIGN TRƯỚC, RỒI TRỘN ĐỀU PHẦN CÒN LẠI
    # ------------------------------------------------------------------ #
    # Mục đích vận hành: Tier-1 nuốt trọn khối benign ở tốc độ đường truyền nên Dashboard có
    # số xả tải ngay, và hàng đợi LLM không bị chen ngang trong lúc Welford còn học nền.
    #
    # VÌ SAO KHÔNG TÁCH ĐÔI CỨNG: bản đầu chỉ `sorted(body, key=_is_attack)` — đo được sự kiện
    # tấn công ĐẦU TIÊN rơi xuống vị trí #470.866, tức 94,8% luồng. Hệ quả: demo trống trơn
    # (không cảnh báo, không MITRE, không APT) suốt gần hết lượt chạy, rồi toàn bộ 26.019 ca
    # tấn công dồn vào 5% cuối thành một bức tường. Nghẽn LLM không biến mất, chỉ bị dời chỗ và
    # trở nên tệ hơn vì mất luôn khả năng tự điều tiết.
    #
    # Cách dùng ở đây: dành `BENIGN_LEADIN_FRAC` khối benign đầu làm đệm thuần, phần benign còn
    # lại TRỘN ĐỀU với toàn bộ tấn công theo tỉ lệ cố định. Vừa có mở đầu sạch và nhanh, vừa
    # rải đều tải LLM trên quãng còn lại thay vì dồn cục.
    #
    # KHÔNG phá chuỗi APT: `check_apt_chain` đếm `DISTINCT apt_day` trong bảng `threat_events`
    # theo `src_ip` — mốc ngày nằm TRONG dữ liệu sự kiện, không phải thứ tự đến. Đảo thứ tự
    # đẩy vì thế không đụng tới 9 chuỗi kill-chain đa ngày.
    def _is_attack(ev: dict) -> bool:
        return bool(ev.get("expected_threat") or ev.get("apt_is_attack"))

    n_warm = len(warmup)
    head, body = enriched_logs[:n_warm], enriched_logs[n_warm:]
    benign = [e for e in body if not _is_attack(e)]  # giữ nguyên thứ tự thời gian gốc
    attacks = [e for e in body if _is_attack(e)]

    cut = int(len(benign) * BENIGN_LEADIN_FRAC)
    lead, rest = benign[:cut], benign[cut:]

    # Trộn `rest` với `attacks` theo tỉ lệ đều: cứ `step` benign thì chèn 1 tấn công.
    mixed: list = []
    step = max(1, len(rest) // max(len(attacks), 1))
    ai = 0
    for i, ev in enumerate(rest):
        mixed.append(ev)
        if ai < len(attacks) and (i + 1) % step == 0:
            mixed.append(attacks[ai])
            ai += 1
    mixed.extend(attacks[ai:])  # phần dư nếu benign hết trước

    enriched_logs = head + lead + mixed

    out_file = os.path.join(ROOT, "data", "demo.json")
    # Ghi COMPACT (không indent) — file ~500k event, indent=2 sẽ phình gấp đôi. Máy đọc thôi.
    with open(out_file, "w") as f:
        json.dump(enriched_logs, f, separators=(",", ":"))

    # Báo cáo phân bổ THẬT để đối chiếu (đẹp + trung thực).
    n = len(enriched_logs)
    dist = Counter(e.get("unified_source") for e in enriched_logs)
    n_attack = sum(1 for e in enriched_logs if e.get("expected_threat") or e.get("apt_is_attack"))
    labels = Counter(str(e.get("gt_label") or "") for e in enriched_logs)
    n_class = len([k for k in labels if k and k not in ("Benign", "None")])
    print(f"[+] Đã lưu {n:,} sự kiện enriched -> {out_file}")
    print(f"    Phân bổ nguồn: {dict(dist.most_common())}")
    print(
        f"    Tấn công/threat: {n_attack:,} ({100 * n_attack / n:.2f}%)  |  "
        f"benign (Tier-1 drop): {n - n_attack:,} ({100 * (n - n_attack) / n:.2f}%)"
    )
    print(f"    Số lớp tấn công phân biệt được: {n_class}")
    # Tách hai lát khi báo cáo: gộp lại thì con số không nói được lát nào đóng góp bao nhiêu
    # vào ngân sách Tier-2, mà đó chính là thứ cần điều tiết.
    n_st_csic = sum(
        1 for e in enriched_logs if e.get("demo_staged") and e.get("unified_source") == "csic"
    )
    n_st_inj = sum(
        1 for e in enriched_logs if e.get("demo_staged") and e.get("unified_source") == "adv_llm"
    )
    n_inj_un = sum(
        1
        for e in enriched_logs
        if e.get("unified_source") == "adv_llm" and not e.get("demo_staged")
    )
    first_atk = next((i for i, e in enumerate(enriched_logs) if _is_attack(e)), n)
    print(
        f"    Lát dàn dựng -> Tier-2: {n_st_csic:,} CSIC ({STAGED_IP_PREFIX}x) "
        f"+ {n_st_inj:,} tiêm nhiễm ({INJECTION_IP_PREFIX}x) = {n_st_csic + n_st_inj:,} mẫu"
    )
    print(
        f"    Tiêm nhiễm KHÔNG dàn dựng (Tier-1 chặn sớm, {INJECTION_UNSTAGED_PREFIX}x): "
        f"{n_inj_un:,} mẫu"
    )
    print(
        f"    Thứ tự: benign chạy trước, sự kiện tấn công đầu tiên ở vị trí #{first_atk:,} "
        f"({100 * first_atk / n:.1f}% luồng)"
    )
    print(f"    Chuỗi APT đa-ngày: {n_chains} (mốc chân lý: {len(apt_truth)} IP)")


if __name__ == "__main__":
    main()
