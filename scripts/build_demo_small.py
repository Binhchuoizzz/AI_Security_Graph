"""SENTINEL — Dựng LUỒNG DEMO NGẮN (~5.000 sự kiện) ĐỦ 4 NGUỒN cho buổi bảo vệ.

TẠI SAO CẦN FILE NÀY (bug thật đã gặp): `run_demo.sh --small` cắt 5.000 sự kiện ĐẦU
của `data/demo.json`. Nhưng luồng đầy đủ được sắp theo THỜI GIAN THẬT, nên các chuỗi APT
đa-ngày chỉ hoàn tất ở vị trí #45.933 / #60.055 / #63.237 → demo ngắn KHÔNG BAO GIỜ hiện
panel "Chiến dịch APT" (một kết quả headline của luận văn). Tương tự, zero-day và
adversarial nằm rải rác nên cũng có thể vắng mặt.

CÁCH LÀM (KHÔNG bịa dữ liệu): phần NetFlow là TẬP CON PHÂN TẦNG lấy nguyên văn từ
`data/demo.json` — mọi sự kiện đều là bản ghi THẬT (CICIDS2018 / DAPT2020 / zero-day
real-derived / adversarial OWASP), giữ nguyên mọi trường kể cả `apt_day`. Việc duy nhất
ta làm là CHỌN sự kiện nào đi vào tập nhỏ, rồi SẮP LẠI THEO ĐÚNG THỨ TỰ GỐC để quan hệ
thời gian (và do đó cơ chế APT đa-ngày) vẫn nổi lên tự nhiên như luồng đầy đủ.

Hai nhóm tầng ỨNG DỤNG (CSIC 2010, đối kháng LLM) được dựng THẲNG ở đây qua
`unified_dataset._build_csic` / `._build_adv_llm` rồi cho qua `enrich()` y như mọi nguồn
khác, KHÔNG lấy từ `demo.json`. Lý do: `demo.json` hiện có 0 bản ghi CSIC (nó được dựng
TRƯỚC khi `data/csic.json` kịp ghi xong, và nhánh nạp ngày ấy trả rỗng lặng lẽ — nay đã
đổi thành báo lỗi to). Tệp này là LUỒNG TRÌNH DIỄN, không phải nền đo chỉ số; số liệu
luận văn lấy từ bộ trộn riêng (`build_datatest.py`), nên nó không cần bám theo `demo.json`.

Đảm bảo mỗi panel Dashboard đều có dữ liệu:
  - Chiến dịch APT   : lấy TRỌN sự kiện của các IP có >= 2 apt_day (ngưỡng is_apt ở
                       ThreatMemoryStore.check_apt_chain) -> chuỗi chắc chắn kích hoạt.
  - Tier-1 chặn/MITRE: phủ ĐỦ các lớp tấn công CICIDS có nhãn (mỗi lớp tối đa N mẫu).
  - Zero-day         : mẫu probe real-derived (Welford bắt, luật tĩnh sót).
  - Quy kết kỹ thuật : CSIC 2010 — request HTTP THẬT, tầng bằng chứng DUY NHẤT có payload.
  - Guardrails       : 4 payload OWASP + prompt injection/jailbreak công khai (AML.T0051).
  - Nền benign       : phần còn lại trong trần NetFlow, để Tier-1 vẫn DROP thật.

TRỌNG SỐ ĐÃ ĐẢO: tầng ứng dụng là chính, NetFlow chỉ còn làm nền — xem khối hạn ngạch.

Chạy:  .venv/bin/python scripts/build_demo_small.py
       .venv/bin/python scripts/build_demo_small.py --netflow 1000 --csic 2000 --adv-llm 300
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

# GT_PATH lấy từ chính module dựng luồng — KHÔNG ghép tay đường dẫn (nó nằm ở
# `experiments/ground_truth.json`, không phải `data/`, và đã có một bản chép tay sai).
from experiments.unified_dataset import (  # noqa: E402
    GT_PATH,
    _build_adv_llm,
    _build_csic,
    enrich,
)

SRC_FILE = os.path.join(ROOT, "data", "demo.json")
OUT_FILE = os.path.join(ROOT, "data", "demo_small.json")

# --------------------------------------------------------------------------- #
# HẠN NGẠCH — luồng LẤY TẦNG ỨNG DỤNG LÀM CHÍNH, NetFlow chỉ còn làm nền
# --------------------------------------------------------------------------- #
# Vì sao đảo trọng số: NetFlow KHÔNG mang payload, nên truy vấn RAG dựng từ nó chỉ còn mô
# tả cổng/giao thức chung chung ("high event frequency ... port 443") và trả về cùng một
# nhúm 5 mã mạng cho gần như mọi lô — đo được 99/118 lô giống hệt nhau. Tức phần NetFlow
# gần như KHÔNG diễn được năng lực quy kết, chỉ tổ đẩy lô vào AWAIT_HITL. CSIC thì ngược
# lại: có payload, có mục KB cụ thể để neo. Nên demo lấy CSIC làm sân khấu chính.
#
# CSIC 2010 — TOÀN BỘ bộ (`data/csic.json` có 4.000: 2.000 tấn công / 2.000 lành).
N_CSIC = 3500
# Đối kháng nhắm vào LLM (prompt injection + jailbreak công khai). Đáp án AML.T0051 đi
# đường ATLAS miễn neo RAG (`nodes._grounded(from_curated=True)`) -> BLOCK_IP, không HITL.
N_ADV_LLM = 500
# TRẦN CỨNG cho NetFlow, gồm CẢ tấn công lẫn benign. Đây là NGUỒN KHỐI LƯỢNG của câu chuyện
# xả tải: phần lớn là benign để Tier-1 DROP thật, cho ra tỉ lệ xả tải đọc được trên màn hình.
N_NETFLOW = 6000

# --------------------------------------------------------------------------- #
# LÁT DÀN DỰNG — CHỈ ĐỂ DIỄN, PHẢI NÓI RÕ KHI TRÌNH BÀY
# --------------------------------------------------------------------------- #
# Đo được ở lượt chạy 2026-08-03: Tier-1 tự giải quyết 94,7% sự kiện CSIC, và TOÀN BỘ mẫu
# mang mã kỹ thuật đều dính lớp chữ ký WAF -> trong 203 sự kiện CSIC lên tới Tier-2 có ĐÚNG
# 0 mẫu có đáp án. Màn hình vì thế không bao giờ hiện được năng lực quy kết.
#
# Lát này lấy N mẫu CSIC CÓ mã kỹ thuật và đổi IP nguồn sang dải `198.19.0.0/16`
# (RFC 2544, dành riêng cho benchmark — không định tuyến trên Internet thật). Cùng với
# `tier1.demo_escalate_waf_prefixes` trong config, đúng dải này được LEO THANG thay vì chặn.
#
# KHÔNG sửa payload, KHÔNG sửa nhãn, KHÔNG sửa phán quyết — chỉ đổi ĐÍCH ĐẾN trong pipeline.
#
# ĐÃ ĐỔI DẢI, và lý do đáng nhớ: bản đầu dùng `203.0.113.0/24` (TEST-NET-3) vì nó sạch trên
# mọi TỆP DỮ LIỆU. Nhưng `tests/test_tier1_filter.py` cũng dùng đúng dải ấy cho các ca kiểm
# thử danh tiếng. Lượt demo chạy xong ghi 202 luật động ACTIVE cho `203.0.113.*` vào
# `config/system_settings.yaml`, thế là `203.0.113.7` bị chặn cứng và 4 test danh tiếng đổ
# (chờ ESCALATE, nhận BLOCK_IP). Bài học: dải dàn dựng phải sạch với CẢ dữ liệu LẪN bộ test,
# vì demo ghi ngược vào config dùng chung.
N_CSIC_STAGED = 250
STAGED_IP_PREFIX = "198.19."

# Ba hạn ngạch dưới đây là phần TẤN CÔNG trong trần NetFlow; phần còn lại của `N_NETFLOW`
# là benign ("chủ yếu là benign" — nền cho Welford học baseline và để Tier-1 vẫn DROP thật).
PER_ATTACK_CLASS = 8  # mỗi CẶP (nguồn × lớp) lấy tối đa bấy nhiêu — vẫn phủ đủ 16 lớp
N_ZERODAY = 50  # probe zero-day (đủ để panel có số)
N_DAPT_EXTRA = 30  # sự kiện DAPT khác (nền chiến dịch, ngoài các IP APT đa-ngày)


def _is_attack(ev: dict) -> bool:
    return bool(ev.get("expected_threat") or ev.get("apt_is_attack"))


def main() -> None:
    # Ba hạn ngạch ĐỘC LẬP thay cho một `--target` gộp. Lý do: `--target` không nói được
    # điều DUY NHẤT đáng điều khiển ở đây — tỉ lệ giữa NetFlow và tầng ứng dụng. Tổng luồng
    # là HỆ QUẢ của ba số này, nên in ra chứ không nhận vào.
    ap = argparse.ArgumentParser()
    ap.add_argument("--netflow", type=int, default=N_NETFLOW, help="trần sự kiện NetFlow")
    ap.add_argument("--csic", type=int, default=N_CSIC, help="số request HTTP CSIC 2010")
    ap.add_argument("--adv-llm", type=int, default=N_ADV_LLM, help="số mẫu đối kháng LLM")
    ap.add_argument(
        "--staged",
        type=int,
        default=N_CSIC_STAGED,
        help="số mẫu CSIC DÀN DỰNG (đổi IP để Tier-1 leo thang thay vì chặn); 0 = tắt",
    )
    args = ap.parse_args()
    n_netflow, n_csic, n_adv, n_staged = args.netflow, args.csic, args.adv_llm, args.staged

    with open(SRC_FILE) as f:
        events = json.load(f)
    _n_src = len(events)

    # BỎ hai nhóm tầng ỨNG DỤNG khỏi rổ lấy mẫu — bước 8 dựng LẠI chúng từ nguồn gốc.
    #
    # Khi script này ra đời, `demo.json` chưa có bản ghi CSIC lẫn đối kháng LLM nào, nên lấy
    # mẫu từ nó rồi dựng thêm ở bước 8 là an toàn. Nay `demo.json` đã mang 36.000 bản ghi CSIC
    # và 650 bản ghi `adv_llm`, nên bước phân tầng theo (nguồn × lớp) hút chúng vào `subset`
    # rồi bước 8 nối thêm một bản nữa: bản ghi bị NHÂN ĐÔI, và chốt chống đụng IP báo động
    # giả vì nhóm đối kháng "đụng" chính nó (đo 12/08/2026: 8 IP `198.18.0.x`, cả 8 đều là
    # `adv_llm`, và script chết trước khi ghi tệp).
    #
    # Lọc ở ĐÂY chứ không nới chốt: chốt đang bảo vệ đúng thứ nó tuyên bố — IP của nhóm đối
    # kháng phải rời hẳn MỌI NGUỒN KHÁC — nên thứ phải sửa là rổ đầu vào, không phải chốt.
    # Tỉ lệ tấn công của luồng ĐẦY ĐỦ phải chốt TRƯỚC khi lọc — nó là mốc đối chiếu in ra
    # cuối script, và tính trên rổ đã lọc thì mẫu số mất 36.730 bản ghi (đo: 5,2% -> 1,6%).
    _src_ratio = 100 * sum(1 for e in events if _is_attack(e)) / len(events)
    _REBUILT_AT_STEP_8 = {"csic", "adv_llm"}
    events = [e for e in events if e.get("unified_source") not in _REBUILT_AT_STEP_8]
    print(
        f"[*] Nguồn: {_n_src:,} sự kiện THẬT từ data/demo.json "
        f"(bỏ {_n_src - len(events):,} bản ghi csic/adv_llm — dựng lại ở bước 8)"
    )

    # --- 1. Các IP APT ĐA-NGÀY: lấy TRỌN để chuỗi chắc chắn kích hoạt ------- #
    days_by_ip = defaultdict(set)
    for ev in events:
        if ev.get("apt_is_attack"):
            days_by_ip[ev.get("Source IP")].add(ev.get("apt_day"))
    apt_ips = {ip for ip, ds in days_by_ip.items() if len({d for d in ds if d is not None}) >= 2}

    keep: set[int] = set()
    for i, ev in enumerate(events):
        if ev.get("Source IP") in apt_ips and ev.get("unified_source", "").startswith("dapt"):
            keep.add(i)
    print(f"[+] APT đa-ngày: {len(apt_ips)} IP -> giữ TRỌN {len(keep)} sự kiện")

    # --- 2. Adversarial: lấy TOÀN BỘ --------------------------------------- #
    adv = [i for i, e in enumerate(events) if e.get("unified_source") == "adversarial"]
    keep.update(adv)
    print(f"[+] Adversarial (OWASP thật): {len(adv)}")

    # --- 3. Zero-day ------------------------------------------------------- #
    zd = [i for i, e in enumerate(events) if e.get("unified_source") == "zeroday"]
    zd_take = zd[:: max(1, len(zd) // N_ZERODAY)][:N_ZERODAY]  # rải đều, không lấy cụm đầu
    keep.update(zd_take)
    print(f"[+] Zero-day: {len(zd_take)} / {len(zd)} (rải đều)")

    # --- 4. Tấn công CICIDS: phủ ĐỦ mọi lớp có nhãn ------------------------ #
    # Khoá phân tầng là CẶP (nguồn, lớp), KHÔNG phải lớp đơn thuần. Lý do: nhiều nguồn
    # dùng chung nhãn phẳng `gt_label='Attack'` (cicids_max, dapt_max, zeroday...), nên
    # phân tầng theo lớp đơn dồn tất cả vào MỘT rổ bị chặn ở PER_ATTACK_CLASS — hệ quả đo
    # được: phủ tấn công CICIDS tụt còn 30 mẫu trong khi zero-day chiếm chỗ. Tách theo cặp
    # thì mỗi nguồn giữ nguyên hạn ngạch của mình.
    by_class = defaultdict(list)
    for i, e in enumerate(events):
        if _is_attack(e) and (lab := e.get("gt_label")):
            by_class[(e.get("unified_source", ""), lab)].append(i)
    for idxs in by_class.values():
        step = max(1, len(idxs) // PER_ATTACK_CLASS)
        keep.update(idxs[::step][:PER_ATTACK_CLASS])
    n_cls = len({lab for _, lab in by_class})
    print(
        f"[+] Tấn công có nhãn: {len(by_class)} cặp (nguồn×lớp) / {n_cls} lớp, "
        f"tối đa {PER_ATTACK_CLASS} mẫu mỗi cặp"
    )

    # --- 5. DAPT khác (nền chiến dịch) ------------------------------------- #
    dapt_other = [
        i
        for i, e in enumerate(events)
        if str(e.get("unified_source", "")).startswith("dapt") and i not in keep
    ]
    step = max(1, len(dapt_other) // N_DAPT_EXTRA)
    keep.update(dapt_other[::step][:N_DAPT_EXTRA])

    # --- 6. Nền BENIGN NetFlow: lấp cho ĐỦ TRẦN n_netflow ------------------ #
    # Chỗ trống tính theo TRẦN NETFLOW, không theo tổng luồng. Bản cũ tính theo tổng nên
    # benign nuốt mọi chỗ dư (3.754/5.000) và demo thành thuần NetFlow.
    benign = [i for i, e in enumerate(events) if not _is_attack(e) and i not in keep]
    need = max(0, n_netflow - len(keep))
    step = max(1, len(benign) // need) if need else 1
    keep.update(benign[::step][:need])
    print(
        f"[+] Nền benign NetFlow: {min(need, len(benign)):,} "
        f"-> NetFlow tổng {min(n_netflow, len(keep) + min(need, len(benign))):,} (trần {n_netflow:,})"
    )

    # --- 7. GIỮ NGUYÊN THỨ TỰ GỐC (quan hệ thời gian -> APT nổi lên đúng) -- #
    subset = [events[i] for i in sorted(keep)]

    # --- 8. Ghép hai nhóm tầng ỨNG DỤNG (dựng thẳng, không qua demo.json) -- #
    # `demo.json` có 0 bản ghi CSIC (xem docstring), nên hai nhóm này được dựng tại chỗ rồi
    # cho qua ĐÚNG `enrich()` mà mọi nguồn khác dùng — không nhét nhãn tay.
    with open(GT_PATH, encoding="utf-8") as f:
        _gt = json.load(f)
    gt_samples = _gt if isinstance(_gt, list) else _gt.get("samples", _gt)

    _oi = [0]
    GOLDEN = 0.6180339887498949

    def tkey(day: int) -> float:
        """Cùng dãy golden-ratio của `build_stream` — rải đều & xen kẽ trong một ngày."""
        t = day + (_oi[0] * GOLDEN) % 1.0
        _oi[0] += 1
        return t

    csic_raw = _build_csic(tkey, n_csic * 4)  # nạp rộng rồi mới ưu tiên mẫu có mã kỹ thuật
    csic_tech = [e for e in csic_raw if str(e.get("mitre") or "").strip()]
    csic_rest = [e for e in csic_raw if not str(e.get("mitre") or "").strip()]
    take = csic_tech[:n_csic]
    if len(take) < n_csic and csic_rest:
        step = max(1, len(csic_rest) // (n_csic - len(take)))
        take += csic_rest[::step][: n_csic - len(take)]
    csic_logs = [enrich(e, demo_signals=True) for e in take]
    print(
        f"[+] CSIC 2010 (HTTP THẬT): {len(csic_logs)} "
        f"(trong đó {len(csic_tech[:n_csic])} mang mã kỹ thuật -> chấm QUY KẾT được)"
    )

    # --- 8b. LÁT DÀN DỰNG: đổi IP để Tier-1 leo thang thay vì chặn ---------- #
    # Chỉ ĐỔI IP NGUỒN. Payload, URI, nhãn, mã kỹ thuật giữ nguyên 100%.
    # GOM THEO HỌ rồi CẤP 10 MẪU MỖI IP — giống hệt `build_demo.py`.
    #
    # Bản trước cấp MỖI MẪU MỘT IP (`k // 254`, `k % 254` chạy hết dải), nên 250 mẫu dàn dựng
    # thành 250 IP và Tier-2 gộp ra 250 lô MỘT-LOG. Đo lượt chạy 12/08/2026 trên lát nhỏ:
    # 746/750 lô có đúng 1 log. Một log thì tác tử gần như không có ngữ cảnh, nên lát nhỏ đo
    # ra thứ KHÁC HẲN lát đầy (549 IP × 10 log) và hai bên không so được với nhau — đúng cái
    # bẫy mà `RUN_PROJECT.md` đã cảnh báo cho lát đầy nhưng chưa vá ở đây.
    #
    # Gom theo họ để mỗi lô THUẦN một kỹ thuật (lô trộn thì không tồn tại đáp án đúng duy
    # nhất), rồi bỏ phần dư < 10 của từng họ thay vì dồn sang họ khác.
    _PER_IP = 10
    _by_tech: dict[str, list] = {}
    for e in csic_logs:
        if t := str(e.get("wa_mitre") or "").strip():
            _by_tech.setdefault(t, []).append(e)
    # CHIA VÒNG TRÒN từng lô 10, KHÔNG lấp đầy theo họ đông nhất trước. Lấp tuần tự thì họ
    # lớn nhất nuốt trọn ngân sách: đo được 250/250 mẫu dàn dựng đều là T1595.003, và bảng
    # quy kết của lát nhỏ chỉ còn đúng một kỹ thuật — vô dụng cho cả demo lẫn hậu kiểm.
    _pools = {t: list(v) for t, v in _by_tech.items() if len(v) >= _PER_IP}
    _budget = n_staged // _PER_IP  # số lô
    staged: list = []
    while _budget > 0 and _pools:
        for _t in sorted(_pools):
            if _budget <= 0:
                break
            staged.extend(_pools[_t][:_PER_IP])
            _pools[_t] = _pools[_t][_PER_IP:]
            _budget -= 1
        _pools = {t: v for t, v in _pools.items() if len(v) >= _PER_IP}
    for k, ev in enumerate(staged):
        # DẢI LIÊN TIẾP: 10 mẫu kề nhau -> cùng một IP, nên bộ đệm Tier-2 đầy 10 trước khi
        # timeout kịp chạm. /16 nên cần hai octet.
        _slot = k // _PER_IP
        ev["Source IP"] = f"{STAGED_IP_PREFIX}{_slot // 254}.{_slot % 254 + 1}"
        ev["demo_staged"] = True  # cờ CÔNG KHAI để hậu kiểm tách nhóm này ra
    if staged:
        print(
            f"[!] DÀN DỰNG: {len(staged)} mẫu CSIC CÓ mã kỹ thuật đổi IP -> "
            f"{STAGED_IP_PREFIX}x.x ({Counter(e.get('wa_mitre') for e in staged).most_common()})"
        )
        print(
            "    => cần bật trong config:  tier1.demo_escalate_waf_prefixes: "
            f'["{STAGED_IP_PREFIX}"]'
        )

    adv_raw = _build_adv_llm(gt_samples, tkey, n_adv)
    adv_logs = [enrich(e, demo_signals=True) for e in adv_raw]

    # CHỐT: IP của nhóm đối kháng phải RỜI HẲN mọi nguồn khác. Nếu trùng, lệnh chặn IP đè
    # lên cả hai nguồn và mọi thống kê tính theo IP nhiễm chéo — lỗi này ĐÃ xảy ra thật với
    # dải `172.16.x.x` (4 IP đụng DAPT2020). Chết sớm còn hơn dựng ra luồng bẩn.
    adv_ips = {e.get("Source IP") for e in adv_logs}
    other_ips = {e.get("Source IP") for e in subset} | {e.get("Source IP") for e in csic_logs}
    if clash := sorted(filter(None, adv_ips & other_ips)):
        raise SystemExit(
            f"IP nhóm đối kháng LLM đụng độ {len(clash)} IP của nguồn khác: {clash[:8]}\n"
            "Đổi dải trong `unified_dataset._build_adv_llm` (hiện dùng 198.18.0.0/15)."
        )

    # CHỐT: dải DÀN DỰNG phải là của RIÊNG lát đó. Nếu một sự kiện KHÁC lọt vào dải này thì
    # núm `demo_escalate_waf_prefixes` sẽ đổi hành vi cho cả nó — dàn dựng rò ra ngoài phạm
    # vi đã tuyên bố, đúng thứ khiến một buổi bảo vệ mất tín nhiệm.
    stray = [
        str(e.get("Source IP", ""))
        for e in (*subset, *csic_logs, *adv_logs)
        if str(e.get("Source IP", "")).startswith(STAGED_IP_PREFIX) and not e.get("demo_staged")
    ]
    if stray:
        raise SystemExit(
            f"{len(stray)} sự kiện KHÔNG dàn dựng lại nằm trong dải {STAGED_IP_PREFIX}*: "
            f"{sorted(set(stray))[:8]}"
        )
    adv_kinds = Counter(e.get("adv_llm_type") for e in adv_logs)
    print(f"[+] Đối kháng LLM (văn bản công khai): {len(adv_logs)} {dict(adv_kinds)}")

    # RẢI ĐỀU vào luồng NetFlow thay vì nối đuôi: nối đuôi thì Tier-1 gặp một khối L7 liền
    # mạch ở cuối, còn Dashboard thì im lìm suốt nửa đầu demo.
    extra = csic_logs + adv_logs
    if extra:
        gap = max(1, len(subset) // len(extra))
        merged: list = []
        it = iter(extra)
        for pos, ev in enumerate(subset):
            merged.append(ev)
            if pos % gap == 0:
                nxt = next(it, None)
                if nxt is not None:
                    merged.append(nxt)
        merged.extend(it)  # phần dư nếu subset ngắn hơn dự tính
        subset = merged

    with open(OUT_FILE, "w") as f:
        json.dump(subset, f, separators=(",", ":"))

    # --- Báo cáo phân bổ THẬT để đối chiếu --------------------------------- #
    n_atk = sum(1 for e in subset if _is_attack(e))
    src_ratio = _src_ratio
    print(f"\n[✓] Đã lưu {len(subset):,} sự kiện -> {OUT_FILE}")
    # Tập nhỏ được PHÂN TẦNG cho phủ panel, nên tỉ lệ tấn công CAO HƠN luồng đầy đủ theo
    # thiết kế. In cả hai cạnh nhau để không ai trích tỉ lệ của tập nhỏ như thể đó là hồ
    # sơ tải thật của hệ thống — con số đại diện cho tải nằm ở luồng đầy đủ.
    print(
        f"    Tỉ lệ tấn công: tập nhỏ {100 * n_atk / len(subset):.1f}% "
        f"vs luồng đầy đủ {src_ratio:.1f}% (cao hơn do PHÂN TẦNG, không phải hồ sơ tải)"
    )
    print(f"    Nguồn : {dict(Counter(e.get('unified_source') for e in subset).most_common())}")
    print(
        f"    Tấn công {n_atk:,} ({100 * n_atk / len(subset):.1f}%) · benign {len(subset) - n_atk:,}"
    )
    print(
        f"    Lớp tấn công: {len({e.get('gt_label') for e in subset if _is_attack(e) and e.get('gt_label')})}"
    )
    d2 = defaultdict(set)
    for e in subset:
        if e.get("apt_is_attack"):
            d2[e.get("Source IP")].add(e.get("apt_day"))
    print(f"    IP APT đa-ngày trong tập: {sum(1 for v in d2.values() if len(v) >= 2)} (cần >=1)")


if __name__ == "__main__":
    main()
