"""Generate the vendor name badges used in README.md.

These are plain text badges, not vendor logos: no vendor artwork is stored in
this repository because none of the vendors' brand terms were checked.
Run `python3 docs/vendors/build_badges.py` to regenerate the SVG files.
"""
from pathlib import Path
from xml.sax.saxutils import escape

VENDORS = [
    ("espressif", "乐鑫", "Espressif"),
    ("bouffalo", "博流", "Bouffalo"),
    ("winnermicro", "联盛德", "WinnerMicro"),
    ("wch", "沁恒", "WCH"),
    ("gigadevice", "兆易", "GigaDevice"),
    ("hdsc", "华大", "HDSC"),
    ("nationstech", "国民技术", "Nations"),
    ("rockchip", "瑞芯微", "Rockchip"),
    ("allwinner", "全志", "Allwinner"),
    ("telink", "泰凌微", "Telink"),
    ("realtek", "瑞昱", "Realtek"),
    ("sifli", "思澈", "SiFli"),
    ("openluat", "合宙", "openLuat"),
    ("huawei", "华为", "LiteOS / OpenHarmony"),
    ("tencent", "腾讯", "TencentOS-tiny"),
    ("alibaba", "阿里", "AliOS Things"),
    ("rt-thread", "睿赛德", "RT-Thread"),
    ("gmssl", "北大", "GmSSL"),
    ("tongsuo", "蚂蚁", "Tongsuo"),
]


def width(text):
    return sum(14 if ord(c) > 0x2E80 else 7.2 for c in text)


def badge(zh, en):
    left, right = width(zh) + 16, width(en) + 16
    total = left + right
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total:.0f}" height="24" '
        f'role="img" aria-label="{escape(zh)} {escape(en)}">'
        f'<rect width="{total:.0f}" height="24" rx="4" fill="#f6f8fa" stroke="#d0d7de"/>'
        f'<rect width="{left:.0f}" height="24" rx="4" fill="#24292f"/>'
        f'<rect x="{left - 4:.0f}" width="4" height="24" fill="#24292f"/>'
        '<g font-family="-apple-system,\'PingFang SC\',\'Microsoft YaHei\',sans-serif" '
        'font-size="12" text-anchor="middle">'
        f'<text x="{left / 2:.0f}" y="16" fill="#ffffff">{escape(zh)}</text>'
        f'<text x="{left + right / 2:.0f}" y="16" fill="#24292f">{escape(en)}</text>'
        '</g></svg>\n'
    )


if __name__ == "__main__":
    out = Path(__file__).parent
    for slug, zh, en in VENDORS:
        (out / f"{slug}.svg").write_text(badge(zh, en), encoding="utf-8")
