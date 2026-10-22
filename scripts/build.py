#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdGuard Merged Rules —— 构建器
=============================

把两份 DNS 级拦截规则合并去重，并把 AdRules 的「纯域名白名单源」
自动转换成 AdGuard Home 可识别的 `@@` 例外语法，产出**单条订阅**。

输入源
------
1. Cats-Team/AdRules          -> dns.txt                  (adblock 格式, DNS 级拦截)
2. hagezi/dns-blocklists      -> adblock/pro.txt          (adblock 格式, DNS 级拦截)
3. Cats-Team/AdRules          -> mod/rules/dns-allowlist.txt
   (纯域名排除源：给 AdRules 自己的生成脚本用的,**不是**可订阅的白名单)

输出
----
dist/merged.txt     单条订阅 = 去重后的「源1 ∪ 源2」+ 追加的 `@@` 例外
dist/allowlist.txt  只含 `@@` 例外(想单独挂白名单时用)
dist/stats.json     机器可读的统计数字

设计要点
--------
* 只用标准库,无需 pip install —— 便于在 GitHub Actions 里零配置运行。
* **不丢规则**：源里的三类规则全部保留 ——
    ① 纯域名规则  `||domain^`   (参与按域名的语义去重)
    ② 通配规则    `||*ad.example.com^` 等 (无法按裸域名去重,按原文精确去重)
    ③ 正则规则    `/^re$/`      (按原文精确去重)
* 输出**排序后**写入,保证同样的输入产出逐字节相同的文件,使 git diff 稳定、
  Actions 不会因为顺序抖动而刷无意义的 commit。
* 例外规则(`@@`)在 AdGuard 语法里**优先级永远高于**拦截规则,所以放在文件
  末尾即可生效,不依赖顺序。
* 例外规则也**写进 merged.txt**,这样用户只订阅一条 URL 就能同时得到
  「拦截 + 放行」,不必再手动维护第二份清单。

用法
----
    python scripts/build.py                # 正常构建
    python scripts/build.py --outdir out   # 输出到别处
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# --------------------------------------------------------------------------
# 源定义
# --------------------------------------------------------------------------

REPO = "0Neon0/adguard-merged-rules"

SOURCES = {
    "adrules": {
        "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
        "label": "AdRules DNS List",
        "homepage": "https://github.com/Cats-Team/AdRules",
    },
    "hagezi": {
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
        "label": "HaGeZi's Multi PRO",
        "homepage": "https://github.com/hagezi/dns-blocklists",
    },
    "allowlist": {
        "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/mod/rules/dns-allowlist.txt",
        "label": "AdRules allowlist (plain-domain exclusion source)",
        "homepage": "https://github.com/Cats-Team/AdRules",
    },
}

UA = f"adguard-merged-rules/1.0 (+https://github.com/{REPO})"

# 裸域名:仅由字母数字和 . - _ 组成
RE_PLAIN_DOMAIN = re.compile(r"^[a-zA-Z0-9._-]+$")
# 纯域名规则 `||domain^`(域名部分不含 * ^ |)
RE_ABP_DOMAIN = re.compile(r"^\|\|([^\^*|]+)\^$")
# 正则规则 `/.../`
RE_REGEX_RULE = re.compile(r"^/.*/$")


# --------------------------------------------------------------------------
# 下载
# --------------------------------------------------------------------------

def fetch(url: str, retries: int = 3, timeout: int = 90) -> str:
    """下载文本,失败按指数退避重试。返回解码后的字符串。"""
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
            return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            if attempt < retries:
                wait = 2 ** attempt
                print(f"    ! 第 {attempt} 次失败 ({exc}),{wait}s 后重试",
                      file=sys.stderr)
                time.sleep(wait)
    raise RuntimeError(f"下载失败 {url}: {last}")


# --------------------------------------------------------------------------
# 解析
# --------------------------------------------------------------------------

class Blocklist:
    """一份拦截列表解析后的三个桶。"""

    __slots__ = ("domains", "wildcards", "regexes", "skipped", "unparsed")

    def __init__(self) -> None:
        self.domains: set[str] = set()    # 裸域名 -> 可语义去重
        self.wildcards: set[str] = set()  # 含 * 的规则,按原文留存
        self.regexes: set[str] = set()    # /正则/
        self.skipped: int = 0             # 注释/表头
        self.unparsed: list[str] = []     # 认不出来的,原样保留

    @property
    def total_rules(self) -> int:
        return len(self.domains) + len(self.wildcards) + len(self.regexes) \
            + len(self.unparsed)


def parse_blocklist(text: str) -> Blocklist:
    """
    解析 adblock 格式的拦截列表。**任何非注释行都会被保留**,
    不会因为形态不标准而被静默丢弃。
    """
    bl = Blocklist()

    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("!") or s.startswith("["):
            bl.skipped += 1
            continue

        m = RE_ABP_DOMAIN.match(s)
        if m:
            bl.domains.add(m.group(1).lower())
            continue

        if RE_REGEX_RULE.match(s):
            bl.regexes.add(s)
            continue

        if "*" in s and s.startswith("||"):
            # 通配规则:保留原文(小写化以稳定去重)
            bl.wildcards.add(s.lower())
            continue

        # 兜底:不认识的形态也留着,绝不丢
        bl.unparsed.append(s)

    return bl


def domain_to_wildcard_regex(raw: str) -> str:
    """
    把形如 `liveweb*.msstatic.com` 的条目转成锚定正则 `^liveweb.*\\.msstatic\\.com$`。
    点号转义,`*` 变 `.*`。其余字符原样(它们已是字面量)。
    """
    out = []
    for ch in raw:
        if ch == "*":
            out.append(".*")
        elif ch == ".":
            out.append(r"\.")
        else:
            out.append(ch)
    return "^" + "".join(out) + "$"


def parse_allowlist(text: str) -> tuple[list[str], list[str], list[str]]:
    """
    解析 AdRules 的纯域名白名单源,转换成 AdGuard Home 例外规则。

    返回 (裸域名列表, 已生成的正则例外列表, 需要人工确认的原始行列表)。

    转换策略(按优先级):
      1. 裸域名                  x.com          -> @@||x.com^
      2. 纯子域通配              \\*.jbzj\\.com   -> @@||jbzj.com^   (`||` 已覆盖子域)
      3. 内嵌通配                liveweb\\*.msstatic\\.com
                                                 -> @@/^liveweb.*\\.msstatic\\.com$/
      4. 含字符类/锚点           ^...$  [0-9]    -> @@/ ^...$ /     (保留精确语义)
      5. 其它                                    记入 manual,不猜
    """
    plain: list[str] = []
    regex_exceptions: list[str] = []
    manual: list[str] = []

    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("!"):
            continue

        # 1) 裸域名
        if RE_PLAIN_DOMAIN.match(s):
            plain.append(s.lower())
            continue

        stripped = s.replace("\\", "")

        # 2) 纯子域通配 `*.example.com`
        if stripped.startswith("*.") and RE_PLAIN_DOMAIN.match(stripped[2:]):
            plain.append(stripped[2:].lower())
            continue

        # 4) 含正则元字符 -> 按正则处理。**保留原有反斜杠转义**(如 `\.`),
        #    不要用 stripped 版本,否则点号会退化成「任意字符」。
        if any(ch in s for ch in "^$[]()"):
            regex_exceptions.append(f"@@/{s}/")
            continue

        # 3) 内嵌 `*` 通配 -> 构造锚定正则
        if "*" in stripped:
            regex_exceptions.append(f"@@/{domain_to_wildcard_regex(stripped)}/")
            continue

        # 5) 认不出来
        manual.append(s)

    return sorted(set(plain)), sorted(set(regex_exceptions)), sorted(set(manual))


# --------------------------------------------------------------------------
# 构建
# --------------------------------------------------------------------------

def build(outdir: Path) -> dict:
    print("== 下载源文件 ==")
    texts: dict[str, str] = {}
    for key, meta in SOURCES.items():
        print(f"  - {key:9s} {meta['url']}")
        texts[key] = fetch(meta["url"])
        print(f"      {len(texts[key]):,} 字符")

    print("\n== 解析 ==")
    a = parse_blocklist(texts["adrules"])
    h = parse_blocklist(texts["hagezi"])
    for name, bl in (("AdRules", a), ("hagezi ", h)):
        print(f"  {name}  域名 {len(bl.domains):,}  通配 {len(bl.wildcards)}"
              f"  正则 {len(bl.regexes)}  表头 {bl.skipped}"
              f"  未识别 {len(bl.unparsed)}")

    overlap = a.domains & h.domains
    merged_dom = a.domains | h.domains
    merged_wild = a.wildcards | h.wildcards
    merged_re = a.regexes | h.regexes
    unparsed = sorted(set(a.unparsed) | set(h.unparsed))
    print(f"  重叠 {len(overlap):,}  ->  去重后 {len(merged_dom):,} 个域名")

    allow_plain, allow_re, allow_manual = parse_allowlist(texts["allowlist"])
    print(f"  白名单:裸域名 {len(allow_plain)}  正则例外 {len(allow_re)}"
          f"  待人工 {len(allow_manual)}")

    stamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    before_total = len(a.domains) + len(h.domains)

    # ---------------- merged.txt ----------------
    lines: list[str] = [
        "[Adblock Plus 2.0]",
        "! Title: AdGuard 合并规则（AdRules DNS + HaGeZi PRO 双源去重）",
        "! Description: 去重合并的 DNS 级拦截规则,并内嵌 AdRules 白名单转换出的例外规则。",
        f"! Homepage: https://github.com/{REPO}",
        f"! Last modified: {stamp}",
        "!",
        "! ==== 来源 ====",
    ]
    for key in ("adrules", "hagezi"):
        m = SOURCES[key]
        lines.append(f"!   - {m['label']}: {m['homepage']}")
    lines += [
        f"!   - 白名单源: {SOURCES['allowlist']['homepage']}"
        " (mod/rules/dns-allowlist.txt)",
        "!",
        "! ==== 统计 ====",
        f"!   拦截域名       : {len(merged_dom):,}",
        f"!   通配拦截规则   : {len(merged_wild)}",
        f"!   正则拦截规则   : {len(merged_re)}",
        f"!   合并前域名条数 : {before_total:,}",
        f"!   合并省下的重复 : {len(overlap):,}",
        f"!   例外规则(@@)   : {len(allow_plain) + len(allow_re)}",
        "!",
        "! ==== 拦截规则·域名 ====",
    ]

    for d in sorted(merged_dom):
        lines.append(f"||{d}^")

    if merged_wild:
        lines += ["!", "! ==== 拦截规则·通配 ===="]
        lines += sorted(merged_wild)

    if merged_re:
        lines += ["!", "! ==== 拦截规则·正则 ===="]
        lines += sorted(merged_re)

    if unparsed:
        lines += ["!", "! ==== 未归类规则(原样保留) ===="]
        lines += unparsed

    lines += [
        "!",
        "! ==== 例外规则(白名单) ====",
        "! 由 AdRules 的 mod/rules/dns-allowlist.txt 自动转换而来。",
        "! 该源是「纯域名」清单,在 AdGuard 里裸域名等于拦截规则,",
        "! 因此必须改写成 @@||域名^ 才能起到放行作用。",
        "!",
    ]
    for d in allow_plain:
        lines.append(f"@@||{d}^")
    for r in allow_re:
        lines.append(r)
    if allow_manual:
        lines.append("!")
        lines.append("! 以下条目含非标准语法,未自动转换,需人工确认:")
        for s in allow_manual:
            lines.append(f"!   {s}")

    merged_text = "\n".join(lines) + "\n"

    # ---------------- allowlist.txt ----------------
    al: list[str] = [
        "[Adblock Plus 2.0]",
        "! Title: AdRules 白名单（AdGuard 可用例外规则）",
        "! Description: 由 AdRules mod/rules/dns-allowlist.txt 转换而来的 @@ 例外规则。",
        f"! Homepage: https://github.com/{REPO}",
        f"! Last modified: {stamp}",
        f"! 例外条数: {len(allow_plain) + len(allow_re)}",
        "!",
    ]
    for d in allow_plain:
        al.append(f"@@||{d}^")
    for r in allow_re:
        al.append(r)
    allow_text = "\n".join(al) + "\n"

    # ---------------- 写出 ----------------
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "merged.txt").write_text(merged_text, encoding="utf-8", newline="\n")
    (outdir / "allowlist.txt").write_text(allow_text, encoding="utf-8", newline="\n")

    stats = {
        "generated_at": stamp,
        "sources": {k: v["url"] for k, v in SOURCES.items()},
        "blocking_domains": len(merged_dom),
        "blocking_wildcards": len(merged_wild),
        "blocking_regexes": len(merged_re),
        "blocking_total": len(merged_dom) + len(merged_wild) + len(merged_re),
        "before_merge_total": before_total,
        "duplicates_removed": len(overlap),
        "exception_rules": len(allow_plain) + len(allow_re),
        "exceptions_from_plain_domains": len(allow_plain),
        "exceptions_from_regex": len(allow_re),
        "allowlist_manual_review": allow_manual,
        "unparsed_rules": len(unparsed),
        "per_source": {
            "adrules": {
                "domains": len(a.domains),
                "wildcards": len(a.wildcards),
                "regexes": len(a.regexes),
            },
            "hagezi": {
                "domains": len(h.domains),
                "wildcards": len(h.wildcards),
                "regexes": len(h.regexes),
            },
        },
        "merged_lines": len(lines),
        "merged_bytes": len(merged_text.encode("utf-8")),
    }
    (outdir / "stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print("\n== 产出 ==")
    for f in sorted(outdir.iterdir()):
        print(f"  {f.name:16s} {f.stat().st_size:>12,} bytes")

    if unparsed:
        print(f"\n! 注意:{len(unparsed)} 条规则未能归类,已原样保留(见 dist/merged.txt)")
    if allow_manual:
        print(f"! 注意:{len(allow_manual)} 条白名单条目需人工确认")

    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description="合并 AdRules + hagezi 拦截规则")
    ap.add_argument("--outdir", default="dist", help="输出目录(默认 dist)")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    outdir = Path(args.outdir) if Path(args.outdir).is_absolute() \
        else root / args.outdir

    stats = build(outdir)
    print(f"\n完成: 拦截 {stats['blocking_total']:,} 条"
          f"(域名 {stats['blocking_domains']:,} / 通配 {stats['blocking_wildcards']}"
          f" / 正则 {stats['blocking_regexes']}),"
          f" 例外 {stats['exception_rules']} 条")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
