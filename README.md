> 本仓库的 `dist/` 目录由脚本自动生成并每日更新，请勿手工编辑。

# AdGuard 合并规则订阅（AdRules DNS + HaGeZi PRO）

把 **AdRules DNS** 与 **HaGeZi Multi PRO** 两份 DNS 级拦截规则合并去重，并自动把 AdRules 的
`mod/rules/dns-allowlist.txt` 转换成 AdGuard Home 能识别的 `@@` 例外规则，最终产出**一条订阅**。

## 为什么需要它

AdRules 的 `mod/rules/dns-allowlist.txt`（163 条）是纯域名清单，用于 AdRules 自身生成脚本的排除，
并非 AdGuard 语法的白名单。在 AdGuard 过滤语法中，**裸域名等价于拦截规则**（`x.com` 等于 `||x.com^`），
把它直接作为订阅引入会拦截清单内的全部域名，语义与预期相反。

本仓库将其改写成 `@@||域名^` 形式，并追加到合并清单末尾。`@@` 例外规则在 AdGuard 中的优先级
高于拦截规则，因此所在位置不影响生效。

## 订阅地址

```
https://raw.githubusercontent.com/0Neon0/adguard-merged-rules/main/dist/merged.txt
```

在 AdGuard Home 中添加：**过滤器 → DNS 黑名单 → 添加黑名单 → 添加自定义列表**，粘贴上述 URL。

该清单已包含两个上游源的全部拦截规则以及转换后的白名单例外，无需再单独添加 AdRules `dns.txt`、
HaGeZi `pro.txt` 或 `dns-allowlist.txt`，以避免规则重复加载。

## 另外两个产物

| 文件 | 用途 |
|---|---|
| `dist/merged.txt` | **主订阅**：拦截与例外一体，单条订阅即可 |
| `dist/allowlist.txt` | 仅含 `@@` 例外规则。需要将其挂到 AGH「自定义规则」并全局生效时使用 |
| `dist/stats.json` | 每次构建的统计数字（条数、去重数、例外数），机器可读 |

## 当前规模

> 下表为最近一次构建的快照，实时数字以 [`dist/stats.json`](dist/stats.json) 为准。

| 项 | 数值 |
|---|---|
| 合并前域名数 | 417,720 |
| 重复（被去掉） | 79,204 |
| **去重后拦截域名** | **338,516** |
| 通配拦截规则 | 409 |
| 正则拦截规则 | 27 |
| **拦截规则合计** | **338,952** |
| 例外规则 `@@` | 163 |

## 自动更新

`.github/workflows/update.yml` **每 12 小时**自动执行一次，起点为**北京时间 00:00**，
即每天 **北京时间 00:00 与 12:00** 各重建一次：

1. 重新拉取三个上游源
2. 合并 → 去重 → 转换白名单
3. 仅在内容变化时提交，无变化不产生空提交

也可手动触发：**Actions → 自动更新合并规则 → Run workflow**。

## 白名单转换规则

| 原始形态 | 转换结果 | 说明 |
|---|---|---|
| `x.com` | `@@\|\|x.com^` | 裸域名（159 条） |
| `\*.jbzj\.com` | `@@\|\|jbzj.com^` | `\|\|` 已覆盖全部子域 |
| `^[a-zA-Z0-9-]*\.*adtidy\.org$` | `@@/^[a-zA-Z0-9-]*\.*adtidy\.org$/` | 正则例外 |
| `is[0-9]\-ssl.mzstatic.com` | `@@/^is[0-9]-ssl\.mzstatic\.com$/` | 正则例外 |
| `liveweb\*\.msstatic\.com` | `@@/^liveweb.*\.msstatic\.com$/` | 正则例外 |

> 正则例外（`@@/.../`）需要 AdGuard Home 支持正则规则。若 AGH 报「无效规则」，删除这 3 行即可，
> 不影响其余 160 条例外。

## 本地重建

```bash
python scripts/build.py            # 输出到 dist/
python scripts/build.py --outdir out
```

只用 Python 标准库，无需安装任何依赖。

## 致谢

规则版权归原作者所有：

- [Cats-Team/AdRules](https://github.com/Cats-Team/AdRules)
- [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists)

本仓库只做「下载 → 合并去重 → 语法转换」，不修改任何规则的拦截意图。
