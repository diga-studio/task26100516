# MailSentinel

离线 SPF 路径预算分析库：基于域名 → SPF 记录文本的本地快照，分析全部 IPv4
来源地址的 SPF 判定与引用预算计数，并定位只在部分地址段上触发的超限
（permerror）风险。

## 功能

- `analyze(records, root)` 返回无重叠、无遗漏覆盖 `0.0.0.0`–`255.255.255.255`
  的区间列表，每段携带最终判定（`pass`/`fail`/`softfail`/`neutral`/`permerror`）
  与引用计数；判定与计数均相同的相邻区间会被合并。
- 支持机制 `ip4:CIDR`、`include:domain`、`all` 与修饰符 `redirect=domain`，
  限定符 `+ - ~ ?`（缺省 `+`）。
- 预算语义：每个实际到达的 include 与执行的 redirect 计 1（初次读取根记录不计），
  第 11 次引用立即返回 `permerror` 且计数为 11；循环引用只影响实际走入循环的地址。

## 原理

所有 `ip4` CIDR 的边界把 IPv4 空间切成原子段；同一段内每个机制的匹配结果一致，
因此对每个原子段做一次带预算计数的递归求值，再合并相邻同值区间即可。

## 使用

```python
from mailsentinel import analyze

intervals = analyze(
    {
        "example.com": "v=spf1 ip4:0.0.0.0/1 include:loop.example -all",
        "loop.example": "v=spf1 include:loop.example",
    },
    "example.com",
)
for iv in intervals:
    print(iv.start, "-", iv.end, iv.verdict, iv.count)
# 0.0.0.0 - 127.255.255.255 pass 0
# 128.0.0.0 - 255.255.255.255 permerror 11
```

## 运行测试

```bash
python3 -m unittest discover -s tests -v
```

仅依赖 Python 3.8+ 标准库，无需安装第三方包。
