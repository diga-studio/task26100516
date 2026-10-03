# task26100516

## MailSentinel:离线 SPF 路径预算分析库

对域名到 SPF 记录文本的本地快照做离线分析,覆盖全部 IPv4 来源地址,
输出每段地址区间的最终判定(pass / fail / softfail / neutral / permerror)
与引用预算计数,用于定位只在部分来源地址上触发的超限(permerror)风险。

纯 Python 标准库实现,无第三方依赖,不访问网络。

### 语义要点

- 机制按文本顺序执行,首个匹配机制的限定符决定结果;支持 `ip4:CIDR`、
  `include:domain`、`all` 及限定符 `+ - ~ ?`(缺省 `+`),另支持
  `redirect=domain`(每条记录最多一个)。
- 无机制匹配时才执行 `redirect`,直接采用目标结果;无 redirect 返回 neutral。
- `include` 仅在目标返回 pass 时算匹配并应用自身限定符;目标返回
  fail / softfail / neutral 视为不匹配继续执行;permerror 立即向上传播。
- 每个来源地址的预算从 0 开始,跨嵌套累计:每个实际到达的 include 和
  实际执行的 redirect 先加一;初次读取根记录不计数。尝试第 11 次引用时
  立即返回 permerror(最终计数 11,不再读取目标)。重复引用同一域重复计数。
- 循环引用只影响实际走入循环的地址。

### 使用方法

```python
from mailsentinel import analyze

records = {
    "example.com": "v=spf1 ip4:203.0.113.0/24 include:spf.vendor.com -all",
    "spf.vendor.com": "v=spf1 ip4:198.51.100.0/24 ~all",
}
for iv in analyze(records, "example.com"):
    print(hex(iv.start), hex(iv.end), iv.verdict.value, iv.count)
```

`analyze(records, root)` 返回 `Interval` 列表,半开区间 `[start, end)`
(整数地址,`end` 可达 `2**32`),无重叠、无遗漏地覆盖全部 IPv4 空间;
相邻且判定与计数均相同的区间已合并。

### 目录结构

- `mailsentinel/types.py` — 结果枚举、机制、记录、区间等数据类型
- `mailsentinel/parser.py` — SPF 记录文本解析
- `mailsentinel/evaluator.py` — 单地址求值与预算计数(上限 10 次引用)
- `mailsentinel/analyzer.py` — 按 ip4 网段边界切分全地址空间并合并区间
- `tests/test_analyzer.py` — 自动化测试

### 运行测试

```sh
python3 -m pytest
```
