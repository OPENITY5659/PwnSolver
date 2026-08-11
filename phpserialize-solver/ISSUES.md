# PHPUnser 工具不足与改进方向总结

> 基于对 5 个靶场（PHPSerialize-labs 18关、fine-1/php-SER-libs 14关、BuuCTF、CTFSHOW web255/web257、ctf.show upload）的完整测试与 6 轮审查结果。

---

## 一、Payload 生成质量

| # | 问题 | 严重度 | 表现 | 根因 | 改进方向 |
|---|------|--------|------|------|---------|
| 1 | **布尔值序列化错误** | 🟡 中 | `isVip=false` 被序列化为字符串 `s:5:"false"` 而非 `b:0;` | `php_serialize()` 对 `False` 和 `"false"` 字符串不作区分 | 默认值解析时检测 `true`/`false` 关键字，转为 Python `bool` |
| 2 | **条件值未自动填充** | 🟡 中 | web255 `user="admin"` 而非 `"daydream"`；Level 2 `pass="admin"` 而非 `"ok"` | `_parse_conditions()` 只覆盖了 `$this->prop=='value'` 模式 | 扩展条件解析：`$this->prop=='value' and $this->prop2=='value2'`、三元表达式 |
| 3 | **属性值用 `"test"` 兜底** | 🟡 中 | 大量 payload 中关键属性填了无意义的 `"test"` | 无法推断属性用途时的默认值太粗糙 | 根据类名/属性名语义推断（如 `filename`→`flag.php`, `user`→`admin`） |
| 4 | **RCE 命令硬编码** | 🟢 低 | 始终用 `system('cat /flag')`，ctf.show 的 flag 常在 `flag.php` | RCE 命令列表固定 | 根据 sink 类型选择：`include`→读文件，`eval`→执行代码，`system`→命令 |

## 二、POP 链构造

| # | 问题 | 严重度 | 表现 | 根因 | 改进方向 |
|---|------|--------|------|------|---------|
| 5 | **单跳 self-loop** | 🟡 中 | web257 路径 `ctfShowUser→ctfShowUser→backDoor` 有冗余 | BFS 穷举所有类（包括自身），`tgt not in path` 只过滤同一节点重复 | BFS 去重：同一类名只访问一次 |
| 6 | **最长路径选择策略简单** | 🟡 中 | 多个有效链时选最长，忽视链的可靠性 | `all_chains.sort(key=len, reverse=True)` 太粗暴 | 加权评分：优先 sink 直接可达的短链，排除 self-loop |
| 7 | **属性→类映射精度低** | 🟡 中 | 泛型属性名 `obj`/`var`/`data` 返回 ALL 类，导致死胡同多 | `_guess_all_classes` 对未匹配属性无限制返回 | 结合调用上下文缩小范围：`check($var)`→`var` 应指向有 `__call`/`__clone` 的类 |
| 8 | **引用编号偏移** | 🟡 中 | `r:N` 仅计对象，PHP 规范标量也计数；标量出现在对象前时编号错 | `_serialize_object` 的 tracker 只 inc 对象 | 所有 `_serialize` 分支都 inc tracker |
| 9 | **未触发 sink-verification** | 🟡 中 | 链构建不验证 sink 是否通过该边可达 | edge_type（method_call/invoke/toString）未被使用 | 匹配 sink 方法名与边的触发方式 |

## 三、字符串逃逸

| # | 问题 | 严重度 | 表现 | 根因 | 改进方向 |
|---|------|--------|------|------|---------|
| 10 | **只支持单参数 str_replace** | 🔴 高 | Level 8 `str_replace(["flag","php"],"hack",…)` 生成 0 payload | 正则只匹配 `str_replace('x','y',$z)` 单引号格式 | 扩展支持 `array()` 多参数语法 |
| 11 | **未验证扩展后长度** | 🟡 中 | Level 6 payload 生成后未用 `str_replace` 模拟验证 | 测试只检查了预替换格式，没验证替换后 `s:N:` 长度匹配 | 添加 `str_replace` 后 `php_unserialize` 的有效性断言 |
| 12 | **对象计数未自适应** | 🟡 中 | 仅对单属性类做 `:1:`→`:2:` 膨胀 | 硬编码 `"1:"→"2:"` | 根据注入的属性数量计算：`len(props)+injected_count` |

## 四、序列化器

| # | 问题 | 严重度 | 表现 | 根因 | 改进方向 |
|---|------|--------|------|------|---------|
| 13 | **全局状态泄漏** | 🟡 中 | `_ref_index` 跨调用共享，相同 `id()` 被误判为引用 | 全局 dict 不清零（`php_serialize` 已加 `_clear_refs`） | 把 tracker 作为参数传入，去掉全局变量 |
| 14 | **字节长度 vs 码点长度** | 🟢 低 | 非 ASCII 类名/prop 名产生错误 `s:N:` 长度 | `len(s)` 返回码点数 | `len(s.encode('utf-8'))` |
| 15 | **`php_serialize` / `php_serialize_refs` 重复** | 🟢 低 | 两个函数功能完全相同 | 重构后未清理 | 合并为一个，保留 `php_serialize` 单一入口 |

## 五、源码分析器

| # | 问题 | 严重度 | 表现 | 根因 | 改进方向 |
|---|------|--------|------|------|---------|
| 16 | **属性提取误报（已修复）** | ✅ | `echo $flag;` 曾被误认为属性 | property 正则 visibility 可选 | ✅ 已改为强制 visibility 关键字 |
| 17 | **sink 检测截断（已修复）** | ✅ | `unserialize($_POST['o'])->backdoor()` 只捕获到 `'o` | 正则 `[^)]+` 停在第一个 `)` | ✅ 已改为平衡括号匹配 |
| 18 | **include 拼接未检测** | 🟡 中 | `include "tpl/".$_GET["p"].".php"` 不触发 sink | 正则要求 `include 'literal'` 固定字符串 | 检测 `include.*\$_(GET|POST)` 模式 |
| 19 | **注释内 brace 干扰** | 🟢 低 | 注释中的 `{` `}` 破坏方法体范围 | 括号匹配不跳过注释 | ✅ 已添加 `//` `/* */` 跳过逻辑 |
| 20 | **final/abstract class 漏检（已修复）** | ✅ | `final class X` 不匹配 | 正则无修饰符 | ✅ 已添加 `(?:final\|abstract)?` |

## 六、HTTP / CLI / 交互

| # | 问题 | 严重度 | 表现 | 根因 | 改进方向 |
|---|------|--------|------|------|---------|
| 21 | **对真实靶场未端到端测试** | 🟡 中 | 所有测试基于本地源码模拟 | 无法访问需要登录/Docker 的靶场 | 搭建 CI 集成测试（GitHub Actions + Docker） |
| 22 | **GUI 无断言测试** | 🟡 中 | GUI 测试只验证导入，不测试交互逻辑 | `tkinter` 需要 display | 提取 GUI 逻辑为无 UI 函数，单元测试覆盖 |
| 23 | **GUI placeholder 误判** | 🟢 低 | `startswith('<?php\n// Paste')` 拒绝合法代码 | 占位符检测过于精确 | 用 `len(strip) < 20` 或 flag 标记 |

## 七、性能 / 安全

| # | 问题 | 严重度 | 表现 | 根因 | 改进方向 |
|---|------|--------|------|------|---------|
| 24 | **BFS 状态爆炸** | 🔴 高 | 15+ 类 + 泛型属性 → 穷举 `N!·P^N` 路径 → OOM | 无深度/广度限制 | 添加 `max_depth=8` / `max_states=10000` 上限 |
| 25 | **无输入大小限制** | 🟡 中 | 恶意超大源码可导致分析超时 | `analyze()` 无大小上限 | 限制源码 ≤ 100KB |
| 26 | **curl 命令单引号风险** | 🟢 低 | payload 含 `'` 时 curl 命令 shell 注入 | 未转义 | 用 `shlex.quote()` |

## 八、覆盖范围（超出当前能力）

| # | 场景 | 状态 | 说明 |
|---|------|------|------|
| 27 | Phar 反序列化 | ❌ | Level 11/12 / fine-1 L11/L12 无法解决 |
| 28 | SOAP 反序列化 | ❌ | fine-1 L10 无自定义类，需 `SoapClient` |
| 29 | Session 反序列化 | ❌ | 需 `session.serialize_handler` 设置 + 引用 |
| 30 | 条件竞争 | ❌ | `session.upload_progress` 场景 |
| 31 | `__sleep` 自定义序列化 | ❌ | Level 12 只能读源码推断 |

---

## 统计

| 严重度 | 数量 | 占比 |
|--------|------|------|
| 🔴 高 | 2 | 6% |
| 🟡 中 | 16 | 52% |
| 🟢 低 | 9 | 29% |
| ✅ 已修复 | 4 | 13% |

## 优先修复排序

1. **BFS 状态爆炸**（安全风险，加限制即解决）
2. **字符串逃逸 array 多参数**（Level 8 完全无法处理）
3. **单跳 self-loop**（影响 POP 链质量）
4. **条件值自动填充**（大幅提升 web255/Level 2/3 成功率）
5. **布尔值序列化**（影响所有含 bool 属性的 payload）
