# Intel (x86_64) 适配逆向指南

本文档记录 SovietExtension 防撤回 / 多开在 **Intel 芯片 Mac** 上的适配方法，以及已完成版本的
**x86_64 `wechat.dylib`** 静态地址和结构漂移。

## 已完成的部分（无需逆向）

| 项 | 状态 | 说明 |
|---|---|---|
| 插件编译为 universal (x86_64+arm64) | ✅ | 见 `Rely/build_framework.sh`，无需完整 Xcode |
| Intel 微信可加载插件 | ✅ | 实测注入 x86_64 微信进程，构造函数正常执行 |
| 阻止更新 (Anti-Update) | ✅ | 纯 Objective-C runtime hook，架构无关 |
| 苏维埃助手菜单 | ✅ | 纯 Cocoa，架构无关 |
| x86_64 补丁原语 | ✅ | `YMPatchX86ReturnYES` / `YMPatchX86AbsoluteJump` |
| x86_64 安全护栏 | ✅ | 地址未填时自动跳过补丁，**不会乱写、不崩溃** |
| **防撤回 (Anti-Revoke)** | ✅ | 4.1.10、4.1.12 / 269340 的核心拦截和详细灰条均已实测 |
| **真·多开 (Multi-Open)** | ✅ / 部分 | 4.1.10 已适配；4.1.12 地址尚未确认，安全跳过 |

## 为什么不能直接复用 arm64 的地址

`RevokePatch.mm` 里防撤回/多开的原理是：用 IDA/Hopper 逆向出的**静态 VM 地址** + 运行时
ASLR slide 定位 `wechat.dylib` 内部函数，再写入机器码补丁。

- arm64 切片和 x86_64 切片虽然来自同一份源码，但**函数地址完全不同**。
- 补丁字节也不同：arm64 是 `mov w0,#1; ret`，x86_64 是 `mov eax,1; ret`（代码里已分别实现）。

所以每个新 build 都必须在 **x86_64 切片**上重新确认调用点和布局，不能只沿用旧地址。

## 4.1.12 / 269340 防撤回适配（2026-07-27）

当前 Intel 微信信息：

```text
CFBundleShortVersionString = 4.1.12
CFBundleVersion = 269340
```

从 universal `wechat.dylib` 切出的 x86_64 切片中，已定位新版
`CoReplaceOriginMessageByRevoke` 等价函数：

```text
函数入口：          0x3433c90
原消息查询 callsite：0x34346db
真实查询函数：      0x300cfe0
```

调用点反汇编：

```asm
34346bf: mov rdx, [rbp-0x670]
34346c6: mov rcx, [rdx+0x198]   ; svrId
34346cd: add rdx, 0x1b8         ; session std::string*
34346d4: lea rdi, [rbp-0x948]   ; outWrap
34346db: call 0x300cfe0
```

与 4.1.10 / 268853 相比，关键布局发生了以下漂移：

| 字段 | 4.1.10 | 4.1.12 |
|---|---:|---:|
| context 中的 `svrId` | `0x168` | `0x198` |
| session 参数 | `0x188` | `0x1b8` |
| 查询结果有效 / UI 替换标志 | `0x268` (616) | `0x270` (624) |
| 查询结果拷贝大小 | `0x270` | `0x278` |

新版标志偏移可由以下指令关系确认：查询前 `mov edx, 0x278`，结果位于
`[rbp-0x948]`，查询后判断 `cmp byte ptr [rbp-0x6d8], 1`，两者相差 `0x270`。

实现上，`RevokePatch.mm` 的 `YMRevokeX86CallsiteLayout` 按 profile 保存这些偏移。
wrapper 调用真实查询后立即清有效标志，从而保留原消息。

详细灰条也已静态确认：完整 XML 模板位于 `0x8a331c0`，有两个函数引用。其中
`0x43e41b0` 的入口调用约定是 `rsi=session std::string*`、`rdx=content std::string*`，
且会构造 type=10000 MessageWrap，因此它是新版 `insertPaySysMsgToSessionVA`。
MessageWrap 构造函数和 `SetMsgType` 交叉确认详细字段仍为：

```text
originTypeOffset          = 0x108
originCreateTimeMsOffset  = 0x100
originCreateTimeSecOffset = 0x114
originContentOffset       = 0x130
```

`SetMsgType` 会同时写 `+0x0c` 和 `+0x108`；灰条构造函数分别在 `+0x100`、`+0x114`、
`+0x130` 填入毫秒时间、秒时间和格式化后的 XML 内容。

安装后用普通文字消息完成实机撤回测试，日志确认完整链路：

```text
[X86Callsite] origin captured ... type=1 ... contentLen=7
[RevokeCallsite] insert detailed notice result=<non-zero>
```

原消息保留，包含消息类型、原文、撤回人和时间的自定义详细灰条成功插入。

安装补丁前还会校验 callsite 前 28 字节的四条参数准备指令、`svrId/session` 偏移以及
`E8` opcode。地址或结构不匹配时会拒绝写入，避免误 patch 其他调用。

## 需要逆向填入的字段

文件：`SovietExtension/RevokePatch.mm`，`#elif defined(__x86_64__)` 分支下对应版本的 profile。
4.1.10 已完成全部关键地址；适配新版本时按功能逐项确认，未知字段保持为 `0`：

| 字段 | arm64(4.1.10) 参考 | 含义 / 逆向线索 |
|---|---|---|
| `hookPointerVA` | `0x2846E84` | 含义由 `hookMode` 决定；`YMRevokeHookModeX86Callsite` 下填写原消息查询 `call` 指令的 VA |
| `revokeX86Callsite` | N/A | x86 callsite 的 `svrId/session/result flag` 偏移；详细灰条字段未确认时可单独留 0 |
| `rawMessageTemplateVA` | `0x7A7AD88` | 撤回 MessageWrap 模板数据（被 memcpy 616 字节） |
| `messageWrapFromRawVA` | `0x482F54C` | 由 raw 构造 MessageWrap 的函数 |
| `messageWrapDestructVA` | `0x2123AC0` | MessageWrap 析构函数 |
| `insertPaySysMsgToSessionVA` | `0x38EBBFC` | 插入本地 type=10000 系统消息的函数 |
| `YMMultiOpenTryPreventMultiInstanceVA` | `0x1C4EA8` | 防多开判断函数（patch 成返回 YES） |

> 不要假定新版 `layout` 与旧版或 arm64 相同。4.1.12 已证明结果标志和 context 字段均有漂移；
> 未确认的详细提示字段应保持为 `0`，让核心防撤回独立工作。

## 逆向方法（命令行已验证可行）

### 1. 切出 x86_64 切片
```bash
lipo /Applications/WeChat.app/Contents/Resources/wechat.dylib -thin x86_64 -output /tmp/wx_x86
lipo /Applications/WeChat.app/Contents/Resources/wechat.dylib -thin arm64  -output /tmp/wx_arm
```
两个切片的 `__TEXT` 段都是 `vmaddr=0, fileoff=0`，所以**静态 VA == 文件偏移**（__TEXT 内）。

### 2. 用已知 arm64 地址提取「字符串锚点」
先反汇编 arm64 的目标函数，看它引用了哪些字符串常量：
```bash
# 按地址范围反汇编（objdump 支持 --start/--stop-address）
objdump -d --start-address=0x38EBBFC --stop-address=0x38EC400 /tmp/wx_arm
```
找到形如 `adrp xN, <page>` + `add xN, #<off>` 指向的常量地址，再读出内容：
```bash
dd if=/tmp/wx_arm bs=1 skip=$((0x<常量VA>)) count=32 2>/dev/null | xxd
```
> 已确认的锚点示例：`insertPaySysMsg` 相关函数会构造字符串 **`native_applet`**（13 字节，arm64 位于 `0x898c586`）。

### 3. 在 x86_64 切片里反向定位
- 字符串本身在 `__cstring`，两个切片内容相同、地址不同。
- 用 `otool -tV /tmp/wx_x86` 反汇编（量大，建议配合 `grep` 找 `## "字符串"` 注释），
  或对 x86_64 做全量反汇编建立「字符串 → 引用它的函数」索引。
- 用同一锚点字符串确定 x86_64 函数后，函数入口 VA 即所需地址。

### 4. 数据模板（rawMessageTemplate）
- 若该模板是纯只读常量，可用 arm64 的 616 字节在 x86_64 里做字节匹配定位。
- ⚠️ 实测 arm64 的 `0x7861730` 区域是高熵且含重复，**可能内嵌切片相关指针**，
  直接字节匹配未必成立，需在反汇编器里确认其引用点。

### 5. 验证（务必先验证再写真机）
- 填好地址后 `sh Rely/build_framework.sh` 重新编译。
- 用 `lldb` attach 到一份**测试用**微信，确认补丁点的反汇编是预期的函数序言（function prologue），
  机器码长度足够容纳 12 字节 inline jump，且不会切断后续被跳转进来的指令。
- 确认 `insertPaySysMsgToSession`、`messageWrapFromRaw` 等调用约定（x86_64 参数走
  `rdi/rsi/rdx/rcx/r8/r9`，C++ `this` 在 `rdi`）与函数签名一致。

## 实测进展与结论（2026-06-21，CLI 逆向）

已用命令行做了完整尝试，结论是**这部分必须上反汇编器**，原因有据可查：

1. ✅ `LC_FUNCTION_STARTS` 方法可靠：
   ```bash
   objdump --macho --function-starts /tmp/wx_x86 > /tmp/fs_x86.txt   # 34.5 万个函数入口
   ```
   5 个已知 arm64 地址（hook 目标 / messageWrapFromRaw / messageWrapDestruct /
   insertPaySysMsg / multiOpen）全部确认是函数入口，dylib 与 build 268853 匹配。

2. ✅ 已生成可复用的索引（约 1GB，放 /tmp，仅用 grep 查询）：
   ```bash
   otool -tV /tmp/wx_x86 > /tmp/dis_x86.txt
   otool -tV /tmp/wx_arm > /tmp/dis_arm.txt
   grep -nE 'literal pool for:|Objc message:' /tmp/dis_x86.txt > /tmp/xref_x86.txt
   ```

3. ❌ **关键障碍**：把已知 arm64 目标函数的函数体逐一检查后发现——
   - 防撤回链 4 个函数（hook 目标 0x2846E84、messageWrapFromRaw 0x482F54C、
     messageWrapDestruct 0x2123AC0、insertPaySysMsg 0x38EBBFC）**函数体内 0 个字符串引用**，
     没有任何可用于跨架构匹配的字符串锚点。
   - 多开函数 0x1C4EA8 引用 ObjC class/selector，但 `otool -tV` 解析为
     `Objc class ref: bad class ref` 和通用 `_objc_msgSend`，拿不到可锚定的名字。

   ⇒ 这些函数只能靠**调用图结构 + ObjC 元数据解析 + 反编译**来跨架构匹配，
     即 IDA/Hopper（+ BinDiff/Diaphora 做 arm64↔x86_64 函数比对）。grep/otool 无法可靠完成。

### 建议的最终路线（反汇编器）
1. IDA/Hopper 分别加载 arm64、x86_64 两个切片。
2. 在 arm64 切片用本仓库已知地址定位 6 个目标函数，重命名。
3. 用 BinDiff/Diaphora 对两切片做函数比对，自动得到 x86_64 对应函数入口。
4. 人工复核（尤其 hook 目标的函数序言要能容纳 12 字节 inline jump）。
5. 填入 `RevokePatch.mm` 的 x86_64 profile，`build_framework.sh` 重建，**先在 WeChat.app 副本上验证**。

## 风险提示
- 写错地址 / patch 点 → 微信崩溃或行为异常。请勿在唯一主力微信上直接试错。
- 建议拷贝一份 `WeChat.app` 到别处或用测试账号验证通过后，再安装到日常微信。
