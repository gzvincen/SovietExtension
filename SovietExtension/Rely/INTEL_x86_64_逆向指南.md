# Intel (x86_64) 适配逆向指南

本文档记录把 SovietExtension 防撤回 / 多开移植到 **Intel 芯片 Mac** 还差的最后一步：
逆向 **x86_64 版 `wechat.dylib`** 的函数地址。

## 已完成的部分（无需逆向）

| 项 | 状态 | 说明 |
|---|---|---|
| 插件编译为 universal (x86_64+arm64) | ✅ | 见 `Rely/build_framework.sh`，无需完整 Xcode |
| Intel 微信可加载插件 | ✅ | 实测注入 x86_64 微信进程，构造函数正常执行 |
| 阻止更新 (Anti-Update) | ✅ | 纯 Objective-C runtime hook，架构无关 |
| 苏维埃助手菜单 | ✅ | 纯 Cocoa，架构无关 |
| x86_64 补丁原语 | ✅ | `YMPatchX86ReturnYES` / `YMPatchX86AbsoluteJump` |
| x86_64 安全护栏 | ✅ | 地址未填时自动跳过补丁，**不会乱写、不崩溃** |
| **防撤回 (Anti-Revoke)** | ❌ | **需要本文档的逆向** |
| **真·多开 (Multi-Open)** | ❌ | **需要本文档的逆向** |

## 为什么不能直接复用 arm64 的地址

`RevokePatch.mm` 里防撤回/多开的原理是：用 IDA/Hopper 逆向出的**静态 VM 地址** + 运行时
ASLR slide 定位 `wechat.dylib` 内部函数，再写入机器码补丁。

- arm64 切片和 x86_64 切片虽然来自同一份源码，但**函数地址完全不同**。
- 补丁字节也不同：arm64 是 `mov w0,#1; ret`，x86_64 是 `mov eax,1; ret`（代码里已分别实现）。

所以必须在 **x86_64 切片**上重新逆向得到下面 6 个地址。

## 需要逆向填入的字段

文件：`SovietExtension/RevokePatch.mm`，`#elif defined(__x86_64__)` 分支下的两个 profile
（4.1.9.58 / 268602 和 4.1.10.53 / 268853），把对应的 `0` 替换为真实静态 VA：

| 字段 | arm64(4.1.10) 参考 | 含义 / 逆向线索 |
|---|---|---|
| `hookPointerVA` | `0x2846E84` | `ym_HandleSysMsg_RevokeMsg` 函数入口。x86_64 建议用 inline hook（已设 `YMRevokeHookModeInline`），填函数入口 VA |
| `rawMessageTemplateVA` | `0x7A7AD88` | 撤回 MessageWrap 模板数据（被 memcpy 616 字节） |
| `messageWrapFromRawVA` | `0x482F54C` | 由 raw 构造 MessageWrap 的函数 |
| `messageWrapDestructVA` | `0x2123AC0` | MessageWrap 析构函数 |
| `insertPaySysMsgToSessionVA` | `0x38EBBFC` | 插入本地 type=10000 系统消息的函数 |
| `YMMultiOpenTryPreventMultiInstanceVA` | `0x1C4EA8` | 防多开判断函数（patch 成返回 YES） |

> `layout`（MessageWrap 字段偏移）大概率与 arm64 相同（同源结构体），但运行后若灰条乱码/插错会话，需重新核对。

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
