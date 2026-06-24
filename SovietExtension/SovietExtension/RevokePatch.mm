//
//  RevokePatch.mm
//  SovietExtension
//
//  Created by MustangYM on 2026/6/12.
//
//  但我还是想说, 开源共产主义, 爱你们
//         -- MustangYM 2026-6-16

#import "RevokePatch.h"
#import "AntiUpdate.h"
#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <libkern/OSCacheControl.h>
#import <unistd.h>
#import <string.h>
#import <stdint.h>
#import <stdarg.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "MenuManager.h"
#import "NSObject+MainHook.h"

#include <string>
#include <time.h>
#include <atomic>
#include <execinfo.h>

#pragma mark - 全局状态

static BOOL YMHasPatchedAntiRevoke = NO;
static BOOL YMIsTargetWeChatResourceDylibPath(NSString *imagePath);
// 当前 /Applications/WeChat.app/Contents/Resources/wechat.dylib 的 ASLR slide。
// dyld 加载 wechat.dylib 后会赋值。
static uintptr_t YMWeChatDylibSlide = 0;

// 多开 Patch 状态
static BOOL YMHasPatchedMultiOpenResourceDylib = NO;
static BOOL YMHasRegisteredDyldCallback = NO;

// 群员退群监控 Patch 状态
static BOOL YMHasPatchedGroupExitMonitor = NO;

//static const uintptr_t YMMultiOpenTryPreventMultiInstanceVA = 0x1C0A64;

// 先声明，后面 constructor、multi open、anti revoke、群员退群监控都会用。
static void YMDyldImageAdded(const struct mach_header *mh, intptr_t vmaddr_slide);
static void YMRegisterDyldCallbackIfNeeded(void);
static void YMInstallMultiOpenPatch(void);
static void YMInstallGroupExitMonitorPatch(void);

typedef enum {
    YMRevokeHookModePointer = 0,   // 4.1.9：写 off_91EAD20
    YMRevokeHookModeInline  = 1,   // 4.1.10：patch 局部指令点
    YMRevokeHookModeBlockEntry = 2,// x86_64 MVP：直接 patch 撤回处理函数入口 return，阻断撤回（原消息保留）
    YMRevokeHookModeBlockEntryNotice = 3,// x86_64：detour 撤回 handler 入口→插本地灰条提示后 return YES 阻断
    YMRevokeHookModeX86Callsite = 4,     // x86_64：换 CoReplace 里查原消息的 call 目标→捕获原文+清替换标志(ARM 同机制)
} YMRevokeHookMode;

#pragma mark - MessageWrap 字段布局

/*
 当前版本运行时已经验证：
   rawWrap + 24  = 对方 / 当前聊天会话
   rawWrap + 48  = 当前登录账号 / 自己
   rawWrap + 256 = 毫秒级时间戳
   rawWrap + 276 = 秒级时间戳
   rawWrap + 328 = content / XML
 
 以后适配新版时：
   1. 如果 raw field24 / raw field48 打印正常，一般不用改这里。
   2. 如果打印乱码、空字符串、插错会话，再重新确认这些偏移。
 */
typedef struct {
    size_t messageWrapSize;

    size_t remoteUserOrSessionOffset;
    size_t selfUserOffset;

    size_t createTimeMsOffset;
    size_t createTimeSecOffset;

    size_t contentOffset;
} YMMessageWrapLayout;

#pragma mark - 微信版本适配配置

/*
 当前适配版本：
 CFBundleShortVersionString = 4.1.9
 CFBundleVersion = 268602
 Resources/wechat.dylib arm64

 注意：
 这些都是 IDA/Hopper 里的静态 VM 地址。
 运行时地址 = YMWeChatDylibSlide + 静态地址。
 */
typedef struct {
    const char *displayName;

    const char *bundleID;
    const char *shortVersion;
    const char *buildVersion;

    uintptr_t hookPointerVA;
    uintptr_t rawMessageTemplateVA;
    uintptr_t messageWrapFromRawVA;
    uintptr_t messageWrapDestructVA;
    uintptr_t insertPaySysMsgToSessionVA;
    uintptr_t YMMultiOpenTryPreventMultiInstanceVA;
    uintptr_t YMGetMainWeixinProcessCountVA;

    uintptr_t groupExitDBApplyVA;
    uintptr_t groupExitFMessagePreVA;
    uintptr_t groupExitUpdateSessionCacheVA;

    uintptr_t revokeOriginCallsiteAfterQueryVA;
    uintptr_t revokeOriginCallsiteContinueVA;
    uintptr_t revokeOriginCallsiteZeroBranchVA;
    uintptr_t revokeDeleteMessagesVA;

    YMMessageWrapLayout layout;
    
    YMRevokeHookMode hookMode;//4.1.10添加
} YMWeChatAdaptProfile;

/*
 地址表按 CPU 架构分开维护：
   - arm64  切片的静态 VA 走 YMAdaptProfilesARM64
   - x86_64 切片的静态 VA 走 YMAdaptProfilesX86_64
 同一份源码会被编译两次（universal），编译期用 #if 选中对应架构的地址表，
 运行期再按微信版本号匹配具体 profile。
 MessageWrapLayout 在两种架构上一致（同为 LP64 / 同一套 C++ ABI 对齐规则），
 所以两张表的 .layout 内容相同。
 */
#if defined(__arm64__) || defined(__aarch64__)
static const YMWeChatAdaptProfile YMAdaptProfiles[] = {
    {
        .displayName = "Mac WeChat 4.1.9.58 arm64 / 268602",

        .bundleID = "com.tencent.xinWeChat",
        .shortVersion = "4.1.9",
        .buildVersion = "268602",

        // ym_HandleSysMsg_RevokeMsg 开头的热补丁函数指针。
        // 汇编：
        //   ADRP X9, #off_91EAD20@PAGE
        //   LDR  X9, [X9,#off_91EAD20@PAGEOFF]
        //   CBZ  X9, loc_27A03B0
        //   BR   X9
        .hookMode = YMRevokeHookModePointer,
        .hookPointerVA = 0x91EAD20, // ym_HandleSysMsg_RevokeMsg->

        // ym_HandleSysMsg_RevokeMsg 原函数里用来构造撤回 MessageWrap 的模板：unk_7861730
        .rawMessageTemplateVA = 0x7861730, // ym_HandleSysMsg_RevokeMsg->

        // MessageWrap 相关函数
        .messageWrapFromRawVA = 0x4728670, // ym_HandleSysMsg_RevokeMsg->
        .messageWrapDestructVA = 0x206F0D0, // ym_HandleSysMsg_RevokeMsg->

        // 现成的本地系统消息插入函数。
        // sub_3822FA4：内部会构造 type=10000 + paymsg XML，然后调用 ym_AddLocalMessageWrap。
        .insertPaySysMsgToSessionVA = 0x3822FA4, // [CDATA]->
        .YMMultiOpenTryPreventMultiInstanceVA = 0x1C0A64,
        // 4.1.9 暂时没有适配这个进程数量检测点，填 0 表示跳过。
        .YMGetMainWeixinProcessCountVA = 0x449E2BC,

        // 群员退群监控 4.1.9 暂未适配，填 0 自动跳过。
        .groupExitDBApplyVA = 0,
        .groupExitFMessagePreVA = 0,
        .groupExitUpdateSessionCacheVA = 0,

        .revokeOriginCallsiteAfterQueryVA = 0,
        .revokeOriginCallsiteContinueVA = 0,
        .revokeOriginCallsiteZeroBranchVA = 0,
        .revokeDeleteMessagesVA = 0,

        .layout = {
            .messageWrapSize = 616,

            .remoteUserOrSessionOffset = 24,
            .selfUserOffset = 48,

            .createTimeMsOffset = 256,
            .createTimeSecOffset = 276,

            .contentOffset = 328,
        },
    },
    
    {
        .displayName = "Mac WeChat 4.1.10.53 arm64 / 268853",

        .bundleID = "com.tencent.xinWeChat",
        .shortVersion = "4.1.10",
        .buildVersion = "268853",

        // ym_HandleSysMsg_RevokeMsg 开头的热补丁函数指针。
        // 汇编：
        //   ADRP X9, #off_91EAD20@PAGE
        //   LDR  X9, [X9,#off_91EAD20@PAGEOFF]
        //   CBZ  X9, loc_27A03B0
        //   BR   X9
        .hookMode = YMRevokeHookModeInline,
        .hookPointerVA = 0x2846E84, // ym_HandleSysMsg_RevokeMsg->

        // ym_HandleSysMsg_RevokeMsg 原函数里用来构造撤回 MessageWrap 的模板：unk_7861730
        .rawMessageTemplateVA = 0x7A7AD88, // ym_HandleSysMsg_RevokeMsg->

        // MessageWrap 相关函数
        .messageWrapFromRawVA = 0x482F54C, // ym_HandleSysMsg_RevokeMsg->
        .messageWrapDestructVA = 0x2123AC0, // ym_HandleSysMsg_RevokeMsg->

        // 现成的本地系统消息插入函数。
        // sub_3822FA4：内部会构造 type=10000 + paymsg XML，然后调用 ym_AddLocalMessageWrap。
        .insertPaySysMsgToSessionVA = 0x38EBBFC, // [CDATA]->
        .YMMultiOpenTryPreventMultiInstanceVA = 0x1C4EA8,
        // GetMainWeixinProcessCount：统计当前 BundleID 的微信进程数量
        .YMGetMainWeixinProcessCountVA = 0x449E2BC,

        //数据库层, chatroom_member
        .groupExitDBApplyVA = 0x225355C,

        //yq
        .groupExitFMessagePreVA = 0x250EE44,
        //yq
        .groupExitUpdateSessionCacheVA = 0x37EACC0,

        //callsite拿
        /*
         sub_2819F44(__dst, v139[0], v137 + 392, *((_QWORD *)v137 + 45));//不要去直接去碰sub_2819F44这个函数,要去碰他的地址:
         __text:0000000002B7123C                 ADD             X1, X9, #0x188
       __text:0000000002B71240                 BL              sub_2819F44
       __text:0000000002B71244                 LDR             X22, [SP,#0x920+var_650+8]//碰这个指令
       __text:0000000002B71248                 CBZ             X22, loc_2B71274
       __text:0000000002B7124C                 ADD             X8, X22, #8
       __text:0000000002B71250                 MOV             X9, #0xFFFFFFFFFFFFFFFF
         */
        .revokeOriginCallsiteAfterQueryVA = 0x2B71244,//->Lhook->CoReplaceOriginMessageByRevoke里
        .revokeOriginCallsiteContinueVA = 0x2B71254,//->Lhook->CoReplaceOriginMessageByRevoke里
        .revokeOriginCallsiteZeroBranchVA = 0x2B71274,//->Lhook->CoReplaceOriginMessageByRevoke里
        
        .revokeDeleteMessagesVA = 0x2814B9C,//->Lhook->DeleteMessages

        .layout = {
            .messageWrapSize = 616,

            .remoteUserOrSessionOffset = 24,
            .selfUserOffset = 48,

            .createTimeMsOffset = 256,
            .createTimeSecOffset = 276,

            .contentOffset = 328,
        },
    },

    /*
     新版适配示例代码:

     {
         .displayName = "Mac WeChat 4.1.10 arm64 / xxxxxx",

         .bundleID = "com.tencent.xinWeChat",
         .shortVersion = "4.1.10",
         .buildVersion = "新版 CFBundleVersion",

         .hookPointerVA = 新版地址,
         .rawMessageTemplateVA = 新版地址,
         .messageWrapFromRawVA = 新版地址,
         .messageWrapDestructVA = 新版地址,
         .insertPaySysMsgToSessionVA = 新版地址,
         .YMMultiOpenTryPreventMultiInstanceVA = 新版多开入口地址,
         .YMGetMainWeixinProcessCountVA = 新版进程数量检测地址，没有就填 0,

         .groupExitDBApplyVA = 新版 chatroom_member DB apply 函数入口地址，没有就填 0,
         .groupExitFMessagePreVA = 新版 InsertFMessageToSessionPre 函数入口地址，没有就填 0,
         .groupExitUpdateSessionCacheVA = 新版 UpdateSessionCache 函数入口地址，没有就填 0,

         .revokeOriginCallsiteAfterQueryVA = 新版 BL sub_2819F44 后一条指令地址，没有就填 0,
         .revokeOriginCallsiteContinueVA = 新版继续执行地址，没有就填 0,
         .revokeOriginCallsiteZeroBranchVA = 新版 CBZ 分支地址，没有就填 0,
         .revokeDeleteMessagesVA = 新版 DeleteMessages 函数入口地址，没有就填 0,

         .layout = {
             .messageWrapSize = 616,

             .remoteUserOrSessionOffset = 24,
             .selfUserOffset = 48,

             .createTimeMsOffset = 256,
             .createTimeSecOffset = 276,

             .contentOffset = 328,
         },
     },
     */
};

#elif defined(__x86_64__)

/*
 x86_64 地址表。
 ⚠️ 下面所有 VA 都标记为 0，是 Phase 2 待逆向的占位值：
    需要在 wechat.dylib 的 x86_64 切片里重新定位每个函数 / 指令点的静态 VA。
 在地址填好之前：
   - YMProfileHasValidAddresses 会因为关键地址为 0 返回 NO，
     所以防撤回 / 退群在 x86_64 上会被安全跳过，不会崩。
   - 多开 patch 读到 0 地址也会打印 "address is zero, skip"。
 逆向顺序建议：多开 -> 防撤回函数入口 -> 退群监控 + inline callsite。
 */
static const YMWeChatAdaptProfile YMAdaptProfiles[] = {
    {
        .displayName = "Mac WeChat 4.1.10.53 x86_64 / 268853",

        .bundleID = "com.tencent.xinWeChat",
        .shortVersion = "4.1.10",
        .buildVersion = "268853",

        // ✅ Phase 2 防撤回：instrument-and-observe(运行时 backtrace)确认真实撤回链：
        //   sync → 0x2bd6250(handler wrapper,单调用者,return bool) → 0x2bd62d0
        //   → 0x2f93440(CoReplace,624模板@mov edx,0x270 + origin查找+UI替换)。
        //   阻断点取最顶层撤回 wrapper 0x2bd6250，入口 patch 成 return YES(mov eax,1)：
        //   上层认为已处理(不重试/不脱)，但 CoReplace/下游删除全不执行→原消息保留。
        //   （旧候选 0x2b93f40 不在本(1v1)撤回链上，故此前 block 无效。）
        // ✅ 防撤回 callsite 捕获(ARM 同机制，显示原文/昵称，不动 DB)：
        //   hookPointerVA = CoReplace(0x2f93440) 里查原消息那条 call 的 VA。
        //   wrapper 调真正查询拿到原消息→捕获 content/type/time/session(偏移同 arm64)
        //   →插带原文详细灰条→清 outWrap+616 替换标志阻止 UI 替换。
        //   备选：BlockEntryNotice@0x2bd6250(只阻断+概要提示，已实测稳)。
        .hookMode = YMRevokeHookModeX86Callsite,
        .hookPointerVA = 0x2f93eb1,

        // ✅ 防撤回 notice（运行时+结构指纹确认，用于阻断后本地补一条灰条提示）：
        //   rawMessageTemplate: 0x2bd6250 里 memcpy 源(616B sysmsg 模板)。
        //   messageWrapFromRaw: 0x2bd6250 调的 sub(buf,rawRevokeMsg) 构造 wrap。
        //   messageWrapDestruct: 0x2bd6250 末尾析构 wrap 的 sub。
        //   insertPaySysMsgToSession: 引用 `<?xml..<sysmsg type="%s">..CDATA..` 模板
        //     (0x84ef180)+写 msgType=0x2710、签名(arg0忽略,rsi=session,rdx=content)，
        //     与 arm64 0x38EBBFC 同构；x86=0x3e79d80。
        .rawMessageTemplateVA = 0x82AA8A8,
        .messageWrapFromRawVA = 0x4ecc900,
        .messageWrapDestructVA = 0x23b9d80,
        .insertPaySysMsgToSessionVA = 0x3e79d80,

        // ✅ Phase 2 已逆向+结构指纹验证（NSRunningApplication 多实例检测）：
        //    TryPrevent: 栈canary + mainBundle->bundleIdentifier->
        //                runningApplicationsWithBundleIdentifier:->count + activateWithOptions:
        //    ProcessCount: 同上但无 activate，直接返回 count
        .YMMultiOpenTryPreventMultiInstanceVA = 0x1F3830, // arm64 对应 0x1C4EA8
        .YMGetMainWeixinProcessCountVA = 0x4AD0F00,       // arm64 对应 0x449E2BC

        .groupExitDBApplyVA = 0,
        .groupExitFMessagePreVA = 0,
        .groupExitUpdateSessionCacheVA = 0,

        .revokeOriginCallsiteAfterQueryVA = 0,
        .revokeOriginCallsiteContinueVA = 0,
        .revokeOriginCallsiteZeroBranchVA = 0,
        .revokeDeleteMessagesVA = 0,

        // 布局与 arm64 一致（LP64 同一套 C++ ABI），运行期日志再二次确认。
        .layout = {
            .messageWrapSize = 616,

            .remoteUserOrSessionOffset = 24,
            .selfUserOffset = 48,

            .createTimeMsOffset = 256,
            .createTimeSecOffset = 276,

            .contentOffset = 328,
        },
    },
};

#else
#error "Unsupported CPU architecture for YMAdaptProfiles"
#endif

static const size_t YMAdaptProfilesCount = sizeof(YMAdaptProfiles) / sizeof(YMAdaptProfiles[0]);

// 当前运行版本匹配到的配置。
// 后面所有地址都从这里取，不再写死单个 YMCurrentProfile。
static const YMWeChatAdaptProfile *YMActiveProfile = NULL;

#pragma mark - 微信内部函数类型

typedef void (*YMMessageWrapFromRawFunc)(void *message, int64_t rawMessage);
typedef void (*YMMessageWrapDestructFunc)(int64_t message);

typedef int64_t (*YMInsertPaySysMsgToSessionFunc)(int64_t a1,
                                                  const std::string *session,
                                                  const std::string *content);

/*
 paymsg / red_envelope 反编译里表现为：
   ym_AddLocalMessageWrap(v39[0], v32);

 所以这里按两个参数声明：
   messageService = v39[0]
   message        = MessageWrap*
 */
typedef int64_t (*YMAddLocalMessageWrapFunc)(int64_t messageService, void *message);

#pragma mark - 退群相关
typedef int64_t (*YMGroupExitDBApplyFunc)(int64_t task);
typedef void (*YMGroupExitFMessagePreFunc)(int64_t a1, int64_t *a2);
typedef void (*YMGroupExitUpdateSessionCacheFunc)(uint64_t a1, int64_t a2, int64_t a3, int a4);

static uintptr_t YMGroupExitDBApplyRuntimeAddress = 0;
static uint8_t YMGroupExitOriginalDBApplyBytes[16] = {0};
static uint8_t YMGroupExitHookDBApplyBytes[16] = {0};
static BOOL YMGroupExitHasSavedOriginalDBApplyBytes = NO;

static uintptr_t YMGroupExitFMessagePreRuntimeAddress = 0;
static uint8_t YMGroupExitOriginalFMessagePreBytes[16] = {0};
static uint8_t YMGroupExitHookFMessagePreBytes[16] = {0};
static BOOL YMGroupExitHasSavedOriginalFMessagePreBytes = NO;

static uintptr_t YMGroupExitUpdateSessionCacheRuntimeAddress = 0;
static uint8_t YMGroupExitOriginalUpdateSessionCacheBytes[16] = {0};
static uint8_t YMGroupExitHookUpdateSessionCacheBytes[16] = {0};
static BOOL YMGroupExitHasSavedOriginalUpdateSessionCacheBytes = NO;

static std::atomic_bool YMGroupExitCallingOriginalDBApply(false);
static std::atomic_bool YMGroupExitCallingOriginalFMessagePre(false);
static std::atomic_bool YMGroupExitCallingOriginalUpdateSessionCache(false);
static std::atomic_bool YMGroupExitFlushingPending(false);

// 统一读取退群监控开关。
// 注意：安装 hook 前要判断；hook 已经安装后也要在 hook 内判断。
// 因为 ARM64 inline hook 一旦写入当前进程，单纯把 NSUserDefaults 改成 false，
// 已经安装的 hook 不会自动消失。
static BOOL YMIsGroupExitMonitorEnabled(void) {
    return [[NSUserDefaults standardUserDefaults] boolForKey:kExitChatroom];
}

#pragma mark - 日志

void YMLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSLog(@"[YMAntiRevoke] %@", msg);

    NSString *line = [NSString stringWithFormat:@"%@\n", msg];
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    NSString *path = @"/tmp/YMWeChatAntiRevokePatch.log";

    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [data writeToFile:path atomically:YES];
    } else {
        [fh seekToEndOfFile];
        [fh writeData:data];
        [fh closeFile];
    }
}

#pragma mark - 字符串辅助

static NSString *YMNSStringFromCString(const char *cString) {
    if (!cString) {
        return @"";
    }

    return [NSString stringWithUTF8String:cString] ?: @"";
}

static std::string YMStdStringFromNSString(NSString *text) {
    if (!text) {
        return std::string();
    }

    const char *utf8 = [text UTF8String];
    if (!utf8) {
        return std::string();
    }

    return std::string(utf8);
}

static NSString *YMNSStringFromStdString(const std::string *value) {
    if (!value) {
        return @"";
    }

    const char *cString = NULL;

    try {
        cString = value->c_str();
    } catch (...) {
        return @"";
    }

    if (!cString) {
        return @"";
    }

    return [NSString stringWithUTF8String:cString] ?: @"";
}


static BOOL YMSafeReadMemory(uintptr_t address, void *buffer, size_t size) {
    if (address == 0 || !buffer || size == 0) {
        return NO;
    }

    vm_size_t outSize = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)address,
                                         (vm_size_t)size,
                                         (vm_address_t)buffer,
                                         &outSize);

    return kr == KERN_SUCCESS && outSize == size;
}

static BOOL YMSafeReadPointer(uintptr_t address, uintptr_t *value) {
    if (!value) {
        return NO;
    }

    uintptr_t tmp = 0;
    if (!YMSafeReadMemory(address, &tmp, sizeof(tmp))) {
        return NO;
    }

    *value = tmp;
    return YES;
}

static BOOL YMSafeReadUInt32(uintptr_t address, uint32_t *value) {
    if (!value) {
        return NO;
    }

    uint32_t tmp = 0;
    if (!YMSafeReadMemory(address, &tmp, sizeof(tmp))) {
        return NO;
    }

    *value = tmp;
    return YES;
}

/*
 读取微信内部 libc++ std::string 对象。
 反编译里常见判断：
   *(char *)(str + 23) >= 0  => 短字符串，长度在 +23，内容从对象起始处读。
   *(char *)(str + 23) <  0  => 长字符串，data 在 +0，length 在 +8。

 这个函数只读，不析构，不接管所有权。
 */
static NSString *YMNSStringFromLibcppStringObject(const void *stringObject) {
    if (!stringObject) {
        return @"";
    }

    /*
     注意：这里不能直接解引用微信内部指针。
     如果偏移猜错，普通 try/catch 捕获不了 EXC_BAD_ACCESS，所以统一用 vm_read_overwrite 做安全读。
     */
    uint8_t header[24] = {0};
    uintptr_t objectAddress = (uintptr_t)stringObject;
    if (!YMSafeReadMemory(objectAddress, header, sizeof(header))) {
        return @"";
    }

    int8_t flag = *(const int8_t *)(header + 23);

    const char *data = NULL;
    size_t length = 0;
    uint8_t stackBuffer[4096] = {0};

    if (flag >= 0) {
        length = (uint8_t)flag;
        if (length == 0 || length > 23) {
            return @"";
        }
        memcpy(stackBuffer, header, length);
        data = (const char *)stackBuffer;
    } else {
        uintptr_t remoteData = 0;
        memcpy(&remoteData, header, sizeof(remoteData));
        memcpy(&length, header + 8, sizeof(length));

        if (remoteData == 0 || length == 0 || length >= sizeof(stackBuffer)) {
            return @"";
        }

        if (!YMSafeReadMemory(remoteData, stackBuffer, length)) {
            return @"";
        }

        data = (const char *)stackBuffer;
    }

    NSString *value = [[NSString alloc] initWithBytes:data
                                              length:length
                                            encoding:NSUTF8StringEncoding];
    return value ?: @"";
}

#pragma mark - Profile 匹配

// 防撤回功能所需的完整地址是否就绪（base 函数 + 对应 hook 模式入口）。
// 防撤回的安装路径会再各自自检，所以这里只用于判断“防撤回能不能跑”。
static BOOL YMProfileHasAntiRevokeAddresses(const YMWeChatAdaptProfile *profile) {
    if (!profile) {
        return NO;
    }

    // BlockEntry：只 patch 撤回处理函数入口 return，不需要 base 函数 / 模板。
    if (profile->hookMode == YMRevokeHookModeBlockEntry) {
        return profile->hookPointerVA != 0;
    }

    // BlockEntryNotice：detour 入口插提示后阻断。只要有入口即可安装；
    // notice 4 件套缺失时 YMInsertLocalAntiRevokeNotice 会优雅失败，但仍阻断。
    if (profile->hookMode == YMRevokeHookModeBlockEntryNotice) {
        return profile->hookPointerVA != 0;
    }

    // X86Callsite：换查原消息的 call 目标。需要 callsite VA + insert 函数(出原文提示)。
    if (profile->hookMode == YMRevokeHookModeX86Callsite) {
        return profile->hookPointerVA != 0 &&
               profile->insertPaySysMsgToSessionVA != 0;
    }

    BOOL baseOK = profile->rawMessageTemplateVA != 0 &&
                  profile->messageWrapFromRawVA != 0 &&
                  profile->messageWrapDestructVA != 0 &&
                  profile->insertPaySysMsgToSessionVA != 0 &&
                  profile->layout.messageWrapSize > 0;

    if (!baseOK) {
        return NO;
    }

    if (profile->hookMode == YMRevokeHookModePointer) {
        return profile->hookPointerVA != 0;
    }

    if (profile->hookMode == YMRevokeHookModeInline) {
        return profile->revokeOriginCallsiteAfterQueryVA != 0 &&
               profile->revokeOriginCallsiteContinueVA != 0 &&
               profile->revokeOriginCallsiteZeroBranchVA != 0;
    }

    return NO;
}

// 多开功能所需地址是否就绪。
static BOOL YMProfileHasMultiOpenAddresses(const YMWeChatAdaptProfile *profile) {
    return profile && (profile->YMMultiOpenTryPreventMultiInstanceVA != 0 ||
                       profile->YMGetMainWeixinProcessCountVA != 0);
}

/*
 profile 只要能驱动“任意一个”功能就算可用（active）。
 这样在某架构上即便只逆向出了多开地址、防撤回地址还为 0，多开也能独立生效，
 而防撤回 / 退群会在各自安装路径里因地址为 0 安全跳过，不会崩。
 arm64 的 profile 两类地址都齐全，行为不变。
 */
static BOOL YMProfileHasValidAddresses(const YMWeChatAdaptProfile *profile) {
    return YMProfileHasAntiRevokeAddresses(profile) ||
           YMProfileHasMultiOpenAddresses(profile);
}

static const YMWeChatAdaptProfile *YMFindAdaptProfileForCurrentWeChat(void) {
    NSBundle *bundle = [NSBundle mainBundle];

    NSString *bundleID = [bundle bundleIdentifier] ?: @"";
    NSString *shortVersion = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    NSString *buildVersion = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";

    YMLog(@"bundleID=%@, version=%@, build=%@", bundleID, shortVersion, buildVersion);

    for (size_t i = 0; i < YMAdaptProfilesCount; i++) {
        const YMWeChatAdaptProfile *profile = &YMAdaptProfiles[i];

        NSString *expectedBundleID = YMNSStringFromCString(profile->bundleID);
        NSString *expectedShortVersion = YMNSStringFromCString(profile->shortVersion);
        NSString *expectedBuildVersion = YMNSStringFromCString(profile->buildVersion);

        if (![bundleID isEqualToString:expectedBundleID]) {
            continue;
        }

        if (![shortVersion isEqualToString:expectedShortVersion]) {
            continue;
        }

        if (![buildVersion isEqualToString:expectedBuildVersion]) {
            continue;
        }

        YMLog(@"matched adapt profile: %s", profile->displayName);

        if (!YMProfileHasValidAddresses(profile)) {
            YMLog(@"matched profile but addresses are incomplete: %s", profile->displayName);
            return NULL;
        }

        return profile;
    }

    YMLog(@"no adapt profile matched current WeChat version");
    return NULL;
}

static const YMWeChatAdaptProfile *YMGetActiveProfile(void) {
    if (YMActiveProfile) {
        return YMActiveProfile;
    }

    YMActiveProfile = YMFindAdaptProfileForCurrentWeChat();
    return YMActiveProfile;
}

#pragma mark - 地址辅助

uintptr_t YMRuntimeAddress(uintptr_t staticVA) {
    if (YMWeChatDylibSlide == 0 || staticVA == 0) {
        return 0;
    }

    return YMWeChatDylibSlide + staticVA;
}

uintptr_t getDylibSlide()
{
    return YMWeChatDylibSlide;
}

static inline void *YMRuntimePointer(uintptr_t staticVA) {
    uintptr_t address = YMRuntimeAddress(staticVA);
    if (address == 0) {
        return NULL;
    }

    return (void *)address;
}

#pragma mark - 版本检查

static BOOL YMIsTargetWeChatVersion(void) {
    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();

    if (!profile) {
        YMLog(@"unsupported WeChat version, skip anti revoke");
        return NO;
    }

    YMLog(@"current adapt profile=%s", profile->displayName);
    return YES;
}

#pragma mark - C++ std::string 辅助

/*
 第一版先默认使用纯文本系统消息。
 老版 WeChatExtension 也是类似逻辑：msgType=10000 + content 文案。
 如果纯文本不显示，再把这里改成 XML 版本测试。
 */
__attribute__((unused))
static std::string YMBuildAntiRevokeSystemContent(void) {
    return YMStdStringFromNSString(@"已拦截到一条撤回消息");
}

/*
 备用 XML 版本。
 如果纯文本版本插入了但 UI 不显示，可以把 YMBuildAntiRevokeSystemContent()
 里 return 改成这个函数。
 */
__attribute__((unused))
static std::string YMBuildAntiRevokeSystemXMLContent(void) {
    std::string text = YMStdStringFromNSString(@"已拦截到一条撤回消息");

    std::string xml;
    xml += "<?xml version=\"1.0\"?>\n";
    xml += "<sysmsg type=\"paymsg\">";
    xml += "<content><![CDATA[";
    xml += text;
    xml += "]]></content>";
    xml += "</sysmsg>";

    return xml;
}

#pragma mark - shared_ptr 释放辅助

/*
 微信内部大量使用 libc++ shared_ptr。
 反编译中一般是：
   if (control && !atomic_fetch_add(control + 8, -1)) {
       control->__on_zero_shared(control);
       std::__shared_weak_count::__release_weak(control);
   }

 这里第一版只用于自己栈上临时 shared_ptr 的释放。
 如果测试阶段担心这里有风险，可以临时把调用 YMReleaseSharedPtrStorage 的地方注释掉。
 */
__attribute__((unused))
static void YMReleaseSharedPtrStorage(void *storage) {
    if (!storage) {
        return;
    }

    void **items = (void **)storage;
    void *controlBlock = items[1];

    items[0] = NULL;
    items[1] = NULL;

    if (!controlBlock) {
        return;
    }

    // libc++ shared_count 的 shared_owners_ 通常在 controlBlock + 8。
    volatile long *sharedOwners = (volatile long *)((uint8_t *)controlBlock + 8);
    long oldValue = __atomic_fetch_add(sharedOwners, -1, __ATOMIC_ACQ_REL);

    // 反编译里的判断是 oldValue == 0 时释放。
    if (oldValue == 0) {
        void **vtable = *(void ***)controlBlock;

        // vtable[2] 通常对应 __on_zero_shared()
        if (vtable && vtable[2]) {
            typedef void (*OnZeroSharedFunc)(void *);
            ((OnZeroSharedFunc)vtable[2])(controlBlock);
        }

        // vtable[3] 通常对应 __on_zero_shared_weak()
        if (vtable && vtable[3]) {
            typedef void (*OnZeroSharedWeakFunc)(void *);
            ((OnZeroSharedWeakFunc)vtable[3])(controlBlock);
        }
    }
}

#pragma mark - MessageWrap 字段读取

static std::string *YMRawWrapStringField(void *rawWrap, size_t offset) {
    if (!rawWrap) {
        return NULL;
    }

    return (std::string *)((uint8_t *)rawWrap + offset);
}

static uint32_t YMRawWrapUInt32Field(void *rawWrap, size_t offset) {
    if (!rawWrap) {
        return 0;
    }

    return *(uint32_t *)((uint8_t *)rawWrap + offset);
}

static uint64_t YMRawWrapUInt64Field(void *rawWrap, size_t offset) {
    if (!rawWrap) {
        return 0;
    }

    return *(uint64_t *)((uint8_t *)rawWrap + offset);
}

static NSString *YMFormatTimestamp(uint32_t createTimeSec, uint64_t createTimeMs) {
    NSTimeInterval messageTimestamp = 0;

    if (createTimeSec > 0) {
        messageTimestamp = (NSTimeInterval)createTimeSec;
    } else if (createTimeMs > 0) {
        messageTimestamp = (NSTimeInterval)(createTimeMs / 1000);
    } else {
        messageTimestamp = [[NSDate date] timeIntervalSince1970];
    }

    NSDate *messageDate = [NSDate dateWithTimeIntervalSince1970:messageTimestamp];

    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"zh_CN"];
    formatter.timeZone = [NSTimeZone localTimeZone];
    formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";

    return [formatter stringFromDate:messageDate] ?: @"";
}

static NSString *YMExtractXMLTagValue(NSString *xml, NSString *tag) {
    if (xml.length == 0 || tag.length == 0) {
        return @"";
    }

    NSString *openTag = [NSString stringWithFormat:@"<%@>", tag];
    NSString *closeTag = [NSString stringWithFormat:@"</%@>", tag];

    NSRange openRange = [xml rangeOfString:openTag options:NSCaseInsensitiveSearch];
    if (openRange.location == NSNotFound) {
        return @"";
    }

    NSUInteger valueStart = NSMaxRange(openRange);
    if (valueStart >= xml.length) {
        return @"";
    }

    NSRange searchRange = NSMakeRange(valueStart, xml.length - valueStart);
    NSRange closeRange = [xml rangeOfString:closeTag options:NSCaseInsensitiveSearch range:searchRange];
    if (closeRange.location == NSNotFound || closeRange.location < valueStart) {
        return @"";
    }

    NSString *value = [xml substringWithRange:NSMakeRange(valueStart, closeRange.location - valueStart)] ?: @"";
    value = [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

    if ([value hasPrefix:@"<![CDATA["] && [value hasSuffix:@"]]>"] && value.length >= 12) {
        value = [value substringWithRange:NSMakeRange(9, value.length - 12)] ?: @"";
    }

    return [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
}

static NSString *YMRevokerWxidFromRevokeXMLPrefix(NSString *xml) {
    if (xml.length == 0) {
        return @"";
    }

    NSRange sysmsgRange = [xml rangeOfString:@"<sysmsg" options:NSCaseInsensitiveSearch];
    if (sysmsgRange.location == NSNotFound || sysmsgRange.location == 0) {
        return @"";
    }

    NSString *prefix = [[xml substringToIndex:sysmsgRange.location]
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([prefix hasSuffix:@":"]) {
        prefix = [prefix substringToIndex:prefix.length - 1];
    }

    if ([prefix hasPrefix:@"wxid_"] || prefix.length > 0) {
        return prefix;
    }
    return @"";
}

static NSString *YMDisplayNameFromRevokeReplaceMsg(NSString *replaceMsg) {
    if (replaceMsg.length == 0) {
        return @"";
    }

    NSRange firstQuote = [replaceMsg rangeOfString:@"\""];
    if (firstQuote.location != NSNotFound) {
        NSRange searchRange = NSMakeRange(NSMaxRange(firstQuote), replaceMsg.length - NSMaxRange(firstQuote));
        NSRange secondQuote = [replaceMsg rangeOfString:@"\"" options:0 range:searchRange];
        if (secondQuote.location != NSNotFound && secondQuote.location > NSMaxRange(firstQuote)) {
            NSString *name = [replaceMsg substringWithRange:NSMakeRange(NSMaxRange(firstQuote), secondQuote.location - NSMaxRange(firstQuote))];
            name = [name stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (name.length > 0) {
                return name;
            }
        }
    }

    NSString *name = [replaceMsg copy];
    for (NSString *suffix in @[@"撤回了一条消息", @"撤回了消息", @"recalled a message"]) {
        NSRange range = [name rangeOfString:suffix options:NSCaseInsensitiveSearch];
        if (range.location != NSNotFound) {
            name = [name substringToIndex:range.location];
            break;
        }
    }

    name = [[name stringByReplacingOccurrencesOfString:@"\"" withString:@""]
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return name ?: @"";
}

static NSString *YMFindRevokeXMLFromRawWrap(void *rawWrap, size_t wrapSize) {
    if (!rawWrap || wrapSize < 24) {
        return @"";
    }

    /*
     4.1.10 实测：撤回 sysmsg 的 XML 在 MessageWrap + 304，
     +352 是 msgsource，之前按 +328 读取会拿到空字符串。
     这里仍然做全量 fallback 扫描，避免小版本偏移轻微漂移。
     */
    const size_t preferredOffsets[] = {304, 328, 352, 376, 400, 424, 448, 280, 248, 224, 200};
    for (size_t i = 0; i < sizeof(preferredOffsets) / sizeof(preferredOffsets[0]); i++) {
        size_t offset = preferredOffsets[i];
        if (offset + 24 > wrapSize) {
            continue;
        }
        NSString *value = YMNSStringFromLibcppStringObject((uint8_t *)rawWrap + offset);
        NSString *lower = value.lowercaseString;
        if ([lower containsString:@"<sysmsg"] && [lower containsString:@"revokemsg"]) {
            YMLog(@"raw revoke xml found at preferred offset +%zu", offset);
            return value ?: @"";
        }
    }

    for (size_t offset = 0; offset + 24 <= wrapSize; offset += 8) {
        NSString *value = YMNSStringFromLibcppStringObject((uint8_t *)rawWrap + offset);
        if (value.length == 0) {
            continue;
        }
        NSString *lower = value.lowercaseString;
        if ([lower containsString:@"<sysmsg"] && [lower containsString:@"revokemsg"]) {
            YMLog(@"raw revoke xml found by scan at offset +%zu", offset);
            return value ?: @"";
        }
    }

    return @"";
}

static NSString *YMBuildAntiRevokeNoticeText(NSString *remoteUserOrSession,
                                             NSString *selfUser,
                                             NSString *messageTimeText,
                                             NSString *revokerWxid,
                                             NSString *replaceMsg,
                                             NSString *revokeSession,
                                             NSString *msgID,
                                             NSString *newMsgID) {
    NSString *displayName = YMDisplayNameFromRevokeReplaceMsg(replaceMsg);
    NSString *session = revokeSession.length > 0 ? revokeSession : (remoteUserOrSession ?: @"");

    NSMutableString *text = [NSMutableString string];
    [text appendString:@"⚠️苏维埃已拦截撤回消息⚠️\n"];

    if (displayName.length > 0 && revokerWxid.length > 0) {
        [text appendFormat:@"%@（%@）\n", displayName, revokerWxid];
    } else if (displayName.length > 0) {
        [text appendFormat:@"%@\n", displayName];
    } else if (revokerWxid.length > 0) {
        [text appendFormat:@"%@\n", revokerWxid];
    } else {
        [text appendFormat:@"撤回方/会话：%@\n", remoteUserOrSession ?: @""];
    }

    /*
     这里不显示“原消息类型/内容”。
     原消息本身已经因为当前 hook 被保留下来；如果要额外展示类型和内容，
     后续需要换到 CoReplaceOriginMessageByRevoke 并安全自查 MessageWrap，不能再 hook 全局 copy 函数。
     */
    if (messageTimeText.length > 0) {
        [text appendString:messageTimeText];
    }

    return text;
}

#pragma mark - 内存写入

static BOOL YMWritePointer(uintptr_t address,
                           uintptr_t value,
                           uintptr_t expectedOldValue,
                           const char *name) {
    if (address == 0 || value == 0) {
        YMLog(@"invalid pointer patch argument: %s", name);
        return NO;
    }

    uintptr_t *target = (uintptr_t *)address;
    uintptr_t current = *target;

    if (current == value) {
        YMLog(@"pointer already hooked: %s at 0x%lx", name, (unsigned long)address);
        return YES;
    }

    if (current != expectedOldValue) {
        YMLog(@"pointer old value mismatch: %s", name);
        YMLog(@"address=0x%lx, current=0x%lx, expected=0x%lx, new=0x%lx",
              (unsigned long)address,
              (unsigned long)current,
              (unsigned long)expectedOldValue,
              (unsigned long)value);
        return NO;
    }

    vm_size_t pageSize = (vm_size_t)getpagesize();
    vm_address_t pageStart = (vm_address_t)(address & ~((uintptr_t)pageSize - 1));
    vm_size_t protectSize = pageSize;

    kern_return_t kr = vm_protect(mach_task_self(),
                                  pageStart,
                                  protectSize,
                                  false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

    if (kr != KERN_SUCCESS) {
        YMLog(@"vm_protect pointer RW|COPY failed: %s, kr=%d", name, kr);
        return NO;
    }

    __atomic_store_n(target, value, __ATOMIC_SEQ_CST);

    YMLog(@"pointer hook success: %s, address=0x%lx, value=0x%lx",
          name,
          (unsigned long)address,
          (unsigned long)value);

    return YES;
}

#pragma mark - ARM64 代码段 Patch

static void YMPrintCodeBytes(const char *name, const char *stage, void *address) {
    if (!address) {
        YMLog(@"%s %s address is NULL", name, stage);
        return;
    }

    uint32_t bytes[4] = {0};
    memcpy(bytes, address, sizeof(bytes));

    YMLog(@"%s %s address=%p bytes=%08x %08x %08x %08x",
          name,
          stage,
          address,
          bytes[0],
          bytes[1],
          bytes[2],
          bytes[3]);
}

static BOOL YMProtectCodePage(uintptr_t address,
                              size_t patchSize,
                              vm_prot_t protection,
                              const char *name,
                              const char *stage) {
    vm_size_t pageSize = (vm_size_t)getpagesize();
    vm_address_t pageStart = (vm_address_t)(address & ~((uintptr_t)pageSize - 1));

    uintptr_t patchEnd = address + patchSize;
    uintptr_t pageEnd = (patchEnd + pageSize - 1) & ~((uintptr_t)pageSize - 1);

    vm_size_t protectSize = (vm_size_t)(pageEnd - pageStart);

    kern_return_t kr = vm_protect(mach_task_self(),
                                  pageStart,
                                  protectSize,
                                  false,
                                  protection);

    if (kr != KERN_SUCCESS) {
        YMLog(@"%s vm_protect %s failed, address=0x%lx, pageStart=0x%lx, size=%lu, kr=%d",
              name,
              stage,
              (unsigned long)address,
              (unsigned long)pageStart,
              (unsigned long)protectSize,
              kr);
        return NO;
    }

    return YES;
}

#pragma mark - 架构相关机器码发射器（arm64 / x86_64）

/*
 统一的“返回 YES / 非零”桩代码。
   arm64 (8B):  mov w0, #1 ; ret   -> 20 00 80 52 / C0 03 5F D6
   x86_64 (6B): mov eax, 1 ; ret   -> B8 01 00 00 00 / C3

 用 w0 / eax 而不是 x0 / rax，因为这些检测点本质是 BOOL/int 返回
 （反编译里是 if (v & 1)）。返回写入的字节数。
 */
static size_t YMEmitReturnYESStub(uint8_t out[8]) {
#if defined(__x86_64__)
    static const uint8_t code[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};
#elif defined(__arm64__) || defined(__aarch64__)
    static const uint8_t code[] = {0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6};
#else
    #error "Unsupported CPU architecture"
#endif
    memcpy(out, code, sizeof(code));
    return sizeof(code);
}

/*
 “返回 0 ; ret” 桩代码。用于 BlockEntry 防撤回：直接让撤回处理函数入口返回 0
 （目标函数本身就有合法返回 0 的路径），从而不执行任何撤回替换。
   arm64 (8B):  mov w0, #0 ; ret   -> 00 00 80 52 / C0 03 5F D6
   x86_64 (6B): mov eax, 0 ; ret   -> B8 00 00 00 00 / C3
 */
static size_t YMEmitReturnZeroStub(uint8_t out[8]) {
#if defined(__x86_64__)
    static const uint8_t code[] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3};
#elif defined(__arm64__) || defined(__aarch64__)
    static const uint8_t code[] = {0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6};
#else
    #error "Unsupported CPU architecture"
#endif
    memcpy(out, code, sizeof(code));
    return sizeof(code);
}

/*
 统一的“绝对跳转到 targetAddress”跳板，固定占用 16 字节
 （不足处用 NOP 补齐，让 save/restore 的原始字节区长度在两种架构上一致）。

   arm64 (16B):  ldr x16, #8 ; br x16 ; .quad targetAddress
                 50 00 00 58 / 00 02 1F D6 / target 8B
   x86_64 (13B): movabs r11, targetAddress ; jmp r11 ; 然后 NOP 补到 16B
                 49 BB target8B / 41 FF E3 / 90 90 90

 x16 / r11 都是 ABI 允许随意使用的临时寄存器，不破坏入参寄存器
 （arm64 的 x0/x1、x86_64 的 rdi/rsi），所以 hook 仍能拿到原始参数。
 原函数是被 call/BL 调用进来的，返回地址已在栈/LR 上，跳到 hook 后
 hook 末尾 ret 会直接回到上层调用者。返回写入的字节数（恒为 16）。
 */
static size_t YMEmitAbsoluteJump(uintptr_t targetAddress, uint8_t out[16]) {
#if defined(__x86_64__)
    memset(out, 0x90, 16); // 先全部填 nop
    out[0] = 0x49;         // movabs r11, imm64
    out[1] = 0xBB;
    memcpy(out + 2, &targetAddress, sizeof(targetAddress));
    out[10] = 0x41;        // jmp r11
    out[11] = 0xFF;
    out[12] = 0xE3;
#elif defined(__arm64__) || defined(__aarch64__)
    uint32_t insnLdrX16 = 0x58000050; // ldr x16, #8
    uint32_t insnBrX16  = 0xD61F0200; // br x16
    memcpy(out + 0, &insnLdrX16, sizeof(insnLdrX16));
    memcpy(out + 4, &insnBrX16, sizeof(insnBrX16));
    memcpy(out + 8, &targetAddress, sizeof(targetAddress));
#else
    #error "Unsupported CPU architecture"
#endif
    return 16;
}

#pragma mark - 函数补丁

/*
 把目标函数 patch 成直接返回 YES / 非零。
 用于多开检测点（tryPreventMultiInstance / GetMainWeixinProcessCount）。
 */
static BOOL YMPatchFunctionReturnYES(uintptr_t address, const char *name) {
    if (address == 0) {
        YMLog(@"%s patch failed: address is zero", name);
        return NO;
    }

    void *target = (void *)address;

    uint8_t patch[8] = {0};
    size_t patchSize = YMEmitReturnYESStub(patch);

    YMPrintCodeBytes(name, "before", target);

    uint8_t current[8] = {0};
    memcpy(current, target, patchSize);

    if (memcmp(current, patch, patchSize) == 0) {
        YMLog(@"%s already patched, address=0x%lx", name, (unsigned long)address);
        return YES;
    }

    if (!YMProtectCodePage(address,
                           patchSize,
                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
                           name,
                           "RW|COPY")) {
        return NO;
    }

    memcpy(target, patch, patchSize);

    /*
     写指令后必须清 i-cache（arm64 必需；x86_64 上 sys_icache_invalidate 是安全空操作）。
     */
    sys_icache_invalidate(target, patchSize);

    if (!YMProtectCodePage(address,
                           patchSize,
                           VM_PROT_READ | VM_PROT_EXECUTE,
                           name,
                           "RX")) {
        return NO;
    }

    YMPrintCodeBytes(name, "after", target);

    uint8_t check[8] = {0};
    memcpy(check, target, patchSize);

    BOOL ok = memcmp(check, patch, patchSize) == 0;

    YMLog(@"%s patch result=%@, address=0x%lx",
          name,
          ok ? @"OK" : @"FAIL",
          (unsigned long)address);

    return ok;
}

/*
 把目标函数 patch 成直接返回 0（BlockEntry 防撤回）。
 与 YMPatchFunctionReturnYES 结构一致，只是写 return-0 桩。
 */
static BOOL YMPatchFunctionReturnZero(uintptr_t address, const char *name) {
    if (address == 0) {
        YMLog(@"%s patch failed: address is zero", name);
        return NO;
    }

    void *target = (void *)address;

    uint8_t patch[8] = {0};
    size_t patchSize = YMEmitReturnZeroStub(patch);

    YMPrintCodeBytes(name, "before", target);

    uint8_t current[8] = {0};
    memcpy(current, target, patchSize);

    if (memcmp(current, patch, patchSize) == 0) {
        YMLog(@"%s already patched, address=0x%lx", name, (unsigned long)address);
        return YES;
    }

    if (!YMProtectCodePage(address,
                           patchSize,
                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
                           name,
                           "RW|COPY")) {
        return NO;
    }

    memcpy(target, patch, patchSize);
    sys_icache_invalidate(target, patchSize);

    if (!YMProtectCodePage(address,
                           patchSize,
                           VM_PROT_READ | VM_PROT_EXECUTE,
                           name,
                           "RX")) {
        return NO;
    }

    YMPrintCodeBytes(name, "after", target);

    uint8_t check[8] = {0};
    memcpy(check, target, patchSize);
    BOOL ok = memcmp(check, patch, patchSize) == 0;

    YMLog(@"%s patch result=%@, address=0x%lx",
          name,
          ok ? @"OK" : @"FAIL",
          (unsigned long)address);

    return ok;
}

/*
 在 address 处写一个 16 字节绝对跳转到 targetAddress。
 用于函数入口 / 指定指令点的 inline hook（阻止原逻辑或转交我们的 hook）。
 */
static BOOL YMPatchFunctionEntryAbsoluteJump(uintptr_t address,
                                             uintptr_t targetAddress,
                                             const char *name) {
    if (address == 0 || targetAddress == 0) {
        YMLog(@"%s inline hook failed: address or target is zero", name);
        return NO;
    }

    void *target = (void *)address;

    uint8_t patch[16] = {0};
    size_t patchSize = YMEmitAbsoluteJump(targetAddress, patch);

    YMPrintCodeBytes(name, "before", target);

    uint8_t current[16] = {0};
    memcpy(current, target, patchSize);

    if (memcmp(current, patch, patchSize) == 0) {
        YMLog(@"%s already inline hooked, address=0x%lx",
              name,
              (unsigned long)address);
        return YES;
    }

    if (!YMProtectCodePage(address,
                           patchSize,
                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
                           name,
                           "RW|COPY")) {
        return NO;
    }

    memcpy(target, patch, patchSize);

    sys_icache_invalidate(target, patchSize);

    if (!YMProtectCodePage(address,
                           patchSize,
                           VM_PROT_READ | VM_PROT_EXECUTE,
                           name,
                           "RX")) {
        return NO;
    }

    uint8_t check[16] = {0};
    memcpy(check, target, patchSize);

    BOOL ok = memcmp(check, patch, patchSize) == 0;

    YMPrintCodeBytes(name, "after", target);

    YMLog(@"%s inline hook result=%@, address=0x%lx, target=0x%lx",
          name,
          ok ? @"OK" : @"FAIL",
          (unsigned long)address,
          (unsigned long)targetAddress);

    return ok;
}

#pragma mark - 本地插入灰色系统消息

/*
 参数 rawRevokeMessage：
   这是 ym_HandleSysMsg_RevokeMsg 原函数的第二个参数 X1。
   原函数会用 sub_4728670(rawWrap, rawRevokeMessage) 构造一个 MessageWrap。

 复用这一步，主要是为了拿到会话相关字段：
   rawWrap + 24
   rawWrap + 48

 然后构造自己的 type=10000 MessageWrap 插入本地聊天流。
 */
static BOOL YMInsertLocalAntiRevokeNotice(int64_t rawRevokeMessage) {
    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();
    if (!profile) {
        YMLog(@"insert local notice failed: no active profile");
        return NO;
    }

    if (YMWeChatDylibSlide == 0) {
        YMLog(@"insert local notice failed: YMWeChatDylibSlide is zero");
        return NO;
    }

    if (rawRevokeMessage == 0) {
        YMLog(@"insert local notice failed: rawRevokeMessage is zero");
        return NO;
    }

    YMLog(@"try insert local anti revoke notice by sub_3822FA4, rawRevokeMessage=0x%llx, profile=%s",
          (unsigned long long)rawRevokeMessage,
          profile->displayName);

    YMMessageWrapFromRawFunc MessageWrapFromRaw =
    (YMMessageWrapFromRawFunc)YMRuntimePointer(profile->messageWrapFromRawVA);

    YMMessageWrapDestructFunc MessageWrapDestruct =
    (YMMessageWrapDestructFunc)YMRuntimePointer(profile->messageWrapDestructVA);

    YMInsertPaySysMsgToSessionFunc InsertPaySysMsgToSession =
    (YMInsertPaySysMsgToSessionFunc)YMRuntimePointer(profile->insertPaySysMsgToSessionVA);

    if (!MessageWrapFromRaw || !MessageWrapDestruct || !InsertPaySysMsgToSession) {
        YMLog(@"insert local notice failed: internal function pointer is null");
        return NO;
    }

    /*
     rawWrap：
     复刻 ym_HandleSysMsg_RevokeMsg 原始逻辑：

       memcpy(rawWrap, unk_7861730, 616)
       sub_4728670(rawWrap, rawRevokeMessage)

     目的：
       只为了从 rawWrap 里拿到会话字段。
    */
    const size_t wrapSize = profile->layout.messageWrapSize;

    alignas(16) uint8_t rawWrap[616];
    memset(rawWrap, 0, sizeof(rawWrap));

    if (wrapSize > sizeof(rawWrap)) {
        YMLog(@"insert local notice failed: wrapSize too large. wrapSize=%zu", wrapSize);
        return NO;
    }

    void *rawTemplate = YMRuntimePointer(profile->rawMessageTemplateVA);
    if (!rawTemplate) {
        YMLog(@"insert local notice failed: rawTemplate is null");
        return NO;
    }

    memcpy(rawWrap, rawTemplate, wrapSize);

    MessageWrapFromRaw(rawWrap, rawRevokeMessage);

    BOOL ok = NO;

    try {
        std::string *rawField24 = YMRawWrapStringField(rawWrap, profile->layout.remoteUserOrSessionOffset);
        std::string *rawField48 = YMRawWrapStringField(rawWrap, profile->layout.selfUserOffset);

        NSString *remoteUserOrSessionText = YMNSStringFromStdString(rawField24);
        NSString *selfUserText = YMNSStringFromStdString(rawField48);

        YMLog(@"raw field24=%s", rawField24 ? rawField24->c_str() : "");
        YMLog(@"raw field48=%s", rawField48 ? rawField48->c_str() : "");

        /*
         从实际测试结果看：
           rawField24 = 对方 / 当前聊天会话
           rawField48 = 当前登录账号 / 自己

         所以这里必须用 rawField24 作为 session。
         */
        std::string *remoteUserOrSession = rawField24;
        std::string *selfUser = rawField48;

        std::string *session = remoteUserOrSession;

        if (!session || session->empty()) {
            YMLog(@"rawField24 is empty, fallback to rawField48");
            session = rawField48;
        }

        if (!session || session->empty()) {
            YMLog(@"insert local notice failed: session is empty");
            MessageWrapDestruct((int64_t)rawWrap);
            return NO;
        }

        uint32_t rawCreateTimeSec = YMRawWrapUInt32Field(rawWrap, profile->layout.createTimeSecOffset);
        uint64_t rawCreateTimeMs  = YMRawWrapUInt64Field(rawWrap, profile->layout.createTimeMsOffset);

        NSString *messageTimeText = YMFormatTimestamp(rawCreateTimeSec, rawCreateTimeMs);

        std::string *rawField72 = YMRawWrapStringField(rawWrap, 72);
        NSString *revokerWxid = YMNSStringFromStdString(rawField72);
        NSString *revokeXML = YMFindRevokeXMLFromRawWrap(rawWrap, wrapSize);

        if (revokerWxid.length == 0) {
            revokerWxid = YMRevokerWxidFromRevokeXMLPrefix(revokeXML);
        }

        NSString *revokeSession = YMExtractXMLTagValue(revokeXML, @"session");
        NSString *msgID = YMExtractXMLTagValue(revokeXML, @"msgid");
        NSString *newMsgID = YMExtractXMLTagValue(revokeXML, @"newmsgid");
        NSString *replaceMsg = YMExtractXMLTagValue(revokeXML, @"replacemsg");

        YMLog(@"raw field72=%s", rawField72 ? rawField72->c_str() : "");
        YMLog(@"raw revoke xml=%@", revokeXML ?: @"");
        YMLog(@"revoke parsed session=%@ msgid=%@ newmsgid=%@ revoker=%@ replace=%@ displayName=%@",
              revokeSession ?: @"",
              msgID ?: @"",
              newMsgID ?: @"",
              revokerWxid ?: @"",
              replaceMsg ?: @"",
              YMDisplayNameFromRevokeReplaceMsg(replaceMsg) ?: @"");

        NSString *noticeText = YMBuildAntiRevokeNoticeText(remoteUserOrSessionText,
                                                           selfUserText,
                                                           messageTimeText,
                                                           revokerWxid,
                                                           replaceMsg,
                                                           revokeSession,
                                                           msgID,
                                                           newMsgID);

        if (noticeText.length == 0) {
            noticeText = [NSString stringWithFormat:@"⚠️苏维埃已拦截撤回消息⚠️\n会话：%@\n%@",
                          remoteUserOrSessionText ?: @"",
                          messageTimeText ?: @""];
        }

        std::string content = YMStdStringFromNSString(noticeText);

        YMLog(@"raw createTimeSec=%u", rawCreateTimeSec);
        YMLog(@"raw createTimeMs=%llu", (unsigned long long)rawCreateTimeMs);
        YMLog(@"message time=%@", messageTimeText);

        YMLog(@"insert notice session=%s", session->c_str());
        YMLog(@"insert notice remoteUserOrSession=%s", remoteUserOrSession ? remoteUserOrSession->c_str() : "");
        YMLog(@"insert notice selfUser=%s", selfUser ? selfUser->c_str() : "");
        YMLog(@"insert notice content=%s", content.c_str());
        YMLog(@"call insertPaySysMsgToSession at 0x%lx",
              (unsigned long)YMRuntimeAddress(profile->insertPaySysMsgToSessionVA));

        int64_t result = InsertPaySysMsgToSession(0, session, &content);

        YMLog(@"insertPaySysMsgToSession result=0x%llx", (unsigned long long)result);

        ok = YES;
    } catch (...) {
        YMLog(@"exception while calling insertPaySysMsgToSession insert local notice");
        ok = NO;
    }

    MessageWrapDestruct((int64_t)rawWrap);

    return ok;
}

#pragma mark - 群员退群监控

static NSMutableDictionary<NSString *, NSSet<NSString *> *> *YMGroupExitMemberCache(void) {
    static NSMutableDictionary<NSString *, NSSet<NSString *> *> *cache = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cache = [[NSMutableDictionary alloc] init];
    });
    return cache;
}

static NSMutableDictionary<NSString *, NSDate *> *YMGroupExitRecentTipCache(void) {
    static NSMutableDictionary<NSString *, NSDate *> *cache = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cache = [[NSMutableDictionary alloc] init];
    });
    return cache;
}

static NSMutableArray<NSDictionary<NSString *, id> *> *YMGroupExitPendingNotices(void) {
    static NSMutableArray<NSDictionary<NSString *, id> *> *queue = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        queue = [[NSMutableArray alloc] init];
    });
    return queue;
}

static void YMGroupExitClearRuntimeStateIfDisabled(const char *source) {
    if (YMIsGroupExitMonitorEnabled()) {
        return;
    }

    NSMutableArray<NSDictionary<NSString *, id> *> *queue = YMGroupExitPendingNotices();
    @synchronized (queue) {
        if (queue.count > 0) {
            YMLog(@"[GroupExitMonitor] disabled, clear pending notices. source=%s count=%lu",
                  source ?: "",
                  (unsigned long)queue.count);
            [queue removeAllObjects];
        }
    }

    NSMutableDictionary<NSString *, NSSet<NSString *> *> *memberCache = YMGroupExitMemberCache();
    @synchronized (memberCache) {
        if (memberCache.count > 0) {
            [memberCache removeAllObjects];
        }
    }

    NSMutableDictionary<NSString *, NSDate *> *recentTipCache = YMGroupExitRecentTipCache();
    @synchronized (recentTipCache) {
        if (recentTipCache.count > 0) {
            [recentTipCache removeAllObjects];
        }
    }
}

static BOOL YMGroupExitProfileReady(const YMWeChatAdaptProfile *profile) {
    if (!profile) {
        return NO;
    }

    return profile->groupExitDBApplyVA != 0 &&
           profile->groupExitFMessagePreVA != 0 &&
           profile->groupExitUpdateSessionCacheVA != 0;
}

static BOOL YMGroupExitIsChatRoomID(NSString *roomID) {
    if (roomID.length == 0) {
        return NO;
    }

    return [roomID containsString:@"@chatroom"];
}

static BOOL YMGroupExitMemberIDLooksUseful(NSString *value, NSString *roomID) {
    if (value.length < 2 || value.length > 128) {
        return NO;
    }

    if (roomID.length > 0 && [value isEqualToString:roomID]) {
        return NO;
    }

    if ([value containsString:@"@chatroom"]) {
        return NO;
    }

    if ([value hasPrefix:@"wxid_"] ||
        [value hasPrefix:@"gh_"] ||
        [value containsString:@"@openim"] ||
        [value containsString:@"@stranger"] ||
        [value rangeOfString:@"^[A-Za-z0-9_\\-]{5,}$" options:NSRegularExpressionSearch].location != NSNotFound) {
        return YES;
    }

    return NO;
}

static NSString *YMGroupExitDisplayNameForMemberID(NSString *memberID, NSString *roomID) {
    // 当前这版先保守使用 memberID。后续如果逆出 contact / chatroom nickname 查询函数，再在这里替换成群昵称。
    if (memberID.length > 0) {
        return memberID;
    }

    return @"某成员";
}

static BOOL YMGroupExitShouldEmitTip(NSString *roomID, NSString *memberID) {
    if (roomID.length == 0 || memberID.length == 0) {
        return NO;
    }

    NSString *key = [NSString stringWithFormat:@"%@|%@", roomID, memberID];
    NSDate *now = [NSDate date];
    NSMutableDictionary<NSString *, NSDate *> *cache = YMGroupExitRecentTipCache();

    @synchronized (cache) {
        NSDate *last = cache[key];
        // 只防同一次 DB apply / session flush 造成的短时间重复提示。
        // 成员重新进群时会清掉这个 key，允许后续再次退群提示。
        if (last && [now timeIntervalSinceDate:last] < 3.0) {
            return NO;
        }

        cache[key] = now;

        if (cache.count > 512) {
            NSArray<NSString *> *allKeys = [cache allKeys];
            for (NSString *oldKey in allKeys) {
                NSDate *date = cache[oldKey];
                if (!date || [now timeIntervalSinceDate:date] > 300.0) {
                    [cache removeObjectForKey:oldKey];
                }
            }
        }
    }

    return YES;
}

static void YMGroupExitClearRecentTip(NSString *roomID, NSString *memberID, NSString *reason) {
    if (roomID.length == 0 || memberID.length == 0) {
        return;
    }

    NSString *key = [NSString stringWithFormat:@"%@|%@", roomID, memberID];
    NSMutableDictionary<NSString *, NSDate *> *cache = YMGroupExitRecentTipCache();

    @synchronized (cache) {
        if (cache[key]) {
            [cache removeObjectForKey:key];
            YMLog(@"[GroupExitMonitor] recent tip cache cleared. room=%@ member=%@ reason=%@",
                  roomID,
                  memberID,
                  reason ?: @"");
        }
    }
}

static void YMGroupExitEnqueueNotice(NSString *roomID, NSString *memberID, NSString *noticeText) {
    if (!YMGroupExitIsChatRoomID(roomID) || memberID.length == 0 || noticeText.length == 0) {
        return;
    }

    if (!YMGroupExitShouldEmitTip(roomID, memberID)) {
        YMLog(@"[GroupExitMonitor] duplicate tip suppressed. room=%@ member=%@", roomID, memberID);
        return;
    }

    NSString *key = [NSString stringWithFormat:@"%@|%@", roomID, memberID];
    NSMutableArray<NSDictionary<NSString *, id> *> *queue = YMGroupExitPendingNotices();
    NSDate *now = [NSDate date];

    @synchronized (queue) {
        for (NSDictionary<NSString *, id> *item in queue) {
            NSString *oldKey = item[@"key"];
            if ([oldKey isEqualToString:key]) {
                YMLog(@"[GroupExitMonitor] pending duplicate suppressed. room=%@ member=%@", roomID, memberID);
                return;
            }
        }

        NSDictionary<NSString *, id> *item = @{
            @"key": key,
            @"roomID": roomID,
            @"memberID": memberID,
            @"noticeText": noticeText,
            @"date": now,
        };

        [queue addObject:item];

        while (queue.count > 128) {
            [queue removeObjectAtIndex:0];
        }
    }

    YMLog(@"[GroupExitMonitor] notice queued. room=%@ member=%@ notice=%@", roomID, memberID, noticeText);
}

static NSArray<NSDictionary<NSString *, id> *> *YMGroupExitDrainPendingNotices(NSUInteger maxCount) {
    NSMutableArray<NSDictionary<NSString *, id> *> *queue = YMGroupExitPendingNotices();
    NSMutableArray<NSDictionary<NSString *, id> *> *items = [NSMutableArray array];

    @synchronized (queue) {
        if (queue.count == 0) {
            return @[];
        }

        NSUInteger count = MIN(maxCount, queue.count);
        for (NSUInteger i = 0; i < count; i++) {
            [items addObject:queue[i]];
        }

        NSRange range = NSMakeRange(0, count);
        [queue removeObjectsInRange:range];
    }

    return [items copy];
}

static NSDictionary<NSString *, NSSet<NSString *> *> *YMGroupExitReadSnapshotsFromDBApplyTask(int64_t task) {
    if (task == 0) {
        return @{};
    }

    uintptr_t vectorObject = 0;
    if (!YMSafeReadPointer((uintptr_t)task + 24, &vectorObject)) {
        YMLog(@"[GroupExitMonitor] DB apply read vector pointer failed. task=0x%llx", (unsigned long long)task);
        return @{};
    }

    if (vectorObject == 0 || vectorObject < 0x100000000ULL) {
        YMLog(@"[GroupExitMonitor] DB apply invalid vector pointer. task=0x%llx vector=0x%lx",
              (unsigned long long)task,
              (unsigned long)vectorObject);
        return @{};
    }

    uintptr_t begin = 0;
    uintptr_t end = 0;
    uintptr_t cap = 0;
    if (!YMSafeReadPointer(vectorObject + 0, &begin) ||
        !YMSafeReadPointer(vectorObject + 8, &end) ||
        !YMSafeReadPointer(vectorObject + 16, &cap)) {
        YMLog(@"[GroupExitMonitor] DB apply read vector begin/end/cap failed. vector=0x%lx", (unsigned long)vectorObject);
        return @{};
    }

    if (begin == 0 || end == 0 || end < begin || cap < end || begin < 0x100000000ULL) {
        YMLog(@"[GroupExitMonitor] DB apply invalid vector bounds. vector=0x%lx begin=0x%lx end=0x%lx cap=0x%lx",
              (unsigned long)vectorObject,
              (unsigned long)begin,
              (unsigned long)end,
              (unsigned long)cap);
        return @{};
    }

    const size_t entrySize = 80;
    uintptr_t byteSize = end - begin;
    if (byteSize == 0 || (byteSize % entrySize) != 0) {
        YMLog(@"[GroupExitMonitor] DB apply vector size mismatch. vector=0x%lx begin=0x%lx end=0x%lx byteSize=%lu",
              (unsigned long)vectorObject,
              (unsigned long)begin,
              (unsigned long)end,
              (unsigned long)byteSize);
        return @{};
    }

    size_t count = (size_t)(byteSize / entrySize);
    if (count == 0 || count > 20000) {
        YMLog(@"[GroupExitMonitor] DB apply unreasonable member count=%zu, skip. vector=0x%lx", count, (unsigned long)vectorObject);
        return @{};
    }

    NSMutableDictionary<NSString *, NSMutableSet<NSString *> *> *groups = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSMutableArray<NSString *> *> *samples = [NSMutableDictionary dictionary];

    for (size_t i = 0; i < count; i++) {
        uintptr_t entry = begin + i * entrySize;

        //LLDB搞出来 ：entry+8 是 roomId，entry+32 是 memberId。
        NSString *roomID = YMNSStringFromLibcppStringObject((const void *)(entry + 8));
        NSString *memberID = YMNSStringFromLibcppStringObject((const void *)(entry + 32));

        if (!YMGroupExitIsChatRoomID(roomID)) {
            continue;
        }

        if (!YMGroupExitMemberIDLooksUseful(memberID, roomID)) {
            continue;
        }

        NSMutableSet<NSString *> *set = groups[roomID];
        if (!set) {
            set = [NSMutableSet set];
            groups[roomID] = set;
        }
        [set addObject:memberID];

        NSMutableArray<NSString *> *sample = samples[roomID];
        if (!sample) {
            sample = [NSMutableArray array];
            samples[roomID] = sample;
        }
        if (sample.count < 6) {
            [sample addObject:memberID];
        }
    }

    if (groups.count == 0) {
        YMLog(@"[GroupExitMonitor] DB apply parsed no valid chatroom members. task=0x%llx vector=0x%lx count=%zu",
              (unsigned long long)task,
              (unsigned long)vectorObject,
              count);
        return @{};
    }

    NSMutableDictionary<NSString *, NSSet<NSString *> *> *result = [NSMutableDictionary dictionary];
    for (NSString *roomID in groups) {
        NSSet<NSString *> *members = [groups[roomID] copy];
        result[roomID] = members;

        YMLog(@"[GroupExitMonitor] DB apply members room=%@ count=%lu vector=0x%lx samples=%@",
              roomID,
              (unsigned long)members.count,
              (unsigned long)vectorObject,
              [samples[roomID] componentsJoinedByString:@", "] ?: @"");
    }

    return [result copy];
}

static void YMGroupExitHandleDBApplySnapshot(NSString *roomID, NSSet<NSString *> *newSnapshot) {
    if (!YMGroupExitIsChatRoomID(roomID) || newSnapshot.count == 0) {
        return;
    }

    NSMutableArray<NSString *> *leftMembers = [NSMutableArray array];
    NSMutableArray<NSString *> *addedMembers = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSSet<NSString *> *> *cache = YMGroupExitMemberCache();
    NSUInteger oldCount = 0;
    NSUInteger newCount = newSnapshot.count;

    @synchronized (cache) {
        NSSet<NSString *> *oldSnapshot = cache[roomID];

        if (oldSnapshot.count == 0) {
            cache[roomID] = [newSnapshot copy];
            YMLog(@"[GroupExitMonitor] DB first snapshot stored. room=%@ members=%lu",
                  roomID,
                  (unsigned long)newSnapshot.count);
            return;
        }

        oldCount = oldSnapshot.count;

        if (![oldSnapshot isEqualToSet:newSnapshot]) {
            NSMutableSet<NSString *> *removed = [oldSnapshot mutableCopy];
            [removed minusSet:newSnapshot];

            NSMutableSet<NSString *> *added = [newSnapshot mutableCopy];
            [added minusSet:oldSnapshot];

            for (NSString *memberID in added) {
                if (memberID.length > 0) {
                    [addedMembers addObject:memberID];
                }
            }

            // DB apply 层已经是 chatroom_member 写库任务，直接按 confirmed cache 做 diff。
            // 仍然保留基本安全阈值，避免结构读取异常导致一次性误报大量成员。
            if (removed.count > 0 && newSnapshot.count < oldSnapshot.count && removed.count <= 20 && removed.count < oldSnapshot.count) {
                for (NSString *memberID in removed) {
                    if (memberID.length > 0) {
                        [leftMembers addObject:memberID];
                    }
                }
            } else if (removed.count > 0) {
                YMLog(@"[GroupExitMonitor] DB removed set not treated as exit. room=%@ old=%lu new=%lu removed=%lu added=%lu",
                      roomID,
                      (unsigned long)oldSnapshot.count,
                      (unsigned long)newSnapshot.count,
                      (unsigned long)removed.count,
                      (unsigned long)added.count);
            }
        }

        cache[roomID] = [newSnapshot copy];
    }

    for (NSString *memberID in addedMembers) {
        YMGroupExitClearRecentTip(roomID, memberID, @"member appeared in DB snapshot");
    }

    if (leftMembers.count == 0) {
        YMLog(@"[GroupExitMonitor] DB snapshot updated, no member left. room=%@ old=%lu new=%lu",
              roomID,
              (unsigned long)oldCount,
              (unsigned long)newCount);
        return;
    }

    for (NSString *memberID in leftMembers) {
        NSString *displayName = YMGroupExitDisplayNameForMemberID(memberID, roomID);
        NSString *exitTimeText = YMFormatTimestamp(0, 0);
        NSString *noticeText = [NSString stringWithFormat:@"⚠️苏维埃退群监控⚠️\n%@ 已退群\n%@",
                                displayName ?: memberID,
                                exitTimeText ?: @""];

        YMLog(@"[GroupExitMonitor] DB member left detected. room=%@ member=%@ old=%lu new=%lu notice=%@",
              roomID,
              memberID,
              (unsigned long)oldCount,
              (unsigned long)newCount,
              noticeText ?: @"");

        YMGroupExitEnqueueNotice(roomID, memberID, noticeText);
    }
}

static void YMGroupExitHandleDBApplySnapshots(NSDictionary<NSString *, NSSet<NSString *> *> *snapshots,
                                              int64_t originalResult) {
    if (snapshots.count == 0) {
        return;
    }

    YMLog(@"[GroupExitMonitor] DB apply original result=0x%llx rooms=%lu",
          (unsigned long long)originalResult,
          (unsigned long)snapshots.count);

    for (NSString *roomID in snapshots) {
        NSSet<NSString *> *members = snapshots[roomID];
        YMGroupExitHandleDBApplySnapshot(roomID, members);
    }
}

static BOOL YMGroupExitInsertLocalSystemNotice(NSString *roomID,
                                               NSString *noticeText,
                                               const char *source) {
    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();
    if (!profile) {
        YMLog(@"[GroupExitMonitor] insert failed: no active profile, source=%s", source ?: "");
        return NO;
    }

    if (YMWeChatDylibSlide == 0) {
        YMLog(@"[GroupExitMonitor] insert failed: YMWeChatDylibSlide is zero, source=%s", source ?: "");
        return NO;
    }

    if (!YMGroupExitIsChatRoomID(roomID) || noticeText.length == 0) {
        YMLog(@"[GroupExitMonitor] insert failed: invalid room/content. room=%@ source=%s",
              roomID ?: @"",
              source ?: "");
        return NO;
    }

    YMInsertPaySysMsgToSessionFunc InsertPaySysMsgToSession =
    (YMInsertPaySysMsgToSessionFunc)YMRuntimePointer(profile->insertPaySysMsgToSessionVA);

    if (!InsertPaySysMsgToSession) {
        YMLog(@"[GroupExitMonitor] insert failed: InsertPaySysMsgToSession is NULL, source=%s", source ?: "");
        return NO;
    }

    std::string session = YMStdStringFromNSString(roomID);
    std::string content = YMStdStringFromNSString(noticeText);

    if (session.empty() || content.empty()) {
        YMLog(@"[GroupExitMonitor] insert failed: std::string empty. room=%@ source=%s",
              roomID ?: @"",
              source ?: "");
        return NO;
    }

    YMLog(@"[GroupExitMonitor] insert notice source=%s session=%s contentText=%@ contentLen=%zu",
          source ?: "",
          session.c_str(),
          noticeText ?: @"",
          content.size());

    int64_t result = InsertPaySysMsgToSession(0, &session, &content);

    YMLog(@"[GroupExitMonitor] insert notice result=0x%llx source=%s",
          (unsigned long long)result,
          source ?: "");

    return YES;
}

static void YMGroupExitFlushPendingNotices(const char *source) {
    if (YMGroupExitFlushingPending.exchange(true)) {
        return;
    }

    @autoreleasepool {
        NSArray<NSDictionary<NSString *, id> *> *items = YMGroupExitDrainPendingNotices(20);
        if (items.count == 0) {
            YMGroupExitFlushingPending.store(false);
            return;
        }

        YMLog(@"[GroupExitMonitor] flush pending notices source=%s count=%lu",
              source ?: "",
              (unsigned long)items.count);

        for (NSDictionary<NSString *, id> *item in items) {
            NSString *roomID = item[@"roomID"];
            NSString *memberID = item[@"memberID"];
            NSString *noticeText = item[@"noticeText"];

            YMLog(@"[GroupExitMonitor] flush notice. room=%@ member=%@ notice=%@",
                  roomID ?: @"",
                  memberID ?: @"",
                  noticeText ?: @"");

            YMGroupExitInsertLocalSystemNotice(roomID,
                                               noticeText,
                                               source ?: "unknown");
        }
    }

    YMGroupExitFlushingPending.store(false);
}

static void YMGroupExitBuildAbsoluteJump(uintptr_t targetAddress, uint8_t patch[16]) {
    // 复用统一的架构发射器，保证 arm64 / x86_64 跳板一致。
    YMEmitAbsoluteJump(targetAddress, patch);
}

static BOOL YMGroupExitWriteCodeBytes(uintptr_t address,
                                      const uint8_t *bytes,
                                      size_t size,
                                      const char *name,
                                      const char *stage) {
    if (address == 0 || !bytes || size == 0) {
        YMLog(@"[GroupExitMonitor] write code failed: invalid argument, name=%s stage=%s", name ?: "", stage ?: "");
        return NO;
    }

    if (!YMProtectCodePage(address,
                           size,
                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
                           name ?: "group exit hook",
                           stage ?: "RW|COPY")) {
        return NO;
    }

    memcpy((void *)address, bytes, size);
    sys_icache_invalidate((void *)address, size);

    if (!YMProtectCodePage(address,
                           size,
                           VM_PROT_READ | VM_PROT_EXECUTE,
                           name ?: "group exit hook",
                           "RX")) {
        return NO;
    }

    return YES;
}

static BOOL YMGroupExitRestoreOriginalDBApply(void) {
    if (!YMGroupExitDBApplyRuntimeAddress || !YMGroupExitHasSavedOriginalDBApplyBytes) {
        return NO;
    }

    return YMGroupExitWriteCodeBytes(YMGroupExitDBApplyRuntimeAddress,
                                     YMGroupExitOriginalDBApplyBytes,
                                     sizeof(YMGroupExitOriginalDBApplyBytes),
                                     "group exit DB apply",
                                     "restore original");
}

static BOOL YMGroupExitReapplyDBApplyHook(void) {
    if (!YMGroupExitDBApplyRuntimeAddress) {
        return NO;
    }

    return YMGroupExitWriteCodeBytes(YMGroupExitDBApplyRuntimeAddress,
                                     YMGroupExitHookDBApplyBytes,
                                     sizeof(YMGroupExitHookDBApplyBytes),
                                     "group exit DB apply",
                                     "reapply hook");
}

static int64_t YMGroupExitCallOriginalDBApply(int64_t task) {
    if (!YMGroupExitDBApplyRuntimeAddress) {
        return 0;
    }

    if (YMGroupExitCallingOriginalDBApply.exchange(true)) {
        YMLog(@"[GroupExitMonitor] recursive original DB apply call suppressed");
        return 0;
    }

    BOOL restored = YMGroupExitRestoreOriginalDBApply();
    if (!restored) {
        YMLog(@"[GroupExitMonitor] restore original DB apply failed, skip calling original to avoid recursion");
        YMGroupExitCallingOriginalDBApply.store(false);
        return 0;
    }

    YMGroupExitDBApplyFunc Original =
    (YMGroupExitDBApplyFunc)YMGroupExitDBApplyRuntimeAddress;

    int64_t result = 0;
    try {
        result = Original(task);
    } catch (...) {
        YMLog(@"[GroupExitMonitor] exception while calling original DB apply");
    }

    YMGroupExitReapplyDBApplyHook();
    YMGroupExitCallingOriginalDBApply.store(false);
    return result;
}

static BOOL YMGroupExitRestoreOriginalFMessagePre(void) {
    if (!YMGroupExitFMessagePreRuntimeAddress || !YMGroupExitHasSavedOriginalFMessagePreBytes) {
        return NO;
    }

    return YMGroupExitWriteCodeBytes(YMGroupExitFMessagePreRuntimeAddress,
                                     YMGroupExitOriginalFMessagePreBytes,
                                     sizeof(YMGroupExitOriginalFMessagePreBytes),
                                     "group exit fmessage_manager::InsertFMessageToSessionPre",
                                     "restore original");
}

static BOOL YMGroupExitReapplyFMessagePreHook(void) {
    if (!YMGroupExitFMessagePreRuntimeAddress) {
        return NO;
    }

    return YMGroupExitWriteCodeBytes(YMGroupExitFMessagePreRuntimeAddress,
                                     YMGroupExitHookFMessagePreBytes,
                                     sizeof(YMGroupExitHookFMessagePreBytes),
                                     "group exit fmessage_manager::InsertFMessageToSessionPre",
                                     "reapply hook");
}

static void YMGroupExitCallOriginalFMessagePre(int64_t a1, int64_t *a2) {
    if (!YMGroupExitFMessagePreRuntimeAddress) {
        return;
    }

    if (YMGroupExitCallingOriginalFMessagePre.exchange(true)) {
        YMLog(@"[GroupExitMonitor] recursive original FMessagePre call suppressed");
        return;
    }

    BOOL restored = YMGroupExitRestoreOriginalFMessagePre();
    if (!restored) {
        YMLog(@"[GroupExitMonitor] restore original FMessagePre failed, skip calling original to avoid recursion");
        YMGroupExitCallingOriginalFMessagePre.store(false);
        return;
    }

    YMGroupExitFMessagePreFunc Original =
    (YMGroupExitFMessagePreFunc)YMGroupExitFMessagePreRuntimeAddress;

    try {
        Original(a1, a2);
    } catch (...) {
        YMLog(@"[GroupExitMonitor] exception while calling original InsertFMessageToSessionPre");
    }

    YMGroupExitReapplyFMessagePreHook();
    YMGroupExitCallingOriginalFMessagePre.store(false);
}

static BOOL YMGroupExitRestoreOriginalUpdateSessionCache(void) {
    if (!YMGroupExitUpdateSessionCacheRuntimeAddress || !YMGroupExitHasSavedOriginalUpdateSessionCacheBytes) {
        return NO;
    }

    return YMGroupExitWriteCodeBytes(YMGroupExitUpdateSessionCacheRuntimeAddress,
                                     YMGroupExitOriginalUpdateSessionCacheBytes,
                                     sizeof(YMGroupExitOriginalUpdateSessionCacheBytes),
                                     "group exit session_service::UpdateSessionCache",
                                     "restore original");
}

static BOOL YMGroupExitReapplyUpdateSessionCacheHook(void) {
    if (!YMGroupExitUpdateSessionCacheRuntimeAddress) {
        return NO;
    }

    return YMGroupExitWriteCodeBytes(YMGroupExitUpdateSessionCacheRuntimeAddress,
                                     YMGroupExitHookUpdateSessionCacheBytes,
                                     sizeof(YMGroupExitHookUpdateSessionCacheBytes),
                                     "group exit session_service::UpdateSessionCache",
                                     "reapply hook");
}

static void YMGroupExitCallOriginalUpdateSessionCache(uint64_t a1, int64_t a2, int64_t a3, int a4) {
    if (!YMGroupExitUpdateSessionCacheRuntimeAddress) {
        return;
    }

    if (YMGroupExitCallingOriginalUpdateSessionCache.exchange(true)) {
        YMLog(@"[GroupExitMonitor] recursive original UpdateSessionCache call suppressed");
        return;
    }

    BOOL restored = YMGroupExitRestoreOriginalUpdateSessionCache();
    if (!restored) {
        YMLog(@"[GroupExitMonitor] restore original UpdateSessionCache failed, skip calling original to avoid recursion");
        YMGroupExitCallingOriginalUpdateSessionCache.store(false);
        return;
    }

    YMGroupExitUpdateSessionCacheFunc Original =
    (YMGroupExitUpdateSessionCacheFunc)YMGroupExitUpdateSessionCacheRuntimeAddress;

    try {
        Original(a1, a2, a3, a4);
    } catch (...) {
        YMLog(@"[GroupExitMonitor] exception while calling original UpdateSessionCache");
    }

    YMGroupExitReapplyUpdateSessionCacheHook();
    YMGroupExitCallingOriginalUpdateSessionCache.store(false);
}

static int64_t YMGroupExitDBApplyHook(int64_t task) {
    @autoreleasepool {
        if (!YMIsGroupExitMonitorEnabled()) {
            YMGroupExitClearRuntimeStateIfDisabled("DB apply hook");
            return YMGroupExitCallOriginalDBApply(task);
        }

        NSDictionary<NSString *, NSSet<NSString *> *> *snapshots = YMGroupExitReadSnapshotsFromDBApplyTask(task);

        int64_t result = YMGroupExitCallOriginalDBApply(task);

        if (YMIsGroupExitMonitorEnabled()) {
            YMGroupExitHandleDBApplySnapshots(snapshots, result);
        } else {
            YMGroupExitClearRuntimeStateIfDisabled("DB apply hook after original");
        }

        return result;
    }
}

static void YMGroupExitFMessagePreHook(int64_t a1, int64_t *a2) {
    @autoreleasepool {
        YMGroupExitCallOriginalFMessagePre(a1, a2);

        if (YMIsGroupExitMonitorEnabled()) {
            YMGroupExitFlushPendingNotices("fmessage_manager InsertFMessageToSessionPre");
        } else {
            YMGroupExitClearRuntimeStateIfDisabled("fmessage_manager InsertFMessageToSessionPre");
        }
    }
}

static void YMGroupExitUpdateSessionCacheHook(uint64_t a1, int64_t a2, int64_t a3, int a4) {
    @autoreleasepool {
        YMGroupExitCallOriginalUpdateSessionCache(a1, a2, a3, a4);

        if (YMIsGroupExitMonitorEnabled()) {
            YMGroupExitFlushPendingNotices("session_service UpdateSessionCache");
        } else {
            YMGroupExitClearRuntimeStateIfDisabled("session_service UpdateSessionCache");
        }
    }
}

static BOOL YMPatchGroupExitSingleFunction(uintptr_t targetAddress,
                                           uintptr_t hookAddress,
                                           uint8_t originalBytes[16],
                                           uint8_t hookBytes[16],
                                           BOOL *hasSavedOriginalBytes,
                                           uintptr_t *runtimeAddressStorage,
                                           const char *name,
                                           NSString *source) {
    if (targetAddress == 0 || hookAddress == 0 || !originalBytes || !hookBytes || !hasSavedOriginalBytes || !runtimeAddressStorage) {
        YMLog(@"[GroupExitMonitor] invalid single hook argument: %s", name ?: "");
        return NO;
    }

    *runtimeAddressStorage = targetAddress;
    YMGroupExitBuildAbsoluteJump(hookAddress, hookBytes);

    uint8_t current[16] = {0};
    memcpy(current, (void *)targetAddress, sizeof(current));

    if (memcmp(current, hookBytes, sizeof(current)) == 0) {
        YMLog(@"[GroupExitMonitor] %s already hooked, address=0x%lx source=%@",
              name ?: "",
              (unsigned long)targetAddress,
              source ?: @"");
        *hasSavedOriginalBytes = YES;
        return YES;
    }

    memcpy(originalBytes, current, sizeof(current));
    *hasSavedOriginalBytes = YES;

    BOOL ok = YMGroupExitWriteCodeBytes(targetAddress,
                                        hookBytes,
                                        16,
                                        name ?: "group exit hook",
                                        "install hook");

    YMLog(@"[GroupExitMonitor] hook result=%@ name=%s source=%@ target=0x%lx hook=0x%lx",
          ok ? @"OK" : @"FAIL",
          name ?: "",
          source ?: @"",
          (unsigned long)targetAddress,
          (unsigned long)hookAddress);

    return ok;
}

static BOOL YMPatchGroupExitMonitorWithSlide(intptr_t slide, NSString *source) {
    if (YMHasPatchedGroupExitMonitor) {
        YMLog(@"[GroupExitMonitor] already patched, skip. source=%@", source);
        return YES;
    }

    if (!YMIsTargetWeChatVersion()) {
        YMLog(@"[GroupExitMonitor] unsupported WeChat version, skip. source=%@", source);
        return NO;
    }

    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();
    if (!YMGroupExitProfileReady(profile)) {
        YMLog(@"[GroupExitMonitor] current profile has no group exit addresses, skip. profile=%s",
              profile ? profile->displayName : "NULL");
        return NO;
    }

    YMWeChatDylibSlide = (uintptr_t)slide;

    uintptr_t dbApplyTarget = YMRuntimeAddress(profile->groupExitDBApplyVA);
    uintptr_t fmessagePreTarget = YMRuntimeAddress(profile->groupExitFMessagePreVA);
    uintptr_t updateSessionCacheTarget = YMRuntimeAddress(profile->groupExitUpdateSessionCacheVA);

    uintptr_t dbApplyHook = (uintptr_t)&YMGroupExitDBApplyHook;
    uintptr_t fmessagePreHook = (uintptr_t)&YMGroupExitFMessagePreHook;
    uintptr_t updateSessionCacheHook = (uintptr_t)&YMGroupExitUpdateSessionCacheHook;

    BOOL okDBApply = YMPatchGroupExitSingleFunction(dbApplyTarget,
                                                   dbApplyHook,
                                                   YMGroupExitOriginalDBApplyBytes,
                                                   YMGroupExitHookDBApplyBytes,
                                                   &YMGroupExitHasSavedOriginalDBApplyBytes,
                                                   &YMGroupExitDBApplyRuntimeAddress,
                                                   "group exit contact_storage chatroom_member DB apply",
                                                   source);

    BOOL okFMessagePre = YMPatchGroupExitSingleFunction(fmessagePreTarget,
                                                       fmessagePreHook,
                                                       YMGroupExitOriginalFMessagePreBytes,
                                                       YMGroupExitHookFMessagePreBytes,
                                                       &YMGroupExitHasSavedOriginalFMessagePreBytes,
                                                       &YMGroupExitFMessagePreRuntimeAddress,
                                                       "group exit fmessage_manager::InsertFMessageToSessionPre",
                                                       source);

    BOOL okUpdateSessionCache = YMPatchGroupExitSingleFunction(updateSessionCacheTarget,
                                                              updateSessionCacheHook,
                                                              YMGroupExitOriginalUpdateSessionCacheBytes,
                                                              YMGroupExitHookUpdateSessionCacheBytes,
                                                              &YMGroupExitHasSavedOriginalUpdateSessionCacheBytes,
                                                              &YMGroupExitUpdateSessionCacheRuntimeAddress,
                                                              "group exit session_service::UpdateSessionCache",
                                                              source);

    BOOL ok = okDBApply && okFMessagePre && okUpdateSessionCache;

    YMLog(@"[GroupExitMonitor] patch result=%@ source=%@ profile=%s slide=0x%lx DBApply=0x%lx FMessagePre=0x%lx UpdateSessionCache=0x%lx",
          ok ? @"OK" : @"FAIL",
          source ?: @"",
          profile->displayName,
          (unsigned long)YMWeChatDylibSlide,
          (unsigned long)dbApplyTarget,
          (unsigned long)fmessagePreTarget,
          (unsigned long)updateSessionCacheTarget);

    YMHasPatchedGroupExitMonitor = ok;
    return ok;
}

static BOOL YMFindAndPatchLoadedGroupExitWeChatDylib(void) {
    uint32_t count = _dyld_image_count();

    YMLog(@"[GroupExitMonitor] scan dyld images, count=%u", count);

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) {
            continue;
        }

        NSString *imagePath = [NSString stringWithUTF8String:name];

        if (!YMIsTargetWeChatResourceDylibPath(imagePath)) {
            continue;
        }

        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        YMLog(@"[GroupExitMonitor] found Resources/wechat.dylib: index=%u, slide=0x%lx, path=%@",
              i,
              (unsigned long)slide,
              imagePath);

        return YMPatchGroupExitMonitorWithSlide(slide, @"dyld image scan");
    }

    YMLog(@"[GroupExitMonitor] Resources/wechat.dylib not found");
    return NO;
}

static void YMInstallGroupExitMonitorPatch(void) {
    if (!YMIsGroupExitMonitorEnabled()) {
        YMLog(@"[GroupExitMonitor] disabled by user defaults, skip install");
        YMGroupExitClearRuntimeStateIfDisabled("install skip");
        return;
    }

    if (YMHasPatchedGroupExitMonitor) {
        return;
    }

    YMRegisterDyldCallbackIfNeeded();
    YMFindAndPatchLoadedGroupExitWeChatDylib();
}




#pragma mark - 撤回原消息局部 Callsite Hook（4.1.10）

/*
fileOffset=0x2b70954 level=2 file=message_revoke_manager.cc func=CoReplaceOriginMessageByRevoke line=1069 ctx=0x1753bfd88 做撤回,
fileOffset=0x281a0f4 level=2 file=message_manager.cc func=GetMessageBySvrIdOnRecent line=2435 ctx=0x1753bfb58  这里面的函数去调用拿到原始MessageWrap
  sub_4247180(&v148);
   sub_1382484(v147, v148);
   sub_211A334(v139, *(_QWORD *)v147);
   sub_2819F44(__dst, v139[0], v137 + 392, *((_QWORD *)v137 + 45));//不要去直接去碰sub_2819F44这个函数,要去碰他的地址:
   __text:0000000002B7123C                 ADD             X1, X9, #0x188
 __text:0000000002B71240                 BL              sub_2819F44
 __text:0000000002B71244                 LDR             X22, [SP,#0x920+var_650+8]//碰这个指令
 __text:0000000002B71248                 CBZ             X22, loc_2B71274
 __text:0000000002B7124C                 ADD             X8, X22, #8
 __text:0000000002B71250                 MOV             X9, #0xFFFFFFFFFFFFFFFF

 [YMAntiRevoke] [WXLOG] fileOffset=0x2814cb4 level=2 file=message_manager.cc func=DeleteMessages line=2155
 */

// 地址放到 YMWeChatAdaptProfile 里了，后面适配新版别满文件乱搜。

extern "C" uintptr_t YMRevokeOriginCallsiteContinueAddress;
extern "C" uintptr_t YMRevokeOriginCallsiteZeroBranchAddress;
extern "C" void YMRevokeOriginCallsiteHelper(uintptr_t originalSP, uintptr_t savedRegs);
extern "C" void YMRevokeOriginCallsiteStub(void);

uintptr_t YMRevokeOriginCallsiteContinueAddress = 0;
uintptr_t YMRevokeOriginCallsiteZeroBranchAddress = 0;

static uintptr_t YMRevokeDeleteMessagesRuntimeAddress = 0;
static uint8_t YMRevokeDeleteMessagesOriginalBytes[16] = {0};
static uint8_t YMRevokeDeleteMessagesHookBytes[16] = {0};
static BOOL YMRevokeDeleteMessagesHasSavedOriginalBytes = NO;
static std::atomic_bool YMRevokeDeleteMessagesCallingOriginal(false);

static __thread BOOL YMRevokeDeleteGuardActive = NO;
static __thread uint64_t YMRevokeLastNoticeSvrIdInCallsite = 0;
static __thread uint64_t YMRevokeTargetSvrIdForDeleteGuard = 0;

static NSString *YMRevokeMessageTypeName(uint32_t type) {
    switch (type) {
        case 1: return @"[文本消息]";
        case 3: return @"[图片消息]";
        case 34: return @"[语音消息]";
        case 43: return @"[视频消息]";
        case 47: return @"[表情包]";
        case 48: return @"[位置消息]";
        case 49: return @"[卡片/文件/链接消息]";
        case 10000: return @"[10000（系统消息]";
        case 10002: return @"[10002（系统通知]";
        default: return [NSString stringWithFormat:@"%u", type];
    }
}

static BOOL YMRevokeMessageTypeShouldShowContent(uint32_t type) {
    return type == 1;
}

static BOOL YMRevokeOriginTextLooksUseless(NSString *text) {
    if (text.length == 0) {
        return NO;
    }

    return [text containsString:@"暂不支持该内容"] ||
           [text containsString:@"请在手机上查看"];
}

static NSString *YMRevokeShortLogText(NSString *text) {
    if (text.length == 0) {
        return @"";
    }

    if (text.length > 300) {
        return [[text substringToIndex:300] stringByAppendingString:@"…"];
    }

    return text;
}

static NSString *YMCleanOriginMessageContent(NSString *rawContent, NSString **senderOut) {
    if (senderOut) {
        *senderOut = @"";
    }

    if (rawContent.length == 0) {
        return @"";
    }

    NSString *text = [rawContent stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";

    // 群聊文本常见格式：wxid_xxx:\n内容。展示时把前缀拆出来。
    NSRange colonNewline = [text rangeOfString:@":\n"];
    if (colonNewline.location != NSNotFound && colonNewline.location > 0) {
        NSString *prefix = [text substringToIndex:colonNewline.location] ?: @"";
        NSString *body = [text substringFromIndex:NSMaxRange(colonNewline)] ?: @"";
        prefix = [prefix stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        body = [body stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (prefix.length > 0 && senderOut) {
            *senderOut = prefix;
        }
        if (body.length > 0) {
            return body;
        }
    }

    return text;
}


static BOOL YMRevokeXMLMatchesSvrId(NSString *revokeXML, uint64_t expectedSvrId) {
    if (revokeXML.length == 0) {
        return NO;
    }

    if (expectedSvrId == 0) {
        return YES;
    }

    NSString *newMsgID = YMExtractXMLTagValue(revokeXML, @"newmsgid");
    if (newMsgID.length == 0) {
        newMsgID = YMExtractXMLTagValue(revokeXML, @"newsvrid");
    }
    if (newMsgID.length == 0) {
        return YES;
    }

    uint64_t xmlSvrId = strtoull(newMsgID.UTF8String ?: "", NULL, 10);
    return xmlSvrId == expectedSvrId;
}

static BOOL YMExtractRevokeContextFromWrap(uintptr_t wrap,
                                           uint64_t expectedSvrId,
                                           NSString **xmlOut,
                                           NSString **revokerWxidOut,
                                           NSString **displayNameOut,
                                           NSString **replaceMsgOut,
                                           NSString **msgIDOut,
                                           NSString **newMsgIDOut) {
    if (wrap == 0) {
        return NO;
    }

    NSString *xml = YMFindRevokeXMLFromRawWrap((void *)wrap, 616);
    if (xml.length == 0 || !YMRevokeXMLMatchesSvrId(xml, expectedSvrId)) {
        return NO;
    }

    NSString *replaceMsg = YMExtractXMLTagValue(xml, @"replacemsg");
    NSString *displayName = YMDisplayNameFromRevokeReplaceMsg(replaceMsg);
    NSString *msgID = YMExtractXMLTagValue(xml, @"msgid");
    NSString *newMsgID = YMExtractXMLTagValue(xml, @"newmsgid");
    if (newMsgID.length == 0) {
        newMsgID = YMExtractXMLTagValue(xml, @"newsvrid");
    }

    NSString *revokerWxid = YMNSStringFromLibcppStringObject((const void *)(wrap + 72));
    if (revokerWxid.length == 0) {
        revokerWxid = YMRevokerWxidFromRevokeXMLPrefix(xml);
    }

    if (xmlOut) *xmlOut = xml ?: @"";
    if (revokerWxidOut) *revokerWxidOut = revokerWxid ?: @"";
    if (displayNameOut) *displayNameOut = displayName ?: @"";
    if (replaceMsgOut) *replaceMsgOut = replaceMsg ?: @"";
    if (msgIDOut) *msgIDOut = msgID ?: @"";
    if (newMsgIDOut) *newMsgIDOut = newMsgID ?: @"";
    return YES;
}

static BOOL YMFindRevokeContextAroundCallsite(uintptr_t originalSP,
                                              uintptr_t savedRegs,
                                              uint64_t expectedSvrId,
                                              uintptr_t *wrapOut,
                                              NSString **xmlOut,
                                              NSString **revokerWxidOut,
                                              NSString **displayNameOut,
                                              NSString **replaceMsgOut,
                                              NSString **msgIDOut,
                                              NSString **newMsgIDOut) {
    // 先扫被 stub 保存下来的寄存器。a2/revoke rawWrap 很可能还在某个 callee-saved 寄存器里。
    if (savedRegs != 0) {
        for (int reg = 0; reg <= 29; reg++) {
            uintptr_t candidate = 0;
            if (!YMSafeReadPointer(savedRegs + (uintptr_t)reg * sizeof(uintptr_t), &candidate)) {
                continue;
            }
            if (candidate == 0 || (candidate & 0x7) != 0) {
                continue;
            }

            if (YMExtractRevokeContextFromWrap(candidate,
                                               expectedSvrId,
                                               xmlOut,
                                               revokerWxidOut,
                                               displayNameOut,
                                               replaceMsgOut,
                                               msgIDOut,
                                               newMsgIDOut)) {
                if (wrapOut) *wrapOut = candidate;
                YMLog(@"[RevokeCallsite] revoke context found from saved x%d rawWrap=0x%lx", reg, (unsigned long)candidate);
                return YES;
            }
        }
    }

    // 再扫当前 sub_2B707E0 栈帧里的指针槽。
    if (originalSP != 0) {
        for (uintptr_t offset = 0; offset < 0x920; offset += sizeof(uintptr_t)) {
            uintptr_t candidate = 0;
            if (!YMSafeReadPointer(originalSP + offset, &candidate)) {
                continue;
            }
            if (candidate == 0 || (candidate & 0x7) != 0) {
                continue;
            }

            if (YMExtractRevokeContextFromWrap(candidate,
                                               expectedSvrId,
                                               xmlOut,
                                               revokerWxidOut,
                                               displayNameOut,
                                               replaceMsgOut,
                                               msgIDOut,
                                               newMsgIDOut)) {
                if (wrapOut) *wrapOut = candidate;
                YMLog(@"[RevokeCallsite] revoke context found from stack pointer slot +0x%lx rawWrap=0x%lx", (unsigned long)offset, (unsigned long)candidate);
                return YES;
            }
        }

        // 最后扫栈上是否有直接内嵌的 MessageWrap 副本。
        for (uintptr_t offset = 0; offset + 616 <= 0x920; offset += 8) {
            uintptr_t candidate = originalSP + offset;
            if (YMExtractRevokeContextFromWrap(candidate,
                                               expectedSvrId,
                                               xmlOut,
                                               revokerWxidOut,
                                               displayNameOut,
                                               replaceMsgOut,
                                               msgIDOut,
                                               newMsgIDOut)) {
                if (wrapOut) *wrapOut = candidate;
                YMLog(@"[RevokeCallsite] revoke context found from stack inline wrap +0x%lx rawWrap=0x%lx", (unsigned long)offset, (unsigned long)candidate);
                return YES;
            }
        }
    }

    return NO;
}

static BOOL YMInsertDetailedAntiRevokeNoticeFromOrigin(std::string *sessionString,
                                                       NSString *sessionText,
                                                       uint64_t svrId,
                                                       uint32_t originType,
                                                       NSString *originRawContent,
                                                       uint64_t originCreateTimeMs,
                                                       uint32_t originCreateTimeSec,
                                                       NSString *revokerWxid,
                                                       NSString *revokerDisplayName,
                                                       NSString *replaceMsg,
                                                       NSString *msgID,
                                                       NSString *newMsgID) {
    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();
    if (!profile || YMWeChatDylibSlide == 0 || !sessionString || sessionString->empty()) {
        YMLog(@"[RevokeCallsite] insert detailed notice failed: invalid profile/slide/session");
        return NO;
    }

    YMInsertPaySysMsgToSessionFunc InsertPaySysMsgToSession =
    (YMInsertPaySysMsgToSessionFunc)YMRuntimePointer(profile->insertPaySysMsgToSessionVA);

    if (!InsertPaySysMsgToSession) {
        YMLog(@"[RevokeCallsite] insert detailed notice failed: InsertPaySysMsgToSession is null");
        return NO;
    }

    NSString *sender = @"";
    NSString *cleanContent = @"";
    BOOL shouldShowContent = YMRevokeMessageTypeShouldShowContent(originType);

    if (shouldShowContent) {
        cleanContent = YMCleanOriginMessageContent(originRawContent, &sender);
        if (YMRevokeOriginTextLooksUseless(cleanContent)) {
            shouldShowContent = NO;
            cleanContent = @"";
            sender = @"";
        }
    }

    NSString *timeText = YMFormatTimestamp(originCreateTimeSec, originCreateTimeMs);

    NSMutableString *notice = [NSMutableString string];
    [notice appendString:@"⚠️苏维埃已拦截撤回消息⚠️\n"];
    [notice appendFormat:@"%@\n", YMRevokeMessageTypeName(originType)];

    if (shouldShowContent) {
        if (cleanContent.length > 0) {
            if (cleanContent.length > 1200) {
                cleanContent = [[cleanContent substringToIndex:1200] stringByAppendingString:@"…"];
            }
            [notice appendFormat:@"内容：%@\n", cleanContent];
        } else {
            [notice appendString:@"内容：（空）\n"];
        }
    }

    if (revokerDisplayName.length > 0 && revokerWxid.length > 0) {
        [notice appendFormat:@"%@（%@）\n", revokerDisplayName, revokerWxid];
    } else if (revokerDisplayName.length > 0) {
        [notice appendFormat:@"%@\n", revokerDisplayName];
    } else if (revokerWxid.length > 0) {
        [notice appendFormat:@"%@\n", revokerWxid];
    }
    
    if (timeText.length > 0) {
        [notice appendString:timeText];
    }

    std::string content = YMStdStringFromNSString(notice);

    YMLog(@"[RevokeCallsite] insert detailed notice session=%s content=%s",
          sessionString->c_str(),
          content.c_str());

    int64_t result = 0;
    try {
        result = InsertPaySysMsgToSession(0, sessionString, &content);
    } catch (...) {
        YMLog(@"[RevokeCallsite] exception while inserting detailed notice");
        return NO;
    }

    YMLog(@"[RevokeCallsite] insert detailed notice result=0x%llx", (unsigned long long)result);
    return YES;
}

extern "C" void YMRevokeOriginCallsiteHelper(uintptr_t originalSP, uintptr_t savedRegs) {
    @autoreleasepool {
        const size_t dstOffset = 0x18;
        const size_t extObjectSlotOffset = 0x2C0;

        uintptr_t outWrap = originalSP + dstOffset;
        uintptr_t extObject = 0;
        YMSafeReadPointer(originalSP + extObjectSlotOffset, &extObject);

        uint8_t hasValue = 0;
        YMSafeReadMemory(outWrap + 616, &hasValue, sizeof(hasValue));

        YMLog(@"[RevokeCallsite] after GetMessageBySvrId originalSP=0x%lx outWrap=0x%lx has=%u ext=0x%lx",
              (unsigned long)originalSP,
              (unsigned long)outWrap,
              (unsigned int)hasValue,
              (unsigned long)extObject);

        if (extObject == 0 || hasValue == 0) {
            return;
        }

        uint64_t svrId = 0;
        YMSafeReadMemory(extObject + 360, &svrId, sizeof(svrId));

        std::string *sessionString = (std::string *)(extObject + 392);
        NSString *sessionText = YMNSStringFromLibcppStringObject((const void *)(extObject + 392));

        uint32_t originType = 0;
        uint64_t originCreateTimeMs = 0;
        uint32_t originCreateTimeSec = 0;
        YMSafeReadMemory(outWrap + 264, &originType, sizeof(originType));
        YMSafeReadMemory(outWrap + 256, &originCreateTimeMs, sizeof(originCreateTimeMs));
        YMSafeReadMemory(outWrap + 276, &originCreateTimeSec, sizeof(originCreateTimeSec));

        NSString *originContent = YMNSStringFromLibcppStringObject((const void *)(outWrap + 304));
        NSString *originMsgSource = YMNSStringFromLibcppStringObject((const void *)(outWrap + 352));
        NSString *originContentLog = YMRevokeMessageTypeShouldShowContent(originType) ? YMRevokeShortLogText(originContent) : @"<非文本，不展开>";
        NSString *originMsgSourceLog = YMRevokeShortLogText(originMsgSource);

        YMLog(@"[RevokeCallsite] origin captured session=%@ svrId=%llu type=%@ content=%@ msgSource=%@",
              sessionText ?: @"",
              (unsigned long long)svrId,
              YMRevokeMessageTypeName(originType),
              originContentLog ?: @"",
              originMsgSourceLog ?: @"");

        NSString *revokeXML = @"";
        NSString *revokerWxid = @"";
        NSString *revokerDisplayName = @"";
        NSString *replaceMsg = @"";
        NSString *msgID = @"";
        NSString *newMsgID = @"";
        uintptr_t revokeWrap = 0;
        BOOL foundRevokeContext = YMFindRevokeContextAroundCallsite(originalSP,
                                                                    savedRegs,
                                                                    svrId,
                                                                    &revokeWrap,
                                                                    &revokeXML,
                                                                    &revokerWxid,
                                                                    &revokerDisplayName,
                                                                    &replaceMsg,
                                                                    &msgID,
                                                                    &newMsgID);

        YMLog(@"[RevokeCallsite] revoke context found=%d rawWrap=0x%lx revoker=%@ displayName=%@ replace=%@ msgid=%@ newmsgid=%@ xml=%@",
              foundRevokeContext ? 1 : 0,
              (unsigned long)revokeWrap,
              revokerWxid ?: @"",
              revokerDisplayName ?: @"",
              replaceMsg ?: @"",
              msgID ?: @"",
              newMsgID ?: @"",
              revokeXML ?: @"");

        if (YMRevokeLastNoticeSvrIdInCallsite != svrId) {
            YMRevokeLastNoticeSvrIdInCallsite = svrId;
            YMInsertDetailedAntiRevokeNoticeFromOrigin(sessionString,
                                                       sessionText,
                                                       svrId,
                                                       originType,
                                                       originContent,
                                                       originCreateTimeMs,
                                                       originCreateTimeSec,
                                                       revokerWxid,
                                                       revokerDisplayName,
                                                       replaceMsg,
                                                       msgID,
                                                       newMsgID.length > 0 ? newMsgID : [NSString stringWithFormat:@"%llu", (unsigned long long)svrId]);
        } else {
            YMLog(@"[RevokeCallsite] same svrId already inserted, skip duplicate notice. svrId=%llu",
                  (unsigned long long)svrId);
        }

        // 原消息已经拿到了，后面就别让微信拿这个 __dst 继续搞撤回 UI 了。
        // 先只清 flag，不析构这个栈上 MessageWrap。
        // 这是试水版本，目的是确认后面的撤回 UI 能不能被绕掉。
        *((volatile uint8_t *)(outWrap + 616)) = 0;
        YMLog(@"[RevokeCallsite] clear local origin optional flag to prevent current UI revoke replacement");
    }
}

#if defined(__aarch64__)
__asm__(
".text\n"
".align 2\n"
".globl _YMRevokeOriginCallsiteStub\n"
"_YMRevokeOriginCallsiteStub:\n"
"    sub sp, sp, #0x100\n"
"    stp x0,  x1,  [sp, #0x00]\n"
"    stp x2,  x3,  [sp, #0x10]\n"
"    stp x4,  x5,  [sp, #0x20]\n"
"    stp x6,  x7,  [sp, #0x30]\n"
"    stp x8,  x9,  [sp, #0x40]\n"
"    stp x10, x11, [sp, #0x50]\n"
"    stp x12, x13, [sp, #0x60]\n"
"    stp x14, x15, [sp, #0x70]\n"
"    stp x16, x17, [sp, #0x80]\n"
"    stp x18, x19, [sp, #0x90]\n"
"    stp x20, x21, [sp, #0xA0]\n"
"    stp x22, x23, [sp, #0xB0]\n"
"    stp x24, x25, [sp, #0xC0]\n"
"    stp x26, x27, [sp, #0xD0]\n"
"    stp x28, x29, [sp, #0xE0]\n"
"    str x30,      [sp, #0xF0]\n"
"    add x0, sp, #0x100\n"        // x0 = 原 sub_2B707E0 的 SP
"    mov x1, sp\n"               // x1 = 当前保存寄存器的区域，给 helper 扫描 raw revoke wrap
"    bl _YMRevokeOriginCallsiteHelper\n"
"    ldp x0,  x1,  [sp, #0x00]\n"
"    ldp x2,  x3,  [sp, #0x10]\n"
"    ldp x4,  x5,  [sp, #0x20]\n"
"    ldp x6,  x7,  [sp, #0x30]\n"
"    ldp x8,  x9,  [sp, #0x40]\n"
"    ldp x10, x11, [sp, #0x50]\n"
"    ldp x12, x13, [sp, #0x60]\n"
"    ldp x14, x15, [sp, #0x70]\n"
"    ldp x16, x17, [sp, #0x80]\n"
"    ldp x18, x19, [sp, #0x90]\n"
"    ldp x20, x21, [sp, #0xA0]\n"
"    ldp x22, x23, [sp, #0xB0]\n"
"    ldp x24, x25, [sp, #0xC0]\n"
"    ldp x26, x27, [sp, #0xD0]\n"
"    ldp x28, x29, [sp, #0xE0]\n"
"    ldr x30,      [sp, #0xF0]\n"
"    add sp, sp, #0x100\n"

// 还原 0x2B71244 ~ 0x2B71250 被覆盖的 4 条指令：
//   LDR X22, [SP,#0x2D8]
//   CBZ X22, 0x2B71274
//   ADD X8, X22, #8
//   MOV X9, #-1
"    ldr x22, [sp, #0x2D8]\n"
"    cbz x22, L_YMRevokeCallsiteZero\n"
"    add x8, x22, #8\n"
"    mov x9, #-1\n"
"    adrp x16, _YMRevokeOriginCallsiteContinueAddress@PAGE\n"
"    ldr  x16, [x16, _YMRevokeOriginCallsiteContinueAddress@PAGEOFF]\n"
"    br x16\n"
"L_YMRevokeCallsiteZero:\n"
"    adrp x16, _YMRevokeOriginCallsiteZeroBranchAddress@PAGE\n"
"    ldr  x16, [x16, _YMRevokeOriginCallsiteZeroBranchAddress@PAGEOFF]\n"
"    br x16\n"
);
#elif defined(__x86_64__)
/*
 Phase 2 占位：x86_64 上的 inline callsite hook（保存/还原被覆盖指令 + 跳板）
 需要按 x86_64 反汇编重新设计，这套 arm64 寄存器保存/分支续跑逻辑不适用。
 目前 x86_64 profile 的 callsite VA 均为 0，YMPatchRevokeLocalCallsiteOnly 会提前
 返回，运行期永远不会跳到这里；这里只提供一个占位符号让链接通过。
 */
extern "C" void YMRevokeOriginCallsiteStub(void) {}
#endif

#pragma mark - 撤回 DeleteMessages Guard

typedef int64_t (*YMDeleteMessagesFunc)(int64_t manager, std::string *session, int64_t *messageVector, int flag);

static BOOL YMRevokeRestoreOriginalDeleteMessages(void) {
    if (!YMRevokeDeleteMessagesRuntimeAddress || !YMRevokeDeleteMessagesHasSavedOriginalBytes) {
        return NO;
    }
    return YMGroupExitWriteCodeBytes(YMRevokeDeleteMessagesRuntimeAddress,
                                     YMRevokeDeleteMessagesOriginalBytes,
                                     sizeof(YMRevokeDeleteMessagesOriginalBytes),
                                     "revoke DeleteMessages",
                                     "restore original");
}

static BOOL YMRevokeReapplyDeleteMessagesHook(void) {
    if (!YMRevokeDeleteMessagesRuntimeAddress) {
        return NO;
    }
    return YMGroupExitWriteCodeBytes(YMRevokeDeleteMessagesRuntimeAddress,
                                     YMRevokeDeleteMessagesHookBytes,
                                     sizeof(YMRevokeDeleteMessagesHookBytes),
                                     "revoke DeleteMessages",
                                     "reapply hook");
}

static int64_t YMRevokeCallOriginalDeleteMessages(int64_t manager, std::string *session, int64_t *messageVector, int flag) {
    if (!YMRevokeDeleteMessagesRuntimeAddress) {
        return 0;
    }

    if (YMRevokeDeleteMessagesCallingOriginal.exchange(true)) {
        YMLog(@"[RevokeCallsite] recursive DeleteMessages original call suppressed");
        return 0;
    }

    BOOL restored = YMRevokeRestoreOriginalDeleteMessages();
    if (!restored) {
        YMLog(@"[RevokeCallsite] restore original DeleteMessages failed");
        YMRevokeDeleteMessagesCallingOriginal.store(false);
        return 0;
    }

    YMDeleteMessagesFunc Original = (YMDeleteMessagesFunc)YMRevokeDeleteMessagesRuntimeAddress;
    int64_t result = 0;
    try {
        result = Original(manager, session, messageVector, flag);
    } catch (...) {
        YMLog(@"[RevokeCallsite] exception while calling original DeleteMessages");
    }

    YMRevokeReapplyDeleteMessagesHook();
    YMRevokeDeleteMessagesCallingOriginal.store(false);
    return result;
}

static int64_t YMRevokeDeleteMessagesHook(int64_t manager, std::string *session, int64_t *messageVector, int flag) {
    @autoreleasepool {
        NSString *sessionText = YMNSStringFromLibcppStringObject(session);

        uint64_t count = 0;
        if (messageVector) {
            uint64_t begin = (uint64_t)messageVector[0];
            uint64_t end = (uint64_t)messageVector[1];
            if (end >= begin && begin != 0) {
                count = (end - begin) / 616;
            }
        }

        if (YMRevokeDeleteGuardActive) {
            YMLog(@"[RevokeCallsite] skip DeleteMessages inside revoke manager=0x%llx session=%@ count=%llu flag=%d targetSvrId=%llu",
                  (unsigned long long)manager,
                  sessionText ?: @"",
                  (unsigned long long)count,
                  flag,
                  (unsigned long long)YMRevokeTargetSvrIdForDeleteGuard);

            YMRevokeDeleteGuardActive = NO;
            YMRevokeTargetSvrIdForDeleteGuard = 0;
            YMRevokeLastNoticeSvrIdInCallsite = 0;

            // 伪装删除成功，避免上层重试或卡同步。
            return 1;
        }

        return YMRevokeCallOriginalDeleteMessages(manager, session, messageVector, flag);
    }
}

static BOOL YMPatchRevokeLocalCallsiteOnly(uintptr_t slide, NSString *source) {
    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();
    if (!profile) {
        YMLog(@"[RevokeCallsite] install failed: no active profile");
        return NO;
    }

    if (profile->revokeOriginCallsiteAfterQueryVA == 0 ||
        profile->revokeOriginCallsiteContinueVA == 0 ||
        profile->revokeOriginCallsiteZeroBranchVA == 0) {
        YMLog(@"[RevokeCallsite] install failed: profile has no revoke callsite address, profile=%s",
              profile->displayName);
        return NO;
    }

    uintptr_t callsite = slide + profile->revokeOriginCallsiteAfterQueryVA;

    YMRevokeOriginCallsiteContinueAddress = slide + profile->revokeOriginCallsiteContinueVA;
    YMRevokeOriginCallsiteZeroBranchAddress = slide + profile->revokeOriginCallsiteZeroBranchVA;

    YMLog(@"[RevokeCallsite] install local callsite only source=%@ profile=%s callsite=0x%lx continue=0x%lx zero=0x%lx delete=0x%lx",
          source ?: @"",
          profile->displayName,
          (unsigned long)callsite,
          (unsigned long)YMRevokeOriginCallsiteContinueAddress,
          (unsigned long)YMRevokeOriginCallsiteZeroBranchAddress,
          (unsigned long)(profile->revokeDeleteMessagesVA ? slide + profile->revokeDeleteMessagesVA : 0));

    BOOL okCallsite = YMPatchFunctionEntryAbsoluteJump(callsite,
                                               (uintptr_t)&YMRevokeOriginCallsiteStub,
                                               "revoke origin local callsite after GetMessageBySvrId");

    YMLog(@"[RevokeCallsite] install result callsite=%@",
          okCallsite ? @"OK" : @"FAIL");

    return okCallsite;
}

#pragma mark - 撤回入口 Hook

/*
 这个函数会被 off_91EAD20 热补丁指针调用。

 原函数签名：
   int64_t ym_HandleSysMsg_RevokeMsg(int64_t a1, int64_t a2)

 做两件事：
   1. 自己插入一条本地 type=10000 系统消息
   2. return 1，告诉上层这个 sysmsg 已经处理，阻止微信原始撤回逻辑继续执行
 */
static int64_t YMHandleSysMsgRevokeMsgHook(int64_t a1, int64_t a2) {
    YMLog(@"intercepted revoke message, a1=0x%llx, a2=0x%llx",
          (unsigned long long)a1,
          (unsigned long long)a2);

    BOOL inserted = YMInsertLocalAntiRevokeNotice(a2);

    YMLog(@"insert local anti revoke notice result=%d", inserted ? 1 : 0);

    return 1;
}

#pragma mark - 防撤回 BlockEntry+Notice detour handler（x86_64 使用，两架构都编译以便链接）

/*
 0x2bd6250 入口的 detour 目标。通过 16 字节绝对跳转(jmp)进入，未压新返回地址，
 故栈顶仍是原调用者返回地址；本函数 return 即返回上层 sync 层。
   - 入口寄存器：rdi=arg0(管理器), rsi=arg1=rawRevokeMsg(messageWrapFromRaw 的源)。
   - 先插一条本地灰条提示（复用 arch-independent 的 YMInsertLocalAntiRevokeNotice），
     再返回 1（"已处理"），不调用原函数 → 撤回被阻断、原消息保留、显示提示。
 thread-local 重入保护，避免极端情况下递归。
*/
static int64_t YMRevokeBlockNoticeHandler(int64_t a0, int64_t a1, int64_t a2,
                                          int64_t a3, int64_t a4, int64_t a5) {
    static __thread int inHandler = 0;
    if (!inHandler) {
        inHandler = 1;
        @autoreleasepool {
            try {
                YMInsertLocalAntiRevokeNotice(a1);
            } catch (...) {
                YMLog(@"[BlockNotice] exception while inserting local notice");
            }
        }
        inHandler = 0;
    }
    return 1; // 告诉 sync 层撤回已处理，且不调用原函数 → 阻断
}

#pragma mark - 防撤回 x86 callsite 捕获（ARM 同机制：拦原消息查询，不动 DB）

/*
 思路（对应 ARM 的 callsite hook，但用更安全的"换 call 目标"实现）：
 x86 CoReplaceOriginMessageByRevoke(0x2f93440) 里查原消息：
   0x2f93e95 mov rdx,[rbp-0x660]         ; rdx = extObject(ctx)，svrId@+0x168 session@+0x188
   0x2f93e9c mov rcx,[rdx+0x168]         ; rcx = svrId
   0x2f93ea3 add rdx,0x188              ; rdx = ctx+0x188(session 串地址)
   0x2f93eaa lea rdi,[rbp-0x910]         ; rdi = outWrap(被填充的原消息 wrap)
   0x2f93eb1 call 0x2ba12c0              ; 查到原消息，填入 outWrap
 把这条 call 的目标(rel32)改成下面的 wrapper：先调真正的查询拿到原消息，
 再从 outWrap/extObject 捕获 content/type/time/session(偏移与 arm64 一致)，
 插入带原文的详细灰条，最后把 outWrap+616 的"替换标志"清 0 阻止 UI 替换。
 整条 callsite 唯一，天然只在撤回时触发；不需要寄存器保存跳板。
*/
static uintptr_t YMRevokeX86RealLookupAddr = 0;
typedef int64_t (*YMRevokeX86LookupFunc)(int64_t,int64_t,int64_t,int64_t,int64_t,int64_t);

static void YMRevokeX86CaptureFromCoReplace(uintptr_t outWrap, uintptr_t extObject, uint64_t svrId) {
    if (outWrap == 0 || extObject == 0) {
        return;
    }

    // 原消息是否有效：outWrap+616 == 1 表示这次确实替换了原消息。
    uint8_t hasValue = 0;
    YMSafeReadMemory(outWrap + 616, &hasValue, sizeof(hasValue));
    if (hasValue == 0) {
        return;
    }

    uint32_t originType = 0;
    uint64_t originCreateTimeMs = 0;
    uint32_t originCreateTimeSec = 0;
    YMSafeReadMemory(outWrap + 264, &originType, sizeof(originType));
    YMSafeReadMemory(outWrap + 256, &originCreateTimeMs, sizeof(originCreateTimeMs));
    YMSafeReadMemory(outWrap + 276, &originCreateTimeSec, sizeof(originCreateTimeSec));

    // 用 ->c_str() 路径(YMNSStringFromStdString)读，YMNSStringFromLibcppStringObject 在
    // x86 上对这些 std::string 解析为空(实测 session 用 c_str 能拿到 wxid，用它则空)。
    NSString *originContent = YMNSStringFromStdString((std::string *)(outWrap + 304));
    std::string *sessionString = (std::string *)(extObject + 392);
    NSString *sessionText = YMNSStringFromStdString(sessionString);

    YMLog(@"[X86Callsite] origin captured svrId=%llu type=%u session=%@ contentLen=%lu",
          (unsigned long long)svrId, (unsigned int)originType,
          sessionText ?: @"", (unsigned long)originContent.length);

    // 撤回人：1v1 时即会话对方(sessionText)。后续可从撤回上下文补 replacemsg 昵称。
    YMInsertDetailedAntiRevokeNoticeFromOrigin(sessionString,
                                               sessionText,
                                               svrId,
                                               originType,
                                               originContent,
                                               originCreateTimeMs,
                                               originCreateTimeSec,
                                               sessionText,   // revokerWxid（1v1 近似）
                                               @"",            // revokerDisplayName
                                               @"",            // replaceMsg
                                               @"",            // msgID
                                               @"");           // newMsgID

    // 关键：清掉"替换原消息"的标志，阻止后续 UI 把原消息替换成撤回提示。
    // outWrap 已校验非空且 hasValue 读取成功，是合法可写内存，直接写。
    *((volatile uint8_t *)(outWrap + 616)) = 0;
}

// 换 call 目标后的 wrapper：rdi=outWrap, rdx=extObject+0x188, rcx=svrId。
static int64_t YMRevokeX86LookupWrapper(int64_t a0, int64_t a1, int64_t a2,
                                        int64_t a3, int64_t a4, int64_t a5) {
    int64_t result = 0;
    if (YMRevokeX86RealLookupAddr) {
        result = ((YMRevokeX86LookupFunc)YMRevokeX86RealLookupAddr)(a0, a1, a2, a3, a4, a5);
    }
    static __thread int inWrapper = 0;
    if (!inWrapper) {
        inWrapper = 1;
        @autoreleasepool {
            try {
                YMRevokeX86CaptureFromCoReplace((uintptr_t)a0,
                                                (uintptr_t)a2 - 0x188,
                                                (uint64_t)a3);
            } catch (...) {
                YMLog(@"[X86Callsite] capture exception");
            }
        }
        inWrapper = 0;
    }
    return result;
}

// 把 0x2f93eb1 处 `E8 rel32` 的目标改成 wrapper；rel32 必须 32 位可达。
static BOOL YMPatchRevokeX86Callsite(uintptr_t slide, uintptr_t callSiteVA) {
    if (callSiteVA == 0) {
        return NO;
    }
    uintptr_t callAddr = slide + callSiteVA;

    uint8_t opcode = 0;
    YMSafeReadMemory(callAddr, &opcode, 1);
    if (opcode != 0xE8) {
        YMLog(@"[X86Callsite] install failed: not a call(E8) at 0x%lx, op=0x%02x",
              (unsigned long)callAddr, opcode);
        return NO;
    }

    int32_t oldRel = 0;
    YMSafeReadMemory(callAddr + 1, &oldRel, sizeof(oldRel));
    YMRevokeX86RealLookupAddr = callAddr + 5 + (intptr_t)oldRel;

    intptr_t newRel = (intptr_t)&YMRevokeX86LookupWrapper - (intptr_t)(callAddr + 5);
    if (newRel > INT32_MAX || newRel < INT32_MIN) {
        YMLog(@"[X86Callsite] install failed: wrapper out of rel32 range (newRel=0x%lx)", (unsigned long)newRel);
        YMRevokeX86RealLookupAddr = 0;
        return NO;
    }
    int32_t rel32 = (int32_t)newRel;

    YMLog(@"[X86Callsite] callAddr=0x%lx realLookup=0x%lx wrapper=0x%lx rel32=0x%x",
          (unsigned long)callAddr, (unsigned long)YMRevokeX86RealLookupAddr,
          (unsigned long)&YMRevokeX86LookupWrapper, rel32);

    if (!YMGroupExitWriteCodeBytes(callAddr + 1, (const uint8_t *)&rel32, sizeof(rel32),
                                   "x86 revoke callsite", "patch call rel32")) {
        YMRevokeX86RealLookupAddr = 0;
        return NO;
    }
    return YES;
}

#pragma mark - 安装 Patch

static BOOL YMPatchAntiRevokeWithSlide(intptr_t slide, NSString *source) {
    if (YMHasPatchedAntiRevoke) {
        YMLog(@"already installed, skip. source=%@", source);
        return YES;
    }

    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();
    if (!profile) {
        YMLog(@"no active profile, skip patch");
        return NO;
    }

    YMWeChatDylibSlide = (uintptr_t)slide;

    uintptr_t pointerAddress = YMRuntimeAddress(profile->hookPointerVA);
    uintptr_t hookAddress = (uintptr_t)&YMHandleSysMsgRevokeMsgHook;

    YMLog(@"try install revoke hook from %@, profile=%s, slide=0x%lx, pointer=0x%lx, hook=0x%lx",
          source,
          profile->displayName,
          (unsigned long)YMWeChatDylibSlide,
          (unsigned long)pointerAddress,
          (unsigned long)hookAddress);

    /*
     这里不再 patch 0x27A03A0 代码段。
     而是写微信自己预留/编译出来的函数指针 off_91EAD20。

     好处：
       1. 能拿到 a1/a2 参数
       2. 可以在 hook 里自己插入提示消息
       3. 不需要改 __TEXT 指令
    */
//    BOOL ok = YMWritePointer(pointerAddress,
//                             hookAddress,
//                             0,
//                             "revoke hook pointer -> YMHandleSysMsgRevokeMsgHook");
    
    BOOL ok = NO;

    if (profile->hookMode == YMRevokeHookModePointer) {
        /*
         4.1.9：
         写微信自己预留的 off_91EAD20 函数指针。
         */
        ok = YMWritePointer(pointerAddress,
                            hookAddress,
                            0,
                            "revoke hook pointer -> YMHandleSysMsgRevokeMsgHook");
    } else if (profile->hookMode == YMRevokeHookModeInline) {
        /*
         4.1.10：
         先不拦入口了，入口一 return 就拿不到原消息。
         这里只 patch sub_2B707E0 里查完原消息后的那个点。
         拿到内容后把 __dst flag 清掉，让后面别再撤 UI。
         */
        ok = YMPatchRevokeLocalCallsiteOnly((uintptr_t)slide, source ?: @"anti revoke install");
    } else if (profile->hookMode == YMRevokeHookModeBlockEntry) {
        /*
         x86_64（运行时 instrument-and-observe 确认的真实撤回链顶层 wrapper）：
         hookPointerVA = 0x2bd6250 —— 入站撤回 handler 外层，仅 1 个调用者，正常
         返回 bool=1（"已处理"）。把入口直接 patch 成 `mov eax,1; ret`(return YES)：
         上层 sync 认为撤回已处理（不重试/不脱同步），但模板构建/CoReplace(0x2f93440)
         /下游删除全部不执行 → 原消息保留 = 防撤回。
         代价：不显示撤回人昵称/原文富提示。注意必须 returnYES 而非 return0，
         否则上层可能视作未处理而走别的撤回路径或重试。
         */
        ok = YMPatchFunctionReturnYES(pointerAddress,
                                      "anti revoke block entry -> return YES");
    } else if (profile->hookMode == YMRevokeHookModeBlockEntryNotice) {
        /*
         x86_64：在 0x2bd6250 入口 detour 到 YMRevokeBlockNoticeHandler。
         handler 先用 arg1(=rawRevokeMsg) 调 YMInsertLocalAntiRevokeNotice 插一条
         本地灰条提示（"已拦截撤回"），再 return 1（"已处理"）且不调用原函数 →
         原消息保留 + 显示提示。notice 失败也不影响阻断。
         */
        ok = YMPatchFunctionEntryAbsoluteJump(pointerAddress,
                                              (uintptr_t)&YMRevokeBlockNoticeHandler,
                                              "anti revoke block+notice");
    } else if (profile->hookMode == YMRevokeHookModeX86Callsite) {
        /*
         x86_64：换 CoReplace 里查原消息那条 call 的目标 → wrapper 捕获原文+清替换标志。
         hookPointerVA 存的是那条 call 指令的 VA(0x2f93eb1)。
        */
        ok = YMPatchRevokeX86Callsite((uintptr_t)slide, profile->hookPointerVA);
    } else {
        YMLog(@"unknown revoke hook mode: %d", profile->hookMode);
        ok = NO;
    }

    if (ok) {
        YMHasPatchedAntiRevoke = YES;
    }

    return ok;
}

#pragma mark - dyld 查找 wechat.dylib

static BOOL YMIsTargetWeChatResourceDylibPath(NSString *imagePath) {
    if (imagePath.length == 0) {
        return NO;
    }

    BOOL isTarget =
    [imagePath hasSuffix:@"/Contents/Resources/wechat.dylib"] ||
    ([imagePath containsString:@"/Contents/Resources/"] &&
     [[imagePath lastPathComponent] isEqualToString:@"wechat.dylib"]);

    return isTarget;
}

static BOOL YMFindAndPatchLoadedWeChatResourceDylib(void) {
    uint32_t count = _dyld_image_count();

    YMLog(@"scan dyld images, count=%u", count);

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) {
            continue;
        }

        NSString *imagePath = [NSString stringWithUTF8String:name];

        if (!YMIsTargetWeChatResourceDylibPath(imagePath)) {
            continue;
        }

        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        YMLog(@"found loaded Resources/wechat.dylib: index=%u, slide=0x%lx, path=%@",
              i,
              (unsigned long)slide,
              imagePath);

        return YMPatchAntiRevokeWithSlide(slide, @"dyld image scan");
    }

    YMLog(@"Resources/wechat.dylib not found in dyld image list");
    return NO;
}

static void YMInstallAntiRevokePatch(void) {
    if (YMHasPatchedAntiRevoke) {
        return;
    }

    if (!YMIsTargetWeChatVersion()) {
        return;
    }

    YMFindAndPatchLoadedWeChatResourceDylib();
}

#pragma mark - 多开 Patch

static BOOL YMPatchMultiOpenWithWeChatDylibSlide(intptr_t slide, NSString *source) {
    if (YMHasPatchedMultiOpenResourceDylib) {
        YMLog(@"multi open already patched, skip. source=%@", source);
        return YES;
    }

    /*
     这里仍然复用匹配逻辑。
     避免地址漂移后误 patch 新版本。
     */
    if (!YMIsTargetWeChatVersion()) {
        YMLog(@"multi open unsupported version, skip. source=%@", source);
        return NO;
    }

    YMWeChatDylibSlide = (uintptr_t)slide;

    uintptr_t tryPreventAddress = YMRuntimeAddress(YMActiveProfile->YMMultiOpenTryPreventMultiInstanceVA);
    uintptr_t processCountAddress = YMRuntimeAddress(YMActiveProfile->YMGetMainWeixinProcessCountVA);

    YMLog(@"try install multi open patch from %@, profile=%s, slide=0x%lx, tryPrevent=0x%lx, processCount=0x%lx",
          source,
          YMActiveProfile->displayName,
          (unsigned long)YMWeChatDylibSlide,
          (unsigned long)tryPreventAddress,
          (unsigned long)processCountAddress);

    /*
     多开需要尽量同时绕过两层：
       1. TryPreventMultiInstance：启动早期防多开逻辑。
       2. GetMainWeixinProcessCount：通过 NSRunningApplication 统计同 BundleID 进程数量。
          4.1.10 如果不 patch 这个函数，第二个微信实例会检测到已有进程，
          很容易进入反复授权 / 防多开流程。
     */
    BOOL patchedAny = NO;
    BOOL finalOK = YES;

    if (tryPreventAddress != 0) {
        BOOL okTryPrevent = YMPatchFunctionReturnYES(
            tryPreventAddress,
            "multi open: TryPreventMultiInstance -> return 1"
        );

        patchedAny = YES;
        finalOK = finalOK && okTryPrevent;

        YMLog(@"multi open TryPreventMultiInstance patch=%@",
              okTryPrevent ? @"OK" : @"FAIL");
    } else {
        YMLog(@"multi open TryPreventMultiInstance address is zero, skip");
    }

    if (processCountAddress != 0) {
        BOOL okProcessCount = YMPatchFunctionReturnYES(
            processCountAddress,
            "multi open: GetMainWeixinProcessCount -> return 1"
        );

        patchedAny = YES;
        finalOK = finalOK && okProcessCount;

        YMLog(@"multi open GetMainWeixinProcessCount patch=%@",
              okProcessCount ? @"OK" : @"FAIL");
    } else {
        YMLog(@"multi open GetMainWeixinProcessCount address is zero, skip");
    }

    YMHasPatchedMultiOpenResourceDylib = patchedAny && finalOK;

    YMLog(@"multi open patch summary: patchedAny=%@, final=%@",
          patchedAny ? @"YES" : @"NO",
          YMHasPatchedMultiOpenResourceDylib ? @"OK" : @"FAIL");

    return YMHasPatchedMultiOpenResourceDylib;
}

static BOOL YMFindAndPatchLoadedMultiOpenWeChatDylib(void) {
    uint32_t count = _dyld_image_count();

    YMLog(@"scan dyld images for multi open, count=%u", count);

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) {
            continue;
        }

        NSString *imagePath = [NSString stringWithUTF8String:name];

        if (!YMIsTargetWeChatResourceDylibPath(imagePath)) {
            continue;
        }

        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        YMLog(@"found Resources/wechat.dylib for multi open: index=%u, slide=0x%lx, path=%@",
              i,
              (unsigned long)slide,
              imagePath);

        return YMPatchMultiOpenWithWeChatDylibSlide(slide, @"dyld image scan");
    }

    YMLog(@"Resources/wechat.dylib not found for multi open");
    return NO;
}

static void YMInstallMultiOpenPatch(void) {
    if (YMHasPatchedMultiOpenResourceDylib) {
        return;
    }

    /*
     防多开发生在启动早期，所以这里不能 dispatch_after。
     constructor 进来后立刻：
       1. 注册 dyld callback
       2. 扫描已经加载的 wechat.dylib
     */
    YMRegisterDyldCallbackIfNeeded();
    YMFindAndPatchLoadedMultiOpenWeChatDylib();
}

static void YMDyldImageAdded(const struct mach_header *mh, intptr_t vmaddr_slide) {
    const char *name = NULL;

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if (_dyld_get_image_header(i) == mh) {
            name = _dyld_get_image_name(i);
            break;
        }
    }

    if (!name) {
        return;
    }

    NSString *imagePath = [NSString stringWithUTF8String:name];

    if (!YMIsTargetWeChatResourceDylibPath(imagePath)) {
        return;
    }

    YMLog(@"dyld added target Resources/wechat.dylib: %@, callback slide=0x%lx",
          imagePath,
          (unsigned long)vmaddr_slide);

    /*
     多开必须尽早 patch。
     所以只要 wechat.dylib 被 dyld 加载，就马上 patch sub_1C0A64 / sub_4396B00。
     */
    YMPatchMultiOpenWithWeChatDylibSlide(vmaddr_slide, @"dyld add image callback");

    /*
     群员退群监控受 kExitChatroom 控制。
     注意：dyld callback 是多开/防撤回共用的，不能在这里无条件安装退群 hook。
     */
    if (YMIsGroupExitMonitorEnabled()) {
        YMPatchGroupExitMonitorWithSlide(vmaddr_slide, @"dyld add image callback");
    } else {
        YMLog(@"[GroupExitMonitor] disabled by user defaults, skip dyld callback patch");
        YMGroupExitClearRuntimeStateIfDisabled("dyld add image callback");
    }

    /*
     防撤回仍然受用户开关控制。
     */
    if ([[NSUserDefaults standardUserDefaults] boolForKey:kAntiRevoke]) {
        YMPatchAntiRevokeWithSlide(vmaddr_slide, @"dyld add image callback");
    }
}

static void YMRegisterDyldCallbackIfNeeded(void) {
    if (YMHasRegisteredDyldCallback) {
        return;
    }

    YMHasRegisteredDyldCallback = YES;

    YMLog(@"register dyld add image callback");
    _dyld_register_func_for_add_image(YMDyldImageAdded);
}

#pragma mark - 功能安装

static void YMInstallAssistantMenu(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [[MenuManager shareInstance] initAssistantMenuItems];
    });
}

static void YMInstallAntiUpdateIfNeeded(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        NSString *loadFlag = [[NSUserDefaults standardUserDefaults] objectForKey:kIsFirstLoad];
        if (loadFlag.length < 3) {
            [[NSUserDefaults standardUserDefaults] setBool:YES forKey:kAntiUpdate];
            [[NSUserDefaults standardUserDefaults] setObject:@"SOVIET" forKey:kIsFirstLoad];
        }

        if ([[NSUserDefaults standardUserDefaults] boolForKey:kAntiUpdate]) {
            YMDisableSparkleAutoUpdateDefaults();
            YMDisableSparkleByRuntimeHook();
        }
    });
}

static void YMInstallAntiRevokeIfNeeded(void) {
    if (![[NSUserDefaults standardUserDefaults] boolForKey:kAntiRevoke]) {
        YMLog(@"anti revoke disabled by user defaults, skip");
        return;
    }

    /*
     先注册 dyld 回调。
     如果 wechat.dylib 在之后加载，可以第一时间拿到 slide。
    */
    YMRegisterDyldCallbackIfNeeded();

    /*
     再主动扫描一次。
     如果 wechat.dylib 在之前已经加载，可以直接安装 hook。
    */
    YMInstallAntiRevokePatch();

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        YMInstallAntiRevokePatch();
    });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        YMInstallAntiRevokePatch();
    });
}


#pragma mark - 撤回路径诊断（x86_64 instrument-and-observe）
/*
 纯静态分析已证伪 "block 整个 0x2b93f40/0x2b94050 能阻止撤回"，真正的
 "删除原消息 + 显示撤回" 路径未知。这里用运行时插桩：对一组撤回相关候选
 函数做透传 hook（还原-调用-重挂），每次进入时打印 调用者 + backtrace，
 让用户触发一次真实撤回后，从日志回溯出真正的处理链。x86_64 专用。
*/
#if defined(__x86_64__)

typedef int64_t (*YMDiagOrigFunc)(int64_t,int64_t,int64_t,int64_t,int64_t,int64_t);

typedef struct {
    const char *name;
    uintptr_t   staticVA;
    uintptr_t   runtimeAddr;
    uint8_t     origBytes[16];
    uint8_t     hookBytes[16];
    BOOL        saved;
} YMDiagEntry;

static YMDiagEntry gYMDiagTable[] = {
    // 兜底锚点：撤回必然要按 svrid 找到原消息。它的 backtrace 直接暴露真正的 handler。
    { "GetMsgBySvrId_2a176b0", 0x2a176b0, 0, {0}, {0}, NO },
    // 未测过的 svrid-caller 函数（上一轮 7 个已证伪，全部换新）。
    { "f_2a172f0", 0x2a172f0, 0, {0}, {0}, NO },
    { "f_2a726d0", 0x2a726d0, 0, {0}, {0}, NO },
    { "f_2abba80", 0x2abba80, 0, {0}, {0}, NO },
    { "f_2abde80", 0x2abde80, 0, {0}, {0}, NO },
    { "f_2af1510", 0x2af1510, 0, {0}, {0}, NO },
    { "f_2b081d0", 0x2b081d0, 0, {0}, {0}, NO },
    { "f_2b115b0", 0x2b115b0, 0, {0}, {0}, NO },
    { "f_2b29cb0", 0x2b29cb0, 0, {0}, {0}, NO },
    { "f_2b2e770", 0x2b2e770, 0, {0}, {0}, NO },
    { "f_2b39580", 0x2b39580, 0, {0}, {0}, NO },
    { "f_2bb5580", 0x2bb5580, 0, {0}, {0}, NO },
    { "f_2bc9800", 0x2bc9800, 0, {0}, {0}, NO },
    { "f_2bd7b10", 0x2bd7b10, 0, {0}, {0}, NO },
    { "f_2be05b0", 0x2be05b0, 0, {0}, {0}, NO },
    { "f_2beb800", 0x2beb800, 0, {0}, {0}, NO },
    { "f_2ce32f0", 0x2ce32f0, 0, {0}, {0}, NO },
    { "f_2d1f2b0", 0x2d1f2b0, 0, {0}, {0}, NO },
};
#define YM_DIAG_COUNT ((int)(sizeof(gYMDiagTable)/sizeof(gYMDiagTable[0])))

// wechat dylib __text 静态 VA 范围，用于过滤 backtrace 里属于微信本体的帧。
static const uintptr_t kYMTextLo = 0x15000;
static const uintptr_t kYMTextHi = 0x6d9c780;

static std::atomic_int gYMDiagSeq(0);
static __thread int gYMDiagInHook = 0;

static int64_t YMDiagCommon(int idx,
                            int64_t a1,int64_t a2,int64_t a3,
                            int64_t a4,int64_t a5,int64_t a6,
                            void *caller) {
    if (idx < 0 || idx >= YM_DIAG_COUNT) return 0;
    YMDiagEntry *e = &gYMDiagTable[idx];
    if (!e->runtimeAddr) return 0;

    if (!gYMDiagInHook) {
        gYMDiagInHook = 1;
        @autoreleasepool {
            int seq = gYMDiagSeq.fetch_add(1);
            uintptr_t slide = YMWeChatDylibSlide;
            uintptr_t callerVA = (uintptr_t)caller - slide;

            void *bt[20];
            int n = backtrace(bt, 20);
            NSMutableString *chain = [NSMutableString string];
            BOOL first = YES;
            for (int i = 1; i < n; i++) {
                uintptr_t rel = (uintptr_t)bt[i] - slide;
                if (rel < kYMTextLo || rel > kYMTextHi) continue; // 只留微信本体帧
                [chain appendFormat:@"%@0x%lx", (first ? @"" : @" <- "), (unsigned long)rel];
                first = NO;
            }
            YMLog(@"[Diag#%d] %s a1=0x%llx a2=0x%llx a3=0x%llx a4=0x%llx caller=0x%lx | bt: %@",
                  seq, e->name,
                  (unsigned long long)a1,(unsigned long long)a2,
                  (unsigned long long)a3,(unsigned long long)a4,
                  (unsigned long)callerVA, chain);
        }
        gYMDiagInHook = 0;
    }

    // 透传：还原原始 16 字节 -> 调原函数 -> 重新挂钩。
    YMGroupExitWriteCodeBytes(e->runtimeAddr, e->origBytes, 16, e->name, "diag restore");
    YMDiagOrigFunc orig = (YMDiagOrigFunc)e->runtimeAddr;
    int64_t result = 0;
    try {
        result = orig(a1,a2,a3,a4,a5,a6);
    } catch (...) {
        YMLog(@"[Diag] exception while calling original %s", e->name);
    }
    YMGroupExitWriteCodeBytes(e->runtimeAddr, e->hookBytes, 16, e->name, "diag rehook");
    return result;
}

// 每个候选一个独立 thunk：知道自己的 index，并用 __builtin_return_address(0)
// 取到真实调用者（因为入口是 jmp 跳板，未压新返回地址，栈顶仍是原调用者）。
#define YM_DIAG_THUNK(I) \
static int64_t YMDiagThunk_##I(int64_t a1,int64_t a2,int64_t a3,int64_t a4,int64_t a5,int64_t a6){ \
    return YMDiagCommon(I,a1,a2,a3,a4,a5,a6,__builtin_return_address(0)); }
YM_DIAG_THUNK(0)  YM_DIAG_THUNK(1)  YM_DIAG_THUNK(2)  YM_DIAG_THUNK(3)
YM_DIAG_THUNK(4)  YM_DIAG_THUNK(5)  YM_DIAG_THUNK(6)  YM_DIAG_THUNK(7)
YM_DIAG_THUNK(8)  YM_DIAG_THUNK(9)  YM_DIAG_THUNK(10) YM_DIAG_THUNK(11)
YM_DIAG_THUNK(12) YM_DIAG_THUNK(13) YM_DIAG_THUNK(14) YM_DIAG_THUNK(15)
YM_DIAG_THUNK(16) YM_DIAG_THUNK(17) YM_DIAG_THUNK(18) YM_DIAG_THUNK(19)
YM_DIAG_THUNK(20) YM_DIAG_THUNK(21) YM_DIAG_THUNK(22) YM_DIAG_THUNK(23)

static void *gYMDiagThunks[] = {
    (void *)YMDiagThunk_0,  (void *)YMDiagThunk_1,  (void *)YMDiagThunk_2,  (void *)YMDiagThunk_3,
    (void *)YMDiagThunk_4,  (void *)YMDiagThunk_5,  (void *)YMDiagThunk_6,  (void *)YMDiagThunk_7,
    (void *)YMDiagThunk_8,  (void *)YMDiagThunk_9,  (void *)YMDiagThunk_10, (void *)YMDiagThunk_11,
    (void *)YMDiagThunk_12, (void *)YMDiagThunk_13, (void *)YMDiagThunk_14, (void *)YMDiagThunk_15,
    (void *)YMDiagThunk_16, (void *)YMDiagThunk_17, (void *)YMDiagThunk_18, (void *)YMDiagThunk_19,
    (void *)YMDiagThunk_20, (void *)YMDiagThunk_21, (void *)YMDiagThunk_22, (void *)YMDiagThunk_23,
};

static void YMInstallRevokeDiag(void) {
    static BOOL installed = NO;
    if (installed) return;
    if (YMWeChatDylibSlide == 0) {
        YMLog(@"[Diag] slide=0, defer");
        return;
    }
    for (int i = 0; i < YM_DIAG_COUNT; i++) {
        YMDiagEntry *e = &gYMDiagTable[i];
        e->runtimeAddr = YMWeChatDylibSlide + e->staticVA;
        memcpy(e->origBytes, (void *)e->runtimeAddr, 16);
        YMEmitAbsoluteJump((uintptr_t)gYMDiagThunks[i], e->hookBytes);
        if (YMGroupExitWriteCodeBytes(e->runtimeAddr, e->hookBytes, 16, e->name, "diag install")) {
            e->saved = YES;
            YMLog(@"[Diag] hooked %s at 0x%lx", e->name, (unsigned long)e->runtimeAddr);
        } else {
            YMLog(@"[Diag] hook FAILED %s at 0x%lx", e->name, (unsigned long)e->runtimeAddr);
        }
    }
    installed = YES;
    YMLog(@"[Diag] install done, slide=0x%lx, %d hooks", (unsigned long)YMWeChatDylibSlide, YM_DIAG_COUNT);
}

#else
static void YMInstallRevokeDiag(void) {}
#endif

#pragma mark - constructor

__attribute__((constructor))
static void YMWeChatAntiRevokePatchEntry(void) {
    @autoreleasepool {
        YMLog(@"constructor called");
        /// 多开必须尽早执行，不能 dispatch_after。
        YMInstallMultiOpenPatch();

        BOOL exitChat = [[NSUserDefaults standardUserDefaults] boolForKey:kExitChatroom];
        if (exitChat) {
            YMInstallGroupExitMonitorPatch();
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                YMInstallGroupExitMonitorPatch();
            });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                YMInstallGroupExitMonitorPatch();
            });
        }
        

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [[MenuManager shareInstance] initAssistantMenuItems];
        });
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            NSString *loadFlag = [[NSUserDefaults standardUserDefaults] objectForKey:kIsFirstLoad];
            if (loadFlag.length < 3) {
                [[NSUserDefaults standardUserDefaults] setBool:YES forKey:kAntiUpdate];
                [[NSUserDefaults standardUserDefaults] setObject:@"SOVIET" forKey:kIsFirstLoad];
            }
            
            if ([[NSUserDefaults standardUserDefaults] boolForKey:kAntiUpdate]) {
                YMDisableSparkleAutoUpdateDefaults();
                YMDisableSparkleByRuntimeHook();
            }
        });
        
        
        if ([[NSUserDefaults standardUserDefaults] boolForKey:kAntiRevoke]) {
            /*
             先注册 dyld 回调。
             如果 wechat.dylib 在之后加载，可以第一时间拿到 slide。
            */
            YMRegisterDyldCallbackIfNeeded();

            /*
             再主动扫描一次。
             如果 wechat.dylib 在之前已经加载，可以直接安装 hook。
            */
            YMInstallAntiRevokePatch();
            // 诊断模块已完成定位，正式补丁阶段关闭，避免热函数 hook 的噪声/开销。
            // 需再次插桩时取消注释 YMInstallRevokeDiag()。
            // YMInstallRevokeDiag();

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                YMInstallAntiRevokePatch();
                // YMInstallRevokeDiag();
            });

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                YMInstallAntiRevokePatch();
                // YMInstallRevokeDiag();
            });
        }

    }
}

