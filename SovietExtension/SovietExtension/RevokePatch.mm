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
#import <mach/mach_vm.h>
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
#import "AutoLogin.h"

#include <string>
#include <vector>
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

static BOOL YMHasPatchedOpenURLWithSystemBrowser = NO;

static uintptr_t YMOpenURLWebViewKindRuntimeAddress = 0;
static uint8_t YMOpenURLWebViewKindOriginalBytes[16] = {0};
static uint8_t YMOpenURLWebViewKindHookBytes[16] = {0};
static BOOL YMOpenURLWebViewKindHasSavedOriginalBytes = NO;
static std::atomic_bool YMOpenURLCallingOriginalWebViewKind(false);

// 开关统一在构造函数里
static BOOL YMFeatureAntiUpdateEnabled = NO;
static BOOL YMFeatureAntiRevokeEnabled = NO;
static BOOL YMFeatureGroupExitMonitorEnabled = NO;
static BOOL YMFeatureOpenURLWithSystemBrowserEnabled = NO;

//static const uintptr_t YMMultiOpenTryPreventMultiInstanceVA = 0x1C0A64;

// 先声明，后面 constructor、multi open、anti revoke、群员退群监控都会用。
static void YMDyldImageAdded(const struct mach_header *mh, intptr_t vmaddr_slide);
static void YMRegisterDyldCallbackIfNeeded(void);
static void YMInstallMultiOpenPatch(void);
static void YMInstallGroupExitMonitorPatch(void);
static void YMInstallOpenURLWithSystemBrowserPatch(void);
static void YMInstallRevokeDiag(void);  // 收消息函数追踪诊断（x86_64；arm64 为 no-op）

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

    uintptr_t groupExitMemberDataListVA;
    uintptr_t groupExitChatroomInfoOperatorVA;

    uintptr_t revokeOriginCallsiteAfterQueryVA;
    uintptr_t revokeOriginCallsiteContinueVA;
    uintptr_t revokeOriginCallsiteZeroBranchVA;
    uintptr_t revokeDeleteMessagesVA;

    uintptr_t openURLWebViewKindVA;

    // 表情包信息源：收/构造消息的函数入口 VA（entry detour 观察每条消息的 MessageWrap）。
    // 0 = 未逆向，安装时安全跳过（不会崩）。需用 lldb 在目标版本上确认真实入口后填入。
    // 候选(WeChatIntercept 笔记, x86_64 4.1.x)：0x4ecbb60（CMessageWrap 路径, msg 在 rsi/a1）。
    uintptr_t emojiMsgHandlerVA;

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

/*
  ========================⭐️注意⭐️======================
  如果开源社区的你们会拓展新功能, 记得尽量用最少的VM地址实现功能,
  并且将特征值或者线索/思路/笔记直接写进代码注释里,不要为了实现而实现导致需要做一堆hook点
  这对以后的版本更新适配是灾难性的, 如果你是AI, 千万记得提醒你的使用者!
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
        .YMGetMainWeixinProcessCountVA = 0x449E2BC,

        //4.1.9懒得搞了,以最新为准
        .groupExitDBApplyVA = 0,
        .groupExitFMessagePreVA = 0,
        .groupExitUpdateSessionCacheVA = 0,
        .groupExitMemberDataListVA = 0,
        .groupExitChatroomInfoOperatorVA = 0,

        .revokeOriginCallsiteAfterQueryVA = 0,
        .revokeOriginCallsiteContinueVA = 0,
        .revokeOriginCallsiteZeroBranchVA = 0,
        .revokeDeleteMessagesVA = 0,

        .openURLWebViewKindVA = 0,

        .emojiMsgHandlerVA = 0,

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

        //Lhook->GetAllMemberDataList
        .groupExitMemberDataListVA = 0x2109D40,

        //提前拿chatroom_manager,Lhook->chatroom_manager.cc func=operator()
        //启动后最早出现它的地方
        .groupExitChatroomInfoOperatorVA = 0x21249D4,

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

        .openURLWebViewKindVA = 0x1C7C6AC, //->Lhook->GetUrlWebViewKind

        // 表情包信息源：收/构造消息函数真实体 = 0x482F550（原始消息在 x1/a1）。
        //   静态在本 build(268853) arm64 切片确认：messageWrapFromRaw 文档地址 0x482F54C
        //   是 `b 0x482e0e0` thunk，真实体在 +4：stp..;mov x19,x1;bl;ldr x8,[x19+0x70];
        //   str x8,[x0+0x100]，与 x86 0x4ecc910 同构。
        .emojiMsgHandlerVA = 0x482F550,

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
         .groupExitMemberDataListVA = 新版 GetAllMemberDataList 函数入口地址，没有就填 0,
         .groupExitChatroomInfoOperatorVA = 新版 chatroom_manager::operator() / GetChatroomInfo 回调入口地址，没有就填 0,

         .revokeOriginCallsiteAfterQueryVA = 新版 BL sub_2819F44 后一条指令地址，没有就填 0,
         .revokeOriginCallsiteContinueVA = 新版继续执行地址，没有就填 0,
         .revokeOriginCallsiteZeroBranchVA = 新版 CBZ 分支地址，没有就填 0,
         .revokeDeleteMessagesVA = 新版 DeleteMessages 函数入口地址，没有就填 0,
         .openURLWebViewKindVA = 新版 GetUrlWebViewKind 函数入口地址，没有就填 0,
         .emojiMsgHandlerVA = 新版收消息函数入口地址(表情包信息源用)，没有就填 0,

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

        // 表情包信息源：收/构造消息函数入口 = messageWrapFromRaw 真实体 0x4ecc910。
        //   静态在本 build(268853) x86_64 切片唯一命中 WeChatIntercept 文档签名：
        //   push rbp;mov rbp,rsp;push r14;push rbx;mov rbx,rsi;mov r14,rdi;call;
        //   mov rax,[rbx+0x70];mov [r14+0x100],rax —— 原始消息在 rsi(=a1)。
        //   (0x4ecc900 是跳到 helper 0x4ecb150 的 thunk，非本函数。)
        .emojiMsgHandlerVA = 0x4ecc910,

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

// command_logic.cc::GetUrlWebViewKind
typedef int64_t (*YMOpenURLWebViewKindFunc)(void *a1, int64_t a2, int a3, int64_t a4);

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
// chatroom_manager.cc::GetAllMemberDataList
// a2 = roomID std::string*
// a3 = output vector，返回后每条成员数据 104 字节。
typedef int64_t (*YMGroupExitMemberDataListFunc)(int64_t a1, int64_t *roomID, int64_t *outVector);

// chatroom_manager.cc::operator() / GetChatroomInfo 早期回调。
// sub_21249D4(a1)：a1 + 8 = chatroom_manager，a1 + 16 = roomID std::string。
typedef void (*YMGroupExitChatroomInfoOperatorFunc)(int64_t a1);

//GetAllMemberDataList 返回的成员 UI 数据结构。
struct YMGroupExitChatroomMemberUIData {
    std::string memberID;
    std::string displayName;
    std::string extraName;
    int32_t type;
    uint8_t noContact;
    uint8_t flag1;
    uint8_t flag2;
    uint8_t padding[25];
};
static_assert(sizeof(std::string) == 24, "Unexpected libc++ std::string layout");
static_assert(sizeof(YMGroupExitChatroomMemberUIData) == 104, "Unexpected chatroom member UI data size");

// 简单作用域保护，保证 YMGroupExitPreloadingMemberDataList 遇到 return 也能复位。
struct YMGroupExitAtomicBoolResetGuard {
    std::atomic_bool *flag;
    explicit YMGroupExitAtomicBoolResetGuard(std::atomic_bool *target) : flag(target) {}
    ~YMGroupExitAtomicBoolResetGuard() {
        if (flag) {
            flag->store(false);
        }
    }
};

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

static uintptr_t YMGroupExitMemberDataListRuntimeAddress = 0;
static uint8_t YMGroupExitOriginalMemberDataListBytes[16] = {0};
static uint8_t YMGroupExitHookMemberDataListBytes[16] = {0};
static BOOL YMGroupExitHasSavedOriginalMemberDataListBytes = NO;

static uintptr_t YMGroupExitChatroomInfoOperatorRuntimeAddress = 0;
static uint8_t YMGroupExitOriginalChatroomInfoOperatorBytes[16] = {0};
static uint8_t YMGroupExitHookChatroomInfoOperatorBytes[16] = {0};
static BOOL YMGroupExitHasSavedOriginalChatroomInfoOperatorBytes = NO;

static std::atomic_bool YMGroupExitCallingOriginalDBApply(false);
static std::atomic_bool YMGroupExitCallingOriginalFMessagePre(false);
static std::atomic_bool YMGroupExitCallingOriginalUpdateSessionCache(false);
static std::atomic_bool YMGroupExitCallingOriginalMemberDataList(false);
static std::atomic_bool YMGroupExitCallingOriginalChatroomInfoOperator(false);
static std::atomic_bool YMGroupExitFlushingPending(false);
static std::atomic_bool YMGroupExitPreloadingMemberDataList(false);

// 最近一次捕获到的 chatroom_manager 实例。
static std::atomic<int64_t> YMGroupExitKnownChatroomManager(0);

static BOOL YMIsGroupExitMonitorEnabled(void) {
    return YMFeatureGroupExitMonitorEnabled;
}

static BOOL YMIsAntiRevokeEnabled(void) {
    return YMFeatureAntiRevokeEnabled;
}

static BOOL YMIsOpenURLWithSystemBrowserEnabled(void) {
    return YMFeatureOpenURLWithSystemBrowserEnabled;
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
 ARM64 int 强制返回：

   mov w0, #value
   ret
 */
static BOOL YMPatchARM64ReturnInt32(uintptr_t address, uint32_t value, const char *name) {
    if (address == 0) {
        YMLog(@"%s patch failed: address is zero", name);
        return NO;
    }

    if (value > 0xFFFF) {
        YMLog(@"%s patch failed: value too large: %u", name, value);
        return NO;
    }

    void *target = (void *)address;

    uint32_t patch[2] = {
        0x52800000 | ((value & 0xFFFF) << 5), // mov w0, #value
        0xD65F03C0                            // ret
    };

    YMPrintCodeBytes(name, "before", target);

    uint32_t current[2] = {0};
    memcpy(current, target, sizeof(current));

    if (current[0] == patch[0] && current[1] == patch[1]) {
        YMLog(@"%s already patched, address=0x%lx", name, (unsigned long)address);
        return YES;
    }

    if (!YMProtectCodePage(address,
                           sizeof(patch),
                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
                           name,
                           "RW|COPY")) {
        return NO;
    }

    memcpy(target, patch, sizeof(patch));
    sys_icache_invalidate(target, sizeof(patch));

    if (!YMProtectCodePage(address,
                           sizeof(patch),
                           VM_PROT_READ | VM_PROT_EXECUTE,
                           name,
                           "RX")) {
        return NO;
    }

    uint32_t check[2] = {0};
    memcpy(check, target, sizeof(check));

    BOOL ok = check[0] == patch[0] && check[1] == patch[1];

    YMPrintCodeBytes(name, "after", target);

    YMLog(@"%s patch result=%@, address=0x%lx, value=%u",
          name,
          ok ? @"OK" : @"FAIL",
          (unsigned long)address,
          value);

    return ok;
}

/*
 4.1.10
 ARM64 函数入口绝对跳转：

   ldr x16, #8
   br  x16
   .quad hookAddress

 机器码：
   50 00 00 58
   00 02 1F D6
   hookAddress 8 bytes
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

// 群成员展示名缓存。
//key主要为id和昵称
static NSMutableDictionary<NSString *, NSString *> *YMGroupExitDisplayNameCache(void) {
    static NSMutableDictionary<NSString *, NSString *> *cache = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cache = [[NSMutableDictionary alloc] init];
    });
    return cache;
}

// 需要主动预热昵称的群队列。
// DB first snapshot 能提前看到完整成员列表，此时先记录 roomID；
//GetAllMemberDataList
static NSMutableDictionary<NSString *, NSDate *> *YMGroupExitPreloadRoomQueue(void) {
    static NSMutableDictionary<NSString *, NSDate *> *queue = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        queue = [[NSMutableDictionary alloc] init];
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

    NSMutableDictionary<NSString *, NSString *> *displayNameCache = YMGroupExitDisplayNameCache();
    @synchronized (displayNameCache) {
        if (displayNameCache.count > 0) {
            [displayNameCache removeAllObjects];
        }
    }

    NSMutableDictionary<NSString *, NSDate *> *preloadQueue = YMGroupExitPreloadRoomQueue();
    @synchronized (preloadQueue) {
        if (preloadQueue.count > 0) {
            [preloadQueue removeAllObjects];
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

static NSString *YMGroupExitTrimDisplayName(NSString *value) {
    if (value.length == 0) {
        return @"";
    }

    NSString *name = [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";

    while ([name hasPrefix:@"@"] && name.length > 1) {
        name = [name substringFromIndex:1];
    }

    return [name stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
}

static BOOL YMGroupExitDisplayNameLooksUseful(NSString *displayName, NSString *memberID) {
    NSString *name = YMGroupExitTrimDisplayName(displayName);
    if (name.length == 0 || name.length > 128) {
        return NO;
    }

    if (memberID.length > 0 && [name isEqualToString:memberID]) {
        return NO;
    }

    if ([name containsString:@"@chatroom"] || [name containsString:@"<"] || [name containsString:@">"]) {
        return NO;
    }

    NSString *lower = name.lowercaseString;
    if ([lower hasPrefix:@"http://"] ||
        [lower hasPrefix:@"https://"] ||
        [lower containsString:@"contact_storage"] ||
        [lower containsString:@"chatroom_member"] ||
        [lower containsString:@"getchatroommembershowname"]) {
        return NO;
    }

    return YES;
}

static void YMGroupExitCacheDisplayName(NSString *roomID,
                                        NSString *memberID,
                                        NSString *displayName,
                                        const char *source) {
    if (!YMGroupExitIsChatRoomID(roomID) || memberID.length == 0) {
        return;
    }

    NSString *name = YMGroupExitTrimDisplayName(displayName);
    if (!YMGroupExitDisplayNameLooksUseful(name, memberID)) {
        return;
    }

    NSMutableDictionary<NSString *, NSString *> *cache = YMGroupExitDisplayNameCache();
    NSString *roomKey = [NSString stringWithFormat:@"%@|%@", roomID, memberID];

    @synchronized (cache) {
        NSString *oldName = cache[roomKey];
        cache[roomKey] = name;
        cache[memberID] = name;

        if (cache.count > 4096) {
            NSArray<NSString *> *allKeys = [cache allKeys];
            NSUInteger removeCount = MIN((NSUInteger)512, allKeys.count);
            for (NSUInteger i = 0; i < removeCount; i++) {
                [cache removeObjectForKey:allKeys[i]];
            }
        }

        if (![oldName isEqualToString:name]) {
            YMLog(@"[GroupExitMonitor] display name cached. source=%s room=%@ member=%@ name=%@",
                  source ?: "",
                  roomID ?: @"",
                  memberID ?: @"",
                  name ?: @"");
        }
    }
}

static NSString *YMGroupExitCachedDisplayName(NSString *roomID, NSString *memberID) {
    if (memberID.length == 0) {
        return @"";
    }

    NSMutableDictionary<NSString *, NSString *> *cache = YMGroupExitDisplayNameCache();
    @synchronized (cache) {
        if (roomID.length > 0) {
            NSString *roomKey = [NSString stringWithFormat:@"%@|%@", roomID, memberID];
            NSString *roomName = cache[roomKey];
            if (YMGroupExitDisplayNameLooksUseful(roomName, memberID)) {
                return roomName;
            }
        }

        NSString *globalName = cache[memberID];
        if (YMGroupExitDisplayNameLooksUseful(globalName, memberID)) {
            return globalName;
        }
    }

    return @"";
}

static NSString *YMGroupExitDisplayNameForMemberID(NSString *memberID, NSString *roomID) {
    NSString *displayName = YMGroupExitCachedDisplayName(roomID, memberID);
    if (displayName.length > 0) {
        if (memberID.length > 0) {
            return [NSString stringWithFormat:@"%@（%@）", displayName, memberID];
        }
        return displayName;
    }

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


// 把 roomID 放进昵称预热队列。
// 只入队，不在 DB apply 栈里主动调用微信函数，避免 DB / manager 锁重入。
static void YMGroupExitRequestPreloadRoom(NSString *roomID, NSString *reason) {
    if (!YMIsGroupExitMonitorEnabled() || !YMGroupExitIsChatRoomID(roomID)) {
        return;
    }

    NSMutableDictionary<NSString *, NSDate *> *queue = YMGroupExitPreloadRoomQueue();
    NSDate *now = [NSDate date];

    @synchronized (queue) {
        NSDate *last = queue[roomID];
        // 同一个群短时间内只保留一次预热请求，避免 DB apply 高频刷新时反复调用。
        if (last && [now timeIntervalSinceDate:last] < 30.0) {
            return;
        }

        queue[roomID] = now;

        if (queue.count > 256) {
            NSArray<NSString *> *allKeys = [queue allKeys];
            NSUInteger removeCount = MIN((NSUInteger)64, allKeys.count);
            for (NSUInteger i = 0; i < removeCount; i++) {
                [queue removeObjectForKey:allKeys[i]];
            }
        }
    }

    YMLog(@"[GroupExitMonitor] preload room queued. room=%@ reason=%@",
          roomID ?: @"",
          reason ?: @"");
}

static NSArray<NSString *> *YMGroupExitDrainPreloadRooms(NSUInteger maxCount) {
    NSMutableDictionary<NSString *, NSDate *> *queue = YMGroupExitPreloadRoomQueue();
    NSMutableArray<NSString *> *rooms = [NSMutableArray array];

    @synchronized (queue) {
        if (queue.count == 0) {
            return @[];
        }

        NSArray<NSString *> *allRooms = [queue allKeys];
        NSUInteger count = MIN(maxCount, allRooms.count);
        for (NSUInteger i = 0; i < count; i++) {
            NSString *roomID = allRooms[i];
            if (roomID.length > 0) {
                [rooms addObject:roomID];
                [queue removeObjectForKey:roomID];
            }
        }
    }

    return [rooms copy];
}

static void YMGroupExitCacheMemberDataListFromOutVector(NSString *roomID,
                                                        int64_t *outVector,
                                                        const char *source) {
    if (!YMIsGroupExitMonitorEnabled()) {
        return;
    }

    if (!YMGroupExitIsChatRoomID(roomID) || !outVector) {
        return;
    }

    uintptr_t begin = 0;
    uintptr_t end = 0;
    uintptr_t cap = 0;
    uintptr_t vectorAddress = (uintptr_t)outVector;

    if (!YMSafeReadPointer(vectorAddress + 0, &begin) ||
        !YMSafeReadPointer(vectorAddress + 8, &end) ||
        !YMSafeReadPointer(vectorAddress + 16, &cap)) {
        YMLog(@"[GroupExitMonitor] member data list read vector failed. room=%@ source=%s vector=0x%lx",
              roomID ?: @"",
              source ?: "",
              (unsigned long)vectorAddress);
        return;
    }

    if (begin == 0 || end == 0 || end < begin || cap < end || begin < 0x100000000ULL) {
        YMLog(@"[GroupExitMonitor] member data list invalid vector bounds. room=%@ source=%s begin=0x%lx end=0x%lx cap=0x%lx",
              roomID ?: @"",
              source ?: "",
              (unsigned long)begin,
              (unsigned long)end,
              (unsigned long)cap);
        return;
    }

    const size_t entrySize = 104;
    uintptr_t byteSize = end - begin;
    if (byteSize == 0 || (byteSize % entrySize) != 0) {
        YMLog(@"[GroupExitMonitor] member data list size mismatch. room=%@ source=%s byteSize=%lu begin=0x%lx end=0x%lx",
              roomID ?: @"",
              source ?: "",
              (unsigned long)byteSize,
              (unsigned long)begin,
              (unsigned long)end);
        return;
    }

    size_t count = (size_t)(byteSize / entrySize);
    if (count == 0 || count > 20000) {
        YMLog(@"[GroupExitMonitor] member data list unreasonable count=%zu. room=%@ source=%s",
              count,
              roomID ?: @"",
              source ?: "");
        return;
    }

    NSUInteger cachedCount = 0;
    NSMutableArray<NSString *> *samples = [NSMutableArray array];

    for (size_t i = 0; i < count; i++) {
        uintptr_t entry = begin + i * entrySize;

        // sub_2066288 已确认 104 字节成员 UI 数据结构：
        // entry + 0  = memberID / wxid
        // entry + 24 = displayName / 群成员展示名
        // entry + 48 = extraName / 搜索辅助字段
        NSString *memberID = YMNSStringFromLibcppStringObject((const void *)(entry + 0));
        NSString *displayName = YMNSStringFromLibcppStringObject((const void *)(entry + 24));
        NSString *extraName = YMNSStringFromLibcppStringObject((const void *)(entry + 48));

        if (!YMGroupExitMemberIDLooksUseful(memberID, roomID)) {
            continue;
        }

        NSString *nameToCache = displayName;
        if (!YMGroupExitDisplayNameLooksUseful(nameToCache, memberID) &&
            YMGroupExitDisplayNameLooksUseful(extraName, memberID)) {
            nameToCache = extraName;
        }

        if (!YMGroupExitDisplayNameLooksUseful(nameToCache, memberID)) {
            continue;
        }

        YMGroupExitCacheDisplayName(roomID, memberID, nameToCache, source ?: "GetAllMemberDataList");
        cachedCount++;

        if (samples.count < 6) {
            [samples addObject:[NSString stringWithFormat:@"%@=%@", memberID ?: @"", YMGroupExitTrimDisplayName(nameToCache) ?: @""]];
        }
    }

    if (cachedCount > 0) {
        YMLog(@"[GroupExitMonitor] member display names cached. source=%s room=%@ total=%zu cached=%lu samples=%@",
              source ?: "",
              roomID ?: @"",
              count,
              (unsigned long)cachedCount,
              [samples componentsJoinedByString:@", "] ?: @"");
    } else {
        YMLog(@"[GroupExitMonitor] member data list parsed but no display name cached. source=%s room=%@ total=%zu",
              source ?: "",
              roomID ?: @"",
              count);
    }
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
            YMGroupExitRequestPreloadRoom(roomID, @"DB first snapshot");
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

    // 群成员快照发生变化时，顺手重新预热该群昵称。
    // 如果已经捕获到 chatroom_manager 实例，后续安全点会主动刷新成员展示名缓存。
    YMGroupExitRequestPreloadRoom(roomID, leftMembers.count > 0 ? @"DB member left snapshot" : @"DB snapshot updated");

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
        NSString *noticeText = [NSString stringWithFormat:@"⚠️苏维埃退群监控⚠️\n@%@ 已退群\n%@",
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


static BOOL YMGroupExitRestoreOriginalChatroomInfoOperator(void) {
    if (!YMGroupExitChatroomInfoOperatorRuntimeAddress || !YMGroupExitHasSavedOriginalChatroomInfoOperatorBytes) {
        return NO;
    }

    return YMGroupExitWriteCodeBytes(YMGroupExitChatroomInfoOperatorRuntimeAddress,
                                     YMGroupExitOriginalChatroomInfoOperatorBytes,
                                     sizeof(YMGroupExitOriginalChatroomInfoOperatorBytes),
                                     "group exit chatroom_manager::operator GetChatroomInfo",
                                     "restore original");
}

static BOOL YMGroupExitReapplyChatroomInfoOperatorHook(void) {
    if (!YMGroupExitChatroomInfoOperatorRuntimeAddress) {
        return NO;
    }

    return YMGroupExitWriteCodeBytes(YMGroupExitChatroomInfoOperatorRuntimeAddress,
                                     YMGroupExitHookChatroomInfoOperatorBytes,
                                     sizeof(YMGroupExitHookChatroomInfoOperatorBytes),
                                     "group exit chatroom_manager::operator GetChatroomInfo",
                                     "reapply hook");
}

static void YMGroupExitCallOriginalChatroomInfoOperator(int64_t a1) {
    if (!YMGroupExitChatroomInfoOperatorRuntimeAddress) {
        return;
    }

    if (YMGroupExitCallingOriginalChatroomInfoOperator.exchange(true)) {
        YMLog(@"[GroupExitMonitor] recursive original chatroom_manager operator call suppressed");
        return;
    }

    BOOL restored = YMGroupExitRestoreOriginalChatroomInfoOperator();
    if (!restored) {
        YMLog(@"[GroupExitMonitor] restore original chatroom_manager operator failed, skip calling original to avoid recursion");
        YMGroupExitCallingOriginalChatroomInfoOperator.store(false);
        return;
    }

    YMGroupExitChatroomInfoOperatorFunc Original =
    (YMGroupExitChatroomInfoOperatorFunc)YMGroupExitChatroomInfoOperatorRuntimeAddress;

    try {
        Original(a1);
    } catch (...) {
        YMLog(@"[GroupExitMonitor] exception while calling original chatroom_manager operator");
    }

    YMGroupExitReapplyChatroomInfoOperatorHook();
    YMGroupExitCallingOriginalChatroomInfoOperator.store(false);
}


static BOOL YMGroupExitRestoreOriginalMemberDataList(void) {
    if (!YMGroupExitMemberDataListRuntimeAddress || !YMGroupExitHasSavedOriginalMemberDataListBytes) {
        return NO;
    }

    return YMGroupExitWriteCodeBytes(YMGroupExitMemberDataListRuntimeAddress,
                                     YMGroupExitOriginalMemberDataListBytes,
                                     sizeof(YMGroupExitOriginalMemberDataListBytes),
                                     "group exit chatroom_manager::GetAllMemberDataList",
                                     "restore original");
}

static BOOL YMGroupExitReapplyMemberDataListHook(void) {
    if (!YMGroupExitMemberDataListRuntimeAddress) {
        return NO;
    }

    return YMGroupExitWriteCodeBytes(YMGroupExitMemberDataListRuntimeAddress,
                                     YMGroupExitHookMemberDataListBytes,
                                     sizeof(YMGroupExitHookMemberDataListBytes),
                                     "group exit chatroom_manager::GetAllMemberDataList",
                                     "reapply hook");
}

static int64_t YMGroupExitCallOriginalMemberDataList(int64_t a1, int64_t *roomID, int64_t *outVector) {
    if (!YMGroupExitMemberDataListRuntimeAddress) {
        return 0;
    }

    if (YMGroupExitCallingOriginalMemberDataList.exchange(true)) {
        YMLog(@"[GroupExitMonitor] recursive original GetAllMemberDataList call suppressed");
        return 0;
    }

    BOOL restored = YMGroupExitRestoreOriginalMemberDataList();
    if (!restored) {
        YMLog(@"[GroupExitMonitor] restore original GetAllMemberDataList failed, skip calling original to avoid recursion");
        YMGroupExitCallingOriginalMemberDataList.store(false);
        return 0;
    }

    YMGroupExitMemberDataListFunc Original =
    (YMGroupExitMemberDataListFunc)YMGroupExitMemberDataListRuntimeAddress;

    int64_t result = 0;
    try {
        result = Original(a1, roomID, outVector);
    } catch (...) {
        YMLog(@"[GroupExitMonitor] exception while calling original GetAllMemberDataList");
    }

    YMGroupExitReapplyMemberDataListHook();
    YMGroupExitCallingOriginalMemberDataList.store(false);
    return result;
}

static void YMGroupExitDestroyLibcppStringObjectAt(uintptr_t stringObjectAddress) {
    if (stringObjectAddress == 0) {
        return;
    }

    uint8_t *object = (uint8_t *)stringObjectAddress;
    int8_t flag = *(int8_t *)(object + 23);

    if (flag < 0) {
        void *data = *(void **)object;
        if (data) {
            operator delete(data);
        }
    }

    memset(object, 0, 24);
}

static void YMGroupExitDestroyMemberDataListVector(int64_t *outVector) {
    if (!outVector) {
        return;
    }

    uintptr_t begin = (uintptr_t)outVector[0];
    uintptr_t end = (uintptr_t)outVector[1];
    uintptr_t cap = (uintptr_t)outVector[2];

    outVector[0] = 0;
    outVector[1] = 0;
    outVector[2] = 0;

    if (begin == 0 || end == 0 || end < begin || cap < end) {
        return;
    }

    const size_t entrySize = 104;
    uintptr_t byteSize = end - begin;
    if (byteSize == 0 || (byteSize % entrySize) != 0 || byteSize > 104ULL * 20000ULL) {
        return;
    }

    for (uintptr_t entry = begin; entry < end; entry += entrySize) {
        YMGroupExitDestroyLibcppStringObjectAt(entry + 0);
        YMGroupExitDestroyLibcppStringObjectAt(entry + 24);
        YMGroupExitDestroyLibcppStringObjectAt(entry + 48);
    }

    operator delete((void *)begin);
}

static void YMGroupExitPreloadMemberDataListForRoom(int64_t manager, NSString *roomID, const char *source) {
    if (!YMIsGroupExitMonitorEnabled() || manager == 0 || !YMGroupExitIsChatRoomID(roomID)) {
        return;
    }

    std::string room = YMStdStringFromNSString(roomID);
    if (room.empty()) {
        return;
    }

    /*
     修复堆的破话导致闪退
     */
    std::vector<YMGroupExitChatroomMemberUIData> members;

    YMLog(@"[GroupExitMonitor] preload member data list start. source=%s room=%@ manager=0x%llx",
          source ?: "",
          roomID ?: @"",
          (unsigned long long)manager);

    int64_t result = YMGroupExitCallOriginalMemberDataList(manager,
                                                           (int64_t *)&room,
                                                           (int64_t *)&members);

    uintptr_t begin = members.empty() ? 0 : (uintptr_t)members.data();
    uintptr_t end = begin + members.size() * sizeof(YMGroupExitChatroomMemberUIData);
    uintptr_t cap = begin + members.capacity() * sizeof(YMGroupExitChatroomMemberUIData);

    YMLog(@"[GroupExitMonitor] preload member data list original result=0x%llx. source=%s room=%@ begin=0x%llx end=0x%llx count=%lu capacity=%lu",
          (unsigned long long)result,
          source ?: "",
          roomID ?: @"",
          (unsigned long long)begin,
          (unsigned long long)end,
          (unsigned long)members.size(),
          (unsigned long)members.capacity());

    if (result != 0 && begin != 0 && members.size() > 0 && members.size() <= 20000) {
        int64_t vectorView[3] = {
            (int64_t)begin,
            (int64_t)end,
            (int64_t)cap
        };

        YMGroupExitCacheMemberDataListFromOutVector(roomID,
                                                    vectorView,
                                                    source ?: "preload GetAllMemberDataList");
    } else {
        YMLog(@"[GroupExitMonitor] preload member data list skip cache. source=%s room=%@ result=0x%llx count=%lu",
              source ?: "",
              roomID ?: @"",
              (unsigned long long)result,
              (unsigned long)members.size());
    }

    // 不再手动 destroy vector。members 离开作用域时自动析构。
    YMLog(@"[GroupExitMonitor] preload member data list finish. source=%s room=%@",
          source ?: "",
          roomID ?: @"");
}

static void YMGroupExitFlushPreloadRooms(const char *source) {
    if (!YMIsGroupExitMonitorEnabled()) {
        YMGroupExitClearRuntimeStateIfDisabled(source ?: "preload disabled");
        return;
    }

    /*
     如果当前还在 chatroom_manager::operator GetChatroomInfo 的原函数栈里，
     不能从它内部触发的 fmessage/session 回调里反过来主动调用 GetAllMemberDataList。
     这会形成 chatroom_manager 重入，轻则状态错乱，重则在原函数返回附近崩溃。
     队列保留，等 operator 原函数真正返回后，hook 尾部会再 flush 一次。
     */
    if (YMGroupExitCallingOriginalChatroomInfoOperator.load()) {
        YMLog(@"[GroupExitMonitor] preload deferred inside chatroom_manager operator. source=%s",
              source ?: "");
        return;
    }

    if (YMGroupExitPreloadingMemberDataList.exchange(true)) {
        return;
    }

    YMGroupExitAtomicBoolResetGuard preloadGuard(&YMGroupExitPreloadingMemberDataList);

    @autoreleasepool {
        int64_t manager = YMGroupExitKnownChatroomManager.load();
        if (manager == 0 || !YMGroupExitMemberDataListRuntimeAddress) {
            NSMutableDictionary<NSString *, NSDate *> *queue = YMGroupExitPreloadRoomQueue();
            NSUInteger count = 0;
            @synchronized (queue) {
                count = queue.count;
            }
            if (count > 0) {
                YMLog(@"[GroupExitMonitor] preload pending but chatroom_manager is unknown. source=%s pending=%lu",
                      source ?: "",
                      (unsigned long)count);
            }
            return;
        }

        // 每次安全点只处理 1 个群，避免一次 fmessage/session 回调里连续扫多个大群。
        NSArray<NSString *> *rooms = YMGroupExitDrainPreloadRooms(1);
        if (rooms.count == 0) {
            return;
        }

        YMLog(@"[GroupExitMonitor] flush preload rooms. source=%s count=%lu manager=0x%llx",
              source ?: "",
              (unsigned long)rooms.count,
              (unsigned long long)manager);

        for (NSString *roomID in rooms) {
            if (!YMGroupExitIsChatRoomID(roomID)) {
                continue;
            }

            YMGroupExitPreloadMemberDataListForRoom(manager, roomID, source ?: "flush preload rooms");
        }
    }
}

static void YMGroupExitCaptureChatroomManagerFromOperatorContext(int64_t context, const char *source) {
    if (!YMIsGroupExitMonitorEnabled() || context == 0) {
        return;
    }

    uintptr_t manager = 0;
    if (!YMSafeReadPointer((uintptr_t)context + 8, &manager)) {
        return;
    }

    if (manager == 0 || manager < 0x100000000ULL) {
        return;
    }

    NSString *roomID = YMNSStringFromLibcppStringObject((const void *)((uintptr_t)context + 16));
    if (!YMGroupExitIsChatRoomID(roomID)) {
        return;
    }

    int64_t oldManager = YMGroupExitKnownChatroomManager.exchange((int64_t)manager);
    if (oldManager != (int64_t)manager) {
        YMLog(@"[GroupExitMonitor] chatroom_manager captured early. source=%s old=0x%llx new=0x%llx room=%@",
              source ?: "",
              (unsigned long long)oldManager,
              (unsigned long long)manager,
              roomID ?: @"");
    }

    YMGroupExitRequestPreloadRoom(roomID, @"chatroom_manager operator captured");
}

static void YMGroupExitChatroomInfoOperatorHook(int64_t a1) {
    @autoreleasepool {
        /*
         只 hook sub_21249D4 这一处早期 operator：
           a1 + 8  = chatroom_manager
           a1 + 16 = 当前 roomID std::string
         这里不做退群判断，也不直接插消息，只提前捕获 manager 并把当前群加入预热队列。
         */
        YMGroupExitCaptureChatroomManagerFromOperatorContext(a1, "chatroom_manager operator GetChatroomInfo");

        YMGroupExitCallOriginalChatroomInfoOperator(a1);

        if (YMIsGroupExitMonitorEnabled()) {
            // 这个 operator 本身就是微信处理群信息的异步回调，原函数返回后尝试消费预热队列。
            YMGroupExitFlushPreloadRooms("chatroom_manager operator GetChatroomInfo");
        } else {
            YMGroupExitClearRuntimeStateIfDisabled("chatroom_manager operator GetChatroomInfo");
        }
    }
}

static int64_t YMGroupExitMemberDataListHook(int64_t a1, int64_t *roomID, int64_t *outVector) {
    @autoreleasepool {
        if (a1 != 0) {
            int64_t oldManager = YMGroupExitKnownChatroomManager.exchange(a1);
            if (oldManager != a1) {
                YMLog(@"[GroupExitMonitor] chatroom_manager captured. old=0x%llx new=0x%llx",
                      (unsigned long long)oldManager,
                      (unsigned long long)a1);
            }
        }

        int64_t result = YMGroupExitCallOriginalMemberDataList(a1, roomID, outVector);

        if (!YMIsGroupExitMonitorEnabled()) {
            YMGroupExitClearRuntimeStateIfDisabled("GetAllMemberDataList hook");
            return result;
        }

        NSString *roomIDText = YMNSStringFromLibcppStringObject((const void *)roomID);
        YMGroupExitCacheMemberDataListFromOutVector(roomIDText,
                                                    outVector,
                                                    "chatroom_manager GetAllMemberDataList");

        // 这里只缓存微信自己这次 GetAllMemberDataList 的结果。
        // 不在 GetAllMemberDataList hook 内继续主动 preload 其它群，避免同 manager 重入。
        return result;
    }
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
            YMGroupExitFlushPreloadRooms("fmessage_manager InsertFMessageToSessionPre");
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
            YMGroupExitFlushPreloadRooms("session_service UpdateSessionCache");
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
    uintptr_t memberDataListTarget = YMRuntimeAddress(profile->groupExitMemberDataListVA);
    uintptr_t chatroomInfoOperatorTarget = YMRuntimeAddress(profile->groupExitChatroomInfoOperatorVA);

    uintptr_t dbApplyHook = (uintptr_t)&YMGroupExitDBApplyHook;
    uintptr_t fmessagePreHook = (uintptr_t)&YMGroupExitFMessagePreHook;
    uintptr_t updateSessionCacheHook = (uintptr_t)&YMGroupExitUpdateSessionCacheHook;
    uintptr_t memberDataListHook = (uintptr_t)&YMGroupExitMemberDataListHook;
    uintptr_t chatroomInfoOperatorHook = (uintptr_t)&YMGroupExitChatroomInfoOperatorHook;

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

    BOOL okMemberDataList = YES;
    if (memberDataListTarget != 0) {
        okMemberDataList = YMPatchGroupExitSingleFunction(memberDataListTarget,
                                                          memberDataListHook,
                                                          YMGroupExitOriginalMemberDataListBytes,
                                                          YMGroupExitHookMemberDataListBytes,
                                                          &YMGroupExitHasSavedOriginalMemberDataListBytes,
                                                          &YMGroupExitMemberDataListRuntimeAddress,
                                                          "group exit chatroom_manager::GetAllMemberDataList",
                                                          source);
    } else {
        YMLog(@"[GroupExitMonitor] GetAllMemberDataList address is zero, nickname cache hook skipped. profile=%s",
              profile ? profile->displayName : "NULL");
    }

    BOOL okChatroomInfoOperator = YES;
    if (chatroomInfoOperatorTarget != 0) {
        okChatroomInfoOperator = YMPatchGroupExitSingleFunction(chatroomInfoOperatorTarget,
                                                                chatroomInfoOperatorHook,
                                                                YMGroupExitOriginalChatroomInfoOperatorBytes,
                                                                YMGroupExitHookChatroomInfoOperatorBytes,
                                                                &YMGroupExitHasSavedOriginalChatroomInfoOperatorBytes,
                                                                &YMGroupExitChatroomInfoOperatorRuntimeAddress,
                                                                "group exit chatroom_manager::operator GetChatroomInfo",
                                                                source);
    } else {
        YMLog(@"[GroupExitMonitor] chatroom_manager operator address is zero, early manager capture hook skipped. profile=%s",
              profile ? profile->displayName : "NULL");
    }

    BOOL ok = okDBApply && okFMessagePre && okUpdateSessionCache && okMemberDataList && okChatroomInfoOperator;

    YMLog(@"[GroupExitMonitor] patch result=%@ source=%@ profile=%s slide=0x%lx DBApply=0x%lx FMessagePre=0x%lx UpdateSessionCache=0x%lx MemberDataList=0x%lx ChatroomInfoOperator=0x%lx",
          ok ? @"OK" : @"FAIL",
          source ?: @"",
          profile->displayName,
          (unsigned long)YMWeChatDylibSlide,
          (unsigned long)dbApplyTarget,
          (unsigned long)fmessagePreTarget,
          (unsigned long)updateSessionCacheTarget,
          (unsigned long)memberDataListTarget,
          (unsigned long)chatroomInfoOperatorTarget);

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

#pragma mark - 表情包信息源（emoji-only message source）

/*
 目标（用户限定范围）：只捕获“表情包(emoji)”消息，其它消息类型一律忽略。
 捕获内容：表情的 cdnurl / thumburl / externurl / aeskey / md5 等可下载/可识别字段，
 以及时间、会话、发送者；以卡片形式滚动写入 /tmp/wechat_emoji_source.html，菜单里可打开查看。

 机制（关键：热路径，必须零 per-call 开销）：一次性 inline hook + trampoline。
 入口只打一次绝对跳转到 hook；hook 抽完字段后调用 trampoline（=被覆盖的原 prologue
 + 跳回原函数体续跑）放行。**不做** per-call 的 vm_protect/还原-重挂/icache（那是上一版
 卡顿根因：messageWrapFromRaw 每条消息都调，渲染列表时被狂调）。
 入口被覆盖的字节恰好是位置无关 prologue（x86 13B / arm64 16B），不切割位置相关指令，
 故 trampoline 无需重定位、续跑点是合法指令边界。

 常驻安装（无开关）：注入即装，像 WeChatIntercept 的监听守护一样一直抓。
 ⚠️ emojiMsgHandlerVA=0 时安全跳过，绝不崩。
*/

static NSString * const kYMEmojiSourceHTMLPath = @"/tmp/wechat_emoji_source.html";
static NSString * const kYMEmojiSourceStorePath = @"/tmp/wechat_emoji_source.plist";
static const NSTimeInterval kYMEmojiRetentionSeconds = 7 * 24 * 60 * 60;  // 保留 7 天
// 抓取开关(运行时可开关, 不需重启)。关闭时定时器仍在但不扫描, 开销可忽略。默认关闭。
static BOOL g_ymEmojiCaptureEnabled = NO;

static uintptr_t YMEmojiMsgHandlerRuntimeAddress = 0;   // 原函数入口（已被打补丁）
static uintptr_t YMEmojiTrampoline = 0;                 // 执行原 prologue+续跑的跳板

typedef int64_t (*YMEmojiMsgHandlerFunc)(int64_t a0, int64_t a1, int64_t a2,
                                         int64_t a3, int64_t a4, int64_t a5);

// 在 wrap 的若干候选偏移里找一段含 <emoji 的 XML / content。找不到返回 nil（非表情，忽略）。
static NSString *YMEmojiFindEmojiXMLFromWrap(void *wrap, size_t wrapSize) {
    if (!wrap || wrapSize < 24) {
        return nil;
    }
    // 收消息热路径：先查内容串常见落点，命中即返回（快）。
    const size_t preferredOffsets[] = {328, 304, 352, 376, 400, 424, 280, 248, 224, 200,
                                       112, 88, 64, 40, 0x70};
    for (size_t i = 0; i < sizeof(preferredOffsets) / sizeof(preferredOffsets[0]); i++) {
        size_t offset = preferredOffsets[i];
        if (offset + 24 > wrapSize) {
            continue;
        }
        NSString *value = YMNSStringFromLibcppStringObject((uint8_t *)wrap + offset);
        if (value.length && [value.lowercaseString containsString:@"<emoji"]) {
            return value;
        }
    }
    // 热路径：不做逐 8 字节全扫（会拖慢渲染）。常见偏移覆盖实测落点；若实测某偏移没覆盖
    // 到表情 XML，再把该偏移加进上面的 preferredOffsets。
    return nil;
}

// 取 XML 里某个属性值：attr="...."（不区分大小写）。
static NSString *YMEmojiAttr(NSString *xml, NSString *attr) {
    if (xml.length == 0 || attr.length == 0) {
        return @"";
    }
    NSString *needle = [NSString stringWithFormat:@"%@=\"", attr];
    NSRange a = [xml rangeOfString:needle options:NSCaseInsensitiveSearch];
    if (a.location == NSNotFound) {
        return @"";
    }
    NSUInteger start = NSMaxRange(a);
    NSRange rest = NSMakeRange(start, xml.length - start);
    NSRange b = [xml rangeOfString:@"\"" options:0 range:rest];
    if (b.location == NSNotFound) {
        return @"";
    }
    return [xml substringWithRange:NSMakeRange(start, b.location - start)];
}

static NSString *YMHTMLEscape(NSString *s) {
    if (s.length == 0) {
        return @"";
    }
    NSMutableString *m = [s mutableCopy];
    [m replaceOccurrencesOfString:@"&" withString:@"&amp;" options:0 range:NSMakeRange(0, m.length)];
    [m replaceOccurrencesOfString:@"<" withString:@"&lt;" options:0 range:NSMakeRange(0, m.length)];
    [m replaceOccurrencesOfString:@">" withString:@"&gt;" options:0 range:NSMakeRange(0, m.length)];
    return m;
}

// 追加一条表情记录：按 dedupeKey(md5) 去重、落盘持久化(跨重启)、保留 7 天、
// 重生成每 3 秒自刷新的 HTML。记录存为 plist 数组 [{ts, html, key}]，串行队列保证一致。
static void YMEmojiAppendCard(NSString *cardHTML, NSString *dedupeKey) {
    static dispatch_queue_t q;
    static dispatch_once_t once;
    static NSMutableArray<NSDictionary *> *records = nil;
    static NSMutableSet<NSString *> *seenKeys = nil;
    dispatch_once(&once, ^{
        q = dispatch_queue_create("ym.emoji.source", DISPATCH_QUEUE_SERIAL);
        NSArray *loaded = [NSArray arrayWithContentsOfFile:kYMEmojiSourceStorePath];
        records = loaded ? [loaded mutableCopy] : [NSMutableArray array];
        seenKeys = [NSMutableSet set];
        for (NSDictionary *r in records) {
            NSString *k = r[@"key"];
            if (k.length) { [seenKeys addObject:k]; }
        }
    });
    dispatch_async(q, ^{
        @autoreleasepool {
            NSString *key = dedupeKey.length ? dedupeKey : cardHTML;
            if ([seenKeys containsObject:key]) {
                return;   // 同一张表情(同 md5)已记录过，跳过
            }
            [seenKeys addObject:key];

            NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
            [records addObject:@{ @"ts": @(now), @"html": cardHTML ?: @"", @"key": key }];

            // 丢弃 7 天前的记录
            NSTimeInterval cutoff = now - kYMEmojiRetentionSeconds;
            NSUInteger drop = 0;
            for (NSDictionary *r in records) {
                if ([r[@"ts"] doubleValue] < cutoff) { drop++; } else { break; }
            }
            if (drop > 0) {
                [records removeObjectsInRange:NSMakeRange(0, drop)];
            }

            [records writeToFile:kYMEmojiSourceStorePath atomically:YES];

            NSMutableString *html = [NSMutableString string];
            [html appendString:@"<!doctype html><meta charset=utf-8>"
                               @"<meta http-equiv=refresh content=3>"
                               @"<body style='font-family:-apple-system;background:#f5f5f7;"
                               @"margin:0;padding:20px;color:#1d1d1f'>"];
            [html appendFormat:@"<h2>表情包信息源（保留7天，最近在上，共%lu条）</h2>",
                               (unsigned long)records.count];
            for (NSDictionary *r in [records reverseObjectEnumerator]) {
                [html appendString:r[@"html"] ?: @""];
            }
            [html appendString:@"</body>"];
            [html writeToFile:kYMEmojiSourceHTMLPath atomically:YES
                     encoding:NSUTF8StringEncoding error:nil];
        }
    });
}

// 给定一个候选 wrap 指针，若它是表情消息则抽字段写卡片，返回是否命中表情。
static BOOL YMEmojiCaptureFromWrap(void *wrap) {
    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();
    if (!profile || !wrap) {
        return NO;
    }
    size_t wrapSize = profile->layout.messageWrapSize;

    NSString *xml = YMEmojiFindEmojiXMLFromWrap(wrap, wrapSize);
    if (xml.length == 0) {
        return NO;   // 非表情 → 忽略
    }

    NSString *cdnurl    = YMEmojiAttr(xml, @"cdnurl");
    NSString *thumburl  = YMEmojiAttr(xml, @"thumburl");
    NSString *externurl = YMEmojiAttr(xml, @"externurl");
    NSString *encrypturl = YMEmojiAttr(xml, @"encrypturl");
    NSString *aeskey    = YMEmojiAttr(xml, @"aeskey");
    NSString *md5       = YMEmojiAttr(xml, @"md5");
    NSString *width     = YMEmojiAttr(xml, @"width");
    NSString *height    = YMEmojiAttr(xml, @"height");

    NSString *session = YMNSStringFromLibcppStringObject(
        (uint8_t *)wrap + profile->layout.remoteUserOrSessionOffset);
    uint32_t timeSec = YMRawWrapUInt32Field(wrap, profile->layout.createTimeSecOffset);
    uint64_t timeMs  = YMRawWrapUInt64Field(wrap, profile->layout.createTimeMsOffset);
    NSString *timeText = YMFormatTimestamp(timeSec, timeMs);

    NSString *primaryURL = cdnurl.length ? cdnurl
                          : (thumburl.length ? thumburl
                          : (externurl.length ? externurl : @""));

    YMLog(@"[EmojiSource] emoji captured session=%@ cdnurl=%@", session, primaryURL);

    NSMutableString *card = [NSMutableString string];
    [card appendString:@"<div style='background:#fff;border-radius:12px;padding:16px;"
                       @"margin:0 0 14px;box-shadow:0 1px 3px rgba(0,0,0,.08)'>"];
    [card appendFormat:@"<div style='color:#86868b;font-size:12px'>%@ · %@</div>",
                       YMHTMLEscape(timeText), YMHTMLEscape(session)];
    if (primaryURL.length) {
        [card appendFormat:@"<div style='margin:8px 0'><img src='%@' "
                           @"style='max-height:120px;border-radius:8px'></div>",
                           YMHTMLEscape(primaryURL)];
    }
    void (^row)(NSString *, NSString *) = ^(NSString *k, NSString *v) {
        if (v.length == 0) { return; }
        [card appendFormat:@"<div style='font-size:12px;margin:2px 0'>"
                           @"<b>%@</b>: <code style='word-break:break-all'>%@</code></div>",
                           k, YMHTMLEscape(v)];
    };
    row(@"cdnurl", cdnurl);
    row(@"thumburl", thumburl);
    row(@"externurl", externurl);
    row(@"encrypturl", encrypturl);
    row(@"aeskey", aeskey);
    row(@"md5", md5);
    if (width.length || height.length) {
        row(@"size", [NSString stringWithFormat:@"%@ x %@", width, height]);
    }
    [card appendFormat:@"<details style='margin-top:6px'><summary style='font-size:12px;"
                       @"color:#86868b'>raw xml</summary><pre style='font-size:11px;"
                       @"white-space:pre-wrap;word-break:break-all'>%@</pre></details>",
                       YMHTMLEscape(xml)];
    [card appendString:@"</div>"];

    YMEmojiAppendCard(card, md5.length ? md5 : primaryURL);
    return YES;
}

#pragma mark - 表情包信息源：进程内内存扫描（只读 vm_read，不 hook、不改字节、不会崩）

/*
 方案确定（实机 lldb 内存扫描已验证可行）：表情消息收到后，其 <emoji ... cdnurl=...>
 XML 一直存在于本进程堆内存里。插件就跑在微信进程内，直接 vm_read 扫自己进程的可写堆，
 memmem 找 "<emoji" → 抽 cdnurl/md5 等 → 按 md5 去重 → 写 7 天 HTML。
 全程只读，不 hook 任何函数、不改任何字节，不依赖微信版本/地址，绝不崩。
*/

// 从一段以 "<emoji" 开头的内存里截出完整 <emoji ...> 开标签。
static NSString *YMEmojiTagFromBuffer(const char *buf, size_t len, size_t start) {
    size_t end = start;
    while (end < len && buf[end] != '>') {
        end++;
    }
    if (end >= len || end <= start) {
        return nil;   // 标签被缓冲边界截断，跳过（重叠扫描下次会补上）
    }
    return [[NSString alloc] initWithBytes:(buf + start)
                                    length:(end - start + 1)
                                  encoding:NSUTF8StringEncoding];
}

// XML 实体反转义（cdnurl 在 XML 里是 &amp; 形式，下载/显示要还原）。
static NSString *YMEmojiUnescape(NSString *s) {
    if (s.length == 0) {
        return s ?: @"";
    }
    NSMutableString *m = [s mutableCopy];
    [m replaceOccurrencesOfString:@"&amp;" withString:@"&" options:0 range:NSMakeRange(0, m.length)];
    [m replaceOccurrencesOfString:@"&lt;" withString:@"<" options:0 range:NSMakeRange(0, m.length)];
    [m replaceOccurrencesOfString:@"&gt;" withString:@">" options:0 range:NSMakeRange(0, m.length)];
    [m replaceOccurrencesOfString:@"&quot;" withString:@"\"" options:0 range:NSMakeRange(0, m.length)];
    return m;
}

// ── 记录存储（结构化，按会话分组）─────────────────────────────
static dispatch_queue_t g_ymEmojiQueue = nil;
static NSMutableArray<NSMutableDictionary *> *g_ymEmojiRecords = nil;
static NSMutableSet<NSString *> *g_ymEmojiSeen = nil;

static void YMEmojiStoreInit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_ymEmojiQueue = dispatch_queue_create("ym.emoji.src", DISPATCH_QUEUE_SERIAL);
        g_ymEmojiRecords = [NSMutableArray array];
        g_ymEmojiSeen = [NSMutableSet set];
        NSArray *loaded = [NSArray arrayWithContentsOfFile:kYMEmojiSourceStorePath];
        NSTimeInterval cut = [[NSDate date] timeIntervalSince1970] - kYMEmojiRetentionSeconds;
        for (NSDictionary *r in loaded) {
            if ([r[@"t"] doubleValue] < cut) { continue; }
            [g_ymEmojiRecords addObject:[r mutableCopy]];
            NSString *k = r[@"md5"];
            if (k.length) { [g_ymEmojiSeen addObject:k]; }
        }
    });
}

// WeChatIntercept 原版页面样式（按用户/群分两列、可折叠、点击下载 .gif）。
static NSString * const kYMEmojiCSS = @"<style>"
    "body{font-family:-apple-system,Helvetica,Arial,sans-serif;background:#f0f2f5;margin:0;padding:14px;}"
    "h1{font-size:15px;color:#555;margin:4px 0 12px;}"
    ".cols{display:flex;gap:14px;align-items:flex-start;}"
    ".col{flex:1;min-width:0;}"
    ".colh{position:sticky;top:0;font-size:13px;font-weight:600;color:#fff;padding:6px 10px;border-radius:8px;margin-bottom:6px;}"
    ".colh.priv{background:#3498db;}.colh.grp{background:#e67e22;}"
    ".empty{color:#bbb;font-size:13px;padding:10px;}"
    ".conv{background:#fff;border-radius:10px;margin:8px 0;padding:4px 10px 8px;box-shadow:0 1px 4px rgba(0,0,0,.08);}"
    ".conv>summary{cursor:pointer;font-weight:600;color:#222;padding:6px 2px;font-size:14px;list-style:none;}"
    ".top{position:sticky;top:0;z-index:5;background:#07c160;color:#fff;padding:10px 16px;border-radius:0 0 12px 12px;box-shadow:0 2px 8px rgba(0,0,0,.12);margin:-14px -14px 12px;}"
    ".top h1{margin:0;font-size:17px;color:#fff;}.sub{font-size:12px;opacity:.9;margin-top:2px;}"
    "summary{display:flex;align-items:center;gap:8px;}summary::-webkit-details-marker{display:none;}"
    "summary::before{content:'\\25B8';color:#bbb;transition:.15s;}details[open]>summary::before{transform:rotate(90deg);}"
    ".cn{font-weight:600;color:#222;font-size:14px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}"
    ".cmeta{color:#9aa0a6;font-size:12px;font-weight:400;}"
    ".grid{display:flex;flex-wrap:wrap;gap:8px;padding:4px 0 2px;}"
    ".it{display:flex;flex-direction:column;align-items:center;}"
    ".ph{display:block;border-radius:8px;overflow:hidden;border:1px solid #eee;background:#fff;transition:.15s;cursor:pointer;}"
    ".ph:hover{transform:scale(1.04);box-shadow:0 3px 10px rgba(0,0,0,.15);}"
    ".ph img{max-height:104px;max-width:130px;display:block;}"
    ".cap{font-size:10px;color:#9aa0a6;margin-top:3px;text-align:center;max-width:130px;}.cap b{color:#e67e22;font-weight:600;}"
    ".bar{display:flex;align-items:center;gap:8px;margin-top:7px;}"
    ".rb{background:rgba(255,255,255,.25);color:#fff;border:0;border-radius:6px;padding:4px 11px;font-size:12px;cursor:pointer;}"
    ".rb:hover{background:rgba(255,255,255,.42);}"
    ".rl{font-size:12px;opacity:.9;}"
    ".rs{font-size:12px;border-radius:6px;border:0;padding:3px 6px;background:#fff;color:#222;cursor:pointer;}"
    ".rc{font-size:12px;opacity:.85;min-width:42px;}"
    "a{color:#2d6cdf;}</style>";

static NSString * const kYMEmojiJS = @"<script>"
    "function dl(u,n){try{fetch(u).then(function(r){return r.blob()}).then(function(b){"
    "var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=n;"
    "document.body.appendChild(a);a.click();a.remove();"
    "setTimeout(function(){URL.revokeObjectURL(a.href)},2000);}).catch(function(){window.open(u)})}"
    "catch(e){window.open(u)}return false;}"
    // 刷新控制：手动(关) / 选间隔自动刷新，选择记 localStorage，带倒计时。
    "var RK='wxri';function setRi(v){localStorage.setItem(RK,v);applyRi();}"
    "function applyRi(){var v=localStorage.getItem(RK);if(v===null)v='5';"
    "var sel=document.getElementById('ri');if(sel)sel.value=v;"
    "if(window._t)clearInterval(window._t);var n=+v;var rc=document.getElementById('rc');"
    "if(n>0){var left=n;if(rc)rc.textContent='('+left+'s)';"
    "window._t=setInterval(function(){left--;if(rc)rc.textContent='('+left+'s)';"
    "if(left<=0){location.reload();}},1000);}else if(rc){rc.textContent='手动';}}"
    "var K='wxsrc';function S(){try{return JSON.parse(localStorage.getItem(K)||'{}')}catch(e){return{}}}"
    "addEventListener('DOMContentLoaded',function(){var s=S();"
    "document.querySelectorAll('details[data-k]').forEach(function(d){"
    "if(d.dataset.k in s){d.open=s[d.dataset.k];}"
    "d.addEventListener('toggle',function(){var o=S();o[d.dataset.k]=d.open;localStorage.setItem(K,JSON.stringify(o));});});"
    "var y=sessionStorage.wxy;if(y)scrollTo(0,+y);"
    "addEventListener('scroll',function(){sessionStorage.wxy=scrollY;});applyRi();});</script>";

static NSString *YMEmojiTsShort(NSString *ts) {
    // "yyyy-MM-dd HH:mm:ss" → "MM-dd HH:mm"
    if (ts.length >= 16) {
        return [ts substringWithRange:NSMakeRange(5, 11)];
    }
    return ts ?: @"";
}

// 单个会话 → <details> 折叠块 + 表情网格。
static NSString *YMEmojiConvHTML(NSArray<NSDictionary *> *items) {
    NSArray *its = [items sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [b[@"t"] compare:a[@"t"]];
    }];
    NSMutableString *cells = [NSMutableString string];
    NSUInteger n = 0;
    for (NSDictionary *r in its) {
        if (n++ >= 120) { break; }
        NSString *u = r[@"url"];
        NSString *nm = YMHTMLEscape(r[@"name"]);
        NSString *media = [NSString stringWithFormat:
            @"<a class=\"ph\" href=\"%@\" title=\"点击下载.gif / 右键存图\" "
            @"onclick=\"return dl('%@','%@')\"><img src=\"%@\" loading=\"lazy\" "
            @"onerror=\"this.style.display='none'\"></a>", u, u, nm, u];
        NSString *by = ([r[@"group"] boolValue] && [r[@"nick"] length])
            ? [NSString stringWithFormat:@"<b>%@</b> ", YMHTMLEscape(r[@"nick"])] : @"";
        [cells appendFormat:@"<div class=\"it\">%@<div class=\"cap\">%@%@</div></div>",
                            media, by, YMHTMLEscape(YMEmojiTsShort(r[@"ts"]))];
    }
    NSDictionary *first = its.firstObject;
    return [NSString stringWithFormat:
        @"<details class=\"conv\" data-k=\"%@\" open><summary><span class=\"cn\">%@</span>"
        @"<span class=\"cmeta\">%lu · %@</span></summary><div class=\"grid\">%@</div></details>",
        YMHTMLEscape(first[@"ckey"]), YMHTMLEscape(first[@"clabel"]),
        (unsigned long)its.count, YMHTMLEscape(YMEmojiTsShort(first[@"ts"])), cells];
}

// 重生成整页 HTML（在串行队列上调用）。
static void YMEmojiWriteHTMLLocked(void) {
    NSMutableDictionary<NSString *, NSMutableArray *> *convs = [NSMutableDictionary dictionary];
    for (NSDictionary *r in g_ymEmojiRecords) {
        NSString *ck = r[@"ckey"] ?: @"未知";
        NSMutableArray *arr = convs[ck];
        if (!arr) { arr = [NSMutableArray array]; convs[ck] = arr; }
        [arr addObject:r];
    }
    NSMutableArray *privs = [NSMutableArray array];
    NSMutableArray *grps = [NSMutableArray array];
    for (NSArray *v in convs.allValues) {
        if ([v.firstObject[@"group"] boolValue]) { [grps addObject:v]; }
        else { [privs addObject:v]; }
    }
    NSComparator latest = ^NSComparisonResult(NSArray *a, NSArray *b) {
        double ta = 0, tb = 0;
        for (NSDictionary *r in a) { ta = MAX(ta, [r[@"t"] doubleValue]); }
        for (NSDictionary *r in b) { tb = MAX(tb, [r[@"t"] doubleValue]); }
        return tb > ta ? NSOrderedDescending : (tb < ta ? NSOrderedAscending : NSOrderedSame);
    };
    [privs sortUsingComparator:latest];
    [grps sortUsingComparator:latest];

    NSMutableString *privHTML = [NSMutableString string];
    for (NSArray *v in privs) { [privHTML appendString:YMEmojiConvHTML(v)]; }
    NSMutableString *grpHTML = [NSMutableString string];
    for (NSArray *v in grps) { [grpHTML appendString:YMEmojiConvHTML(v)]; }
    if (privHTML.length == 0) { [privHTML appendString:@"<div class=\"empty\">暂无</div>"]; }
    if (grpHTML.length == 0) { [grpHTML appendString:@"<div class=\"empty\">暂无</div>"]; }

    NSMutableString *html = [NSMutableString string];
    [html appendString:@"<!doctype html><html><head><meta charset=\"utf-8\"><title>微信表情源</title>"];
    [html appendString:kYMEmojiCSS];
    [html appendString:@"</head><body>"];
    [html appendFormat:@"<div class=\"top\"><h1>📨 微信表情源</h1>"
                       @"<div class=\"sub\">表情/动图GIF · 保留7天 · 共 %lu 条</div>"
                       @"<div class=\"bar\"><button class=\"rb\" onclick=\"location.reload()\">↻ 手动刷新</button>"
                       @"<span class=\"rl\">自动刷新</span>"
                       @"<select id=\"ri\" class=\"rs\" onchange=\"setRi(this.value)\">"
                       @"<option value=\"0\">关</option><option value=\"3\">3秒</option>"
                       @"<option value=\"5\">5秒</option><option value=\"10\">10秒</option>"
                       @"<option value=\"30\">30秒</option><option value=\"60\">60秒</option></select>"
                       @"<span id=\"rc\" class=\"rc\"></span></div></div>",
                       (unsigned long)g_ymEmojiRecords.count];
    [html appendString:@"<div class=\"cols\">"];
    [html appendFormat:@"<div class=\"col\"><div class=\"colh priv\">👤 私聊 · %lu</div>%@</div>",
                       (unsigned long)privs.count, privHTML];
    [html appendFormat:@"<div class=\"col\"><div class=\"colh grp\">👥 群聊 · %lu</div>%@</div>",
                       (unsigned long)grps.count, grpHTML];
    [html appendString:@"</div>"];
    [html appendString:kYMEmojiJS];
    [html appendString:@"</body></html>"];

    [html writeToFile:kYMEmojiSourceHTMLPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

// url 是否"形态完整、能从 CDN 加载"。内存里有干净副本和残缺副本（渲染缓存），
// 残缺副本缺 & 分隔或带 &amp; → CDN 返回 400 → 图加载不出来。只收干净的。
static BOOL YMEmojiURLLoadable(NSString *u) {
    if (u.length < 16 || ![u hasPrefix:@"http"]) {
        return NO;
    }
    if ([u containsString:@"&amp;"]) {
        return NO;   // 没正确反转义
    }
    if ([u containsString:@"filekey="]) {
        // stodownload 型必须带正确的 & 分隔尾参，否则是残缺副本（参数被粘连）。
        if (![u containsString:@"&hy="] && ![u containsString:@"&bizid="] &&
            ![u containsString:@"&storeid="]) {
            return NO;
        }
    }
    return YES;
}

// 选一个"能加载"的 url（优先 cdnurl→thumburl→externurl），都不行返回 nil。
static NSString *YMEmojiPickLoadableURL(NSString *tag) {
    NSArray<NSString *> *keys = @[@"cdnurl", @"thumburl", @"externurl"];
    for (NSString *k in keys) {
        NSString *u = YMEmojiUnescape(YMEmojiAttr(tag, k));
        if (YMEmojiURLLoadable(u)) {
            return u;
        }
    }
    return nil;
}

// ── 昵称/群名解析（内存探针：找 id 联系人对象的相邻"名字"字段）──────────────
static NSMutableSet<NSString *> *g_ymNameTried = nil;

static BOOL YMLooksLikeName(NSString *s) {
    if (s.length < 2 || s.length > 32) {
        return NO;
    }
    if ([s hasPrefix:@"wxid_"] || [s hasPrefix:@"http"]) {
        return NO;
    }
    if ([s rangeOfCharacterFromSet:
            [NSCharacterSet characterSetWithCharactersInString:@"<>=/\\\"{}@&%?:;.,"]].location != NSNotFound) {
        return NO;
    }
    BOOL hasCJK = NO, hasDigit = NO, hasLetter = NO;
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];
        if (c < 0x20) {
            return NO;   // 控制字符 → 不是名字
        } else if (c >= 0x4E00 && c <= 0x9FFF) {
            hasCJK = YES;
        } else if (c >= '0' && c <= '9') {
            hasDigit = YES;
        } else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            hasLetter = YES;
        }
    }
    // 接受：含中文(昵称多为中文)；或 纯字母无数字且≥4(英文名)。排除 "Y"/"a21" 这类。
    if (hasCJK) {
        return YES;
    }
    if (hasLetter && !hasDigit && s.length >= 4) {
        return YES;
    }
    return NO;
}

// 在内存里探测 idStr(wxid/roomid) 对应的昵称/群名；找不到返回 nil。
static NSString *YMProbeName(NSString *idStr) {
    const char *needle = [idStr UTF8String];
    if (!needle) {
        return nil;
    }
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > 64) {
        return nil;
    }
    mach_port_t task = mach_task_self();
    mach_vm_address_t addr = 0;
    const size_t CHUNK = 4 * 1024 * 1024;
    char *buf = (char *)malloc(CHUNK);
    if (!buf) {
        return nil;
    }
    uint64_t scanned = 0;
    const uint64_t BUDGET = 2200ULL * 1024 * 1024;
    // 频次统计：相邻的"像名字"候选出现次数。真昵称(联系人对象+各处引用)会反复出现，
    // 随机垃圾只出现一两次。最后取出现最多且达阈值的。
    NSMutableDictionary<NSString *, NSNumber *> *counts = [NSMutableDictionary dictionary];

    while (scanned < BUDGET) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objName = MACH_PORT_NULL;
        if (mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &cnt, &objName) != KERN_SUCCESS) {
            break;
        }
        mach_vm_address_t rs = addr, re = addr + size;
        addr = re;
        if (!((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) ||
            size == 0 || size > 96 * 1024 * 1024) {
            continue;
        }
        mach_vm_address_t off = rs;
        while (off < re) {
            size_t want = (size_t)MIN((mach_vm_address_t)CHUNK, re - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(task, off, want, (mach_vm_address_t)buf, &got) != KERN_SUCCESS || got == 0) {
                break;
            }
            scanned += got;
            size_t pos = 0;
            while (pos + nlen <= (size_t)got) {
                void *hit = memmem(buf + pos, (size_t)got - pos, needle, nlen);
                if (!hit) {
                    break;
                }
                size_t hoff = (char *)hit - buf;
                mach_vm_address_t live = off + hoff;   // id 字符数据的活地址
                // 若该处是 SSO std::string 对象起点，相邻 +24/+48/.. 是同对象其它字段(含昵称)。
                for (int slot = 1; slot <= 6; slot++) {
                    NSString *cand = YMNSStringFromLibcppStringObject((const void *)(live + 24 * slot));
                    if (YMLooksLikeName(cand)) {
                        counts[cand] = @([counts[cand] intValue] + 1);
                    }
                }
                pos = hoff + 1;
            }
            if ((size_t)got < want) {
                break;
            }
            off += (got > 16384 ? got - 16384 : got);
        }
    }
    free(buf);

    NSString *best = nil;
    int bestN = 0;
    for (NSString *k in counts) {
        int n = [counts[k] intValue];
        if (n > bestN) { bestN = n; best = k; }
    }
    return bestN >= 3 ? best : nil;   // 达到频次阈值才采信，否则回退显示 id
}

// 后台解析 ckey→名字；解析到就更新该会话所有记录的 clabel 并重生成页面（每个 id 只试一次）。
static void YMEmojiResolveCkeyAsync(NSString *ckey) {
    if (ckey.length == 0 || [ckey isEqualToString:@"未知"]) {
        return;
    }
    dispatch_async(g_ymEmojiQueue, ^{
        if (!g_ymNameTried) {
            g_ymNameTried = [NSMutableSet set];
        }
        if ([g_ymNameTried containsObject:ckey]) {
            return;
        }
        [g_ymNameTried addObject:ckey];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            @autoreleasepool {
                NSString *name = YMProbeName(ckey);
                if (name.length == 0) {
                    return;
                }
                dispatch_async(g_ymEmojiQueue, ^{
                    BOOL changed = NO;
                    for (NSMutableDictionary *r in g_ymEmojiRecords) {
                        if ([r[@"ckey"] isEqualToString:ckey]) {
                            r[@"clabel"] = name;
                            changed = YES;
                        }
                    }
                    if (changed) {
                        [g_ymEmojiRecords writeToFile:kYMEmojiSourceStorePath atomically:YES];
                        YMEmojiWriteHTMLLocked();
                        YMLog(@"[EmojiScan] resolved name %@ -> %@", ckey, name);
                    }
                });
            }
        });
    });
}

// 解析一个 <emoji> 标签 → 抽字段 → 分组 → 去重 → 入库 → 重生成页面。
static void YMEmojiAppendFromTag(NSString *tag) {
    if (tag.length == 0) {
        return;
    }
    NSString *md5        = YMEmojiAttr(tag, @"md5");
    NSString *fromUser   = YMEmojiAttr(tag, @"fromusername");
    NSString *toUser     = YMEmojiAttr(tag, @"tousername");

    // 只接受 url 形态完整(可加载)的副本；残缺副本直接跳过(不锁 md5，留给干净副本)。
    NSString *url = YMEmojiPickLoadableURL(tag);
    if (url.length == 0) {
        return;
    }

    YMEmojiStoreInit();
    dispatch_async(g_ymEmojiQueue, ^{
        @autoreleasepool {
            NSString *key = md5.length ? md5 : url;
            if ([g_ymEmojiSeen containsObject:key]) {
                return;   // 同一张表情(同 md5)已记录
            }
            [g_ymEmojiSeen addObject:key];

            BOOL isGroup = [toUser containsString:@"@chatroom"] || [fromUser containsString:@"@chatroom"];
            NSString *ckey = isGroup ? toUser : (fromUser.length ? fromUser : @"未知");
            NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
            NSString *name = [NSString stringWithFormat:@"%@.gif",
                              md5.length ? [md5 substringToIndex:MIN((NSUInteger)20, md5.length)] : @"emoji"];

            NSMutableDictionary *r = [@{
                @"t": @(now),
                @"ts": YMFormatTimestamp((uint32_t)now, 0),
                @"ckey": ckey,
                @"clabel": ckey,
                @"group": @(isGroup),
                @"nick": fromUser ?: @"",
                @"url": url,
                @"md5": md5 ?: @"",
                @"name": name,
            } mutableCopy];
            [g_ymEmojiRecords addObject:r];

            // 昵称/群名解析已停用（启发式不可靠，避免每个新会话白扫内存）。直接显示 id。
            // 如需恢复：取消下行注释（YMProbeName 频次法仍在）。
            // YMEmojiResolveCkeyAsync(ckey);

            // 保留 7 天
            NSTimeInterval cut = now - kYMEmojiRetentionSeconds;
            NSMutableArray *keep = [NSMutableArray array];
            for (NSDictionary *x in g_ymEmojiRecords) {
                if ([x[@"t"] doubleValue] >= cut) { [keep addObject:x]; }
            }
            [g_ymEmojiRecords setArray:keep];

            [g_ymEmojiRecords writeToFile:kYMEmojiSourceStorePath atomically:YES];
            YMEmojiWriteHTMLLocked();
            YMLog(@"[EmojiScan] emoji md5=%@ group=%d ckey=%@ url=%@", md5, isGroup, ckey, url);
        }
    });
}

// 扫描本进程可写堆内存一遍，找所有 <emoji ...> 标签（mach_vm_read_overwrite 只读，安全）。
static void YMEmojiScanMemoryOnce(void) {
    mach_port_t task = mach_task_self();
    mach_vm_address_t addr = 0;
    const size_t CHUNK = 8 * 1024 * 1024;
    const size_t OVERLAP = 16 * 1024;       // 重叠，避免标签跨 chunk 被截断
    char *buf = (char *)malloc(CHUNK);
    if (!buf) {
        return;
    }
    uint64_t scanned = 0;
    // 覆盖全堆：表情可能落在很高地址的区域（搜索/转发发送、快速连发都会到 1.8GB 之外），
    // 预算太小会漏。实测微信可写堆约 3-4GB，这里给足。区域上限 256MB(放过中等堆，仍跳超大缓存)。
    const uint64_t BUDGET = 6000ULL * 1024 * 1024;

    while (scanned < BUDGET) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objName = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &cnt, &objName);
        if (kr != KERN_SUCCESS) {
            break;
        }
        mach_vm_address_t regStart = addr;
        mach_vm_address_t regEnd = addr + size;
        addr = regEnd;   // 下一区域

        BOOL rw = (info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE);
        if (!rw || size == 0 || size > 256 * 1024 * 1024) {
            continue;   // 只扫可读写堆，跳过超大区域（图片/缓存几乎不含小 XML）
        }

        mach_vm_address_t off = regStart;
        while (off < regEnd) {
            size_t want = (size_t)MIN((mach_vm_address_t)CHUNK, regEnd - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(task, off, want,
                                       (mach_vm_address_t)buf, &got) != KERN_SUCCESS || got == 0) {
                break;
            }
            scanned += got;
            size_t pos = 0;
            while (pos + 6 <= (size_t)got) {
                void *hit = memmem(buf + pos, (size_t)got - pos, "<emoji", 6);
                if (!hit) {
                    break;
                }
                size_t hoff = (char *)hit - buf;
                NSString *tag = YMEmojiTagFromBuffer(buf, (size_t)got, hoff);
                if (tag) {
                    @autoreleasepool { YMEmojiAppendFromTag(tag); }
                }
                pos = hoff + 6;
            }
            if ((size_t)got < want) {
                break;
            }
            off += (got > OVERLAP ? got - OVERLAP : got);   // 重叠步进
        }
    }
    free(buf);
}

#pragma mark - 表情包信息源：一次性 inline hook + trampoline（已停用，保留备查）

/*
 入口被覆盖的位置无关 prologue 字节数 = 绝对跳转字节数：
   x86_64: movabs r11,imm64(10) + jmp r11(3) = 13B，恰好覆盖
           push rbp;mov rbp,rsp;push r14;push rbx;mov rbx,rsi;mov r14,rdi（到 0x..91d 边界，
           下一条 call 完整保留）。
   arm64 : ldr x16,#8;br x16;.quad(16) = 16B，恰好覆盖前 4 条 stp/add/mov（到 bl 边界）。
*/
#if defined(__x86_64__)
static const size_t kYMEmojiPrologueBytes = 13;
#elif defined(__arm64__) || defined(__aarch64__)
static const size_t kYMEmojiPrologueBytes = 16;
#endif

// 无 NOP 填充的绝对跳转，返回字节数（x86 13 / arm64 16）。
static size_t YMEmitAbsoluteJumpNoPad(uintptr_t target, uint8_t *out) {
#if defined(__x86_64__)
    out[0] = 0x49; out[1] = 0xBB;            // movabs r11, imm64
    memcpy(out + 2, &target, sizeof(target));
    out[10] = 0x41; out[11] = 0xFF; out[12] = 0xE3;  // jmp r11
    return 13;
#elif defined(__arm64__) || defined(__aarch64__)
    uint32_t ldr = 0x58000050, br = 0xD61F0200;  // ldr x16,#8 ; br x16
    memcpy(out + 0, &ldr, 4);
    memcpy(out + 4, &br, 4);
    memcpy(out + 8, &target, 8);
    return 16;
#endif
}

// ── 一次性诊断：定位消息内容真正落在哪个入参/偏移（前 N 次调用，限量，事后自停）──
static std::atomic<int> YMEmojiDiagCalls(0);

static void YMEmojiDiagDump(void *obj, const char *tag) {
    if (!obj) {
        return;
    }
    for (size_t off = 0; off + 24 <= 768; off += 8) {
        NSString *v = YMNSStringFromLibcppStringObject((uint8_t *)obj + off);
        if (v.length == 0) {
            continue;
        }
        NSString *low = v.lowercaseString;
        if ([low containsString:@"emoji"] || [low containsString:@"cdnurl"] ||
            [low containsString:@"<msg"] || [low containsString:@"<sysmsg"] ||
            [low containsString:@"<appmsg"] || [low containsString:@"wxid_"] ||
            [low containsString:@".gif"] || [low containsString:@"emoticon"] ||
            [low containsString:@"aeskey"] || [low containsString:@"<emoji"]) {
            NSString *snip = v.length > 240 ? [v substringToIndex:240] : v;
            YMLog(@"[EmojiDiag] %s +%zu len=%lu: %@", tag, off, (unsigned long)v.length, snip);
        }
    }
}

static int64_t YMEmojiMsgHandlerHook(int64_t a0, int64_t a1, int64_t a2,
                                     int64_t a3, int64_t a4, int64_t a5) {
    // 只读观察（不改参数），命中表情即记录。trampoline=原函数行为，放行。
    static __thread int inHook = 0;
    if (!inHook) {
        inHook = 1;
        @autoreleasepool {
            try {
                int n = YMEmojiDiagCalls.fetch_add(1);
                if (n < 400) {
                    // 头 400 次调用：把含消息特征串的入参/偏移打出来，定位内容真实落点。
                    YMEmojiDiagDump((void *)a1, "a1");
                    YMEmojiDiagDump((void *)a0, "a0");
                    YMEmojiDiagDump((void *)a2, "a2");
                }
                if (n % 1000 == 0) {
                    YMLog(@"[EmojiDiag] handler fired count=%d", n);
                }
                // 原始消息在 a1(rsi/x1)；保险起见 a1 不中再试 a0。
                if (!YMEmojiCaptureFromWrap((void *)a1)) {
                    YMEmojiCaptureFromWrap((void *)a0);
                }
            } catch (...) {}
        }
        inHook = 0;
    }
    if (!YMEmojiTrampoline) {
        return 0;
    }
    return ((YMEmojiMsgHandlerFunc)YMEmojiTrampoline)(a0, a1, a2, a3, a4, a5);
}

// 分配可执行 trampoline：[原 prologue 字节][绝对跳转回 原入口+prologue]。
static uintptr_t YMEmojiBuildTrampoline(uintptr_t funcEntry) {
    size_t total = kYMEmojiPrologueBytes + 16;   // prologue + 一条绝对跳转(最多16B)
    vm_address_t mem = 0;
    if (vm_allocate(mach_task_self(), &mem, total, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        return 0;
    }
    uint8_t *p = (uint8_t *)mem;
    memcpy(p, (const void *)funcEntry, kYMEmojiPrologueBytes);       // 原 prologue
    YMEmitAbsoluteJumpNoPad(funcEntry + kYMEmojiPrologueBytes,
                            p + kYMEmojiPrologueBytes);              // 跳回续跑点
    if (vm_protect(mach_task_self(), mem, total, false,
                   VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) {
        vm_deallocate(mach_task_self(), mem, total);
        return 0;
    }
    sys_icache_invalidate((void *)mem, total);
    return (uintptr_t)mem;
}

static void YMInstallEmojiSourcePatch(void) {
    if (YMEmojiTrampoline) {
        return;   // 已安装
    }
    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();
    if (!profile || profile->emojiMsgHandlerVA == 0) {
        YMLog(@"[EmojiSource] emojiMsgHandlerVA is 0, skip safely");
        return;
    }
    uintptr_t addr = YMRuntimeAddress(profile->emojiMsgHandlerVA);
    if (addr == 0) {
        YMLog(@"[EmojiSource] runtime address 0 (slide not ready), skip");
        return;
    }

    uintptr_t tramp = YMEmojiBuildTrampoline(addr);
    if (!tramp) {
        YMLog(@"[EmojiSource] build trampoline failed");
        return;
    }

    // 入口一次性打绝对跳转到 hook（之后再不动它，零 per-call 开销）。
    uint8_t patch[16] = {0};
    size_t n = YMEmitAbsoluteJumpNoPad((uintptr_t)&YMEmojiMsgHandlerHook, patch);
    if (!YMGroupExitWriteCodeBytes(addr, patch, n, "emoji handler", "install inline hook")) {
        YMLog(@"[EmojiSource] install inline hook failed");
        vm_deallocate(mach_task_self(), (vm_address_t)tramp, kYMEmojiPrologueBytes + 16);
        return;
    }
    YMEmojiTrampoline = tramp;
    YMEmojiMsgHandlerRuntimeAddress = addr;
    YMLog(@"[EmojiSource] installed(inline+trampoline) entry=0x%lx tramp=0x%lx",
          (unsigned long)addr, (unsigned long)tramp);
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

#pragma mark - URL 外部浏览器 Patch

static BOOL YMOpenURLRestoreOriginalWebViewKind(void) {
    if (!YMOpenURLWebViewKindRuntimeAddress || !YMOpenURLWebViewKindHasSavedOriginalBytes) {
        return NO;
    }

    return YMGroupExitWriteCodeBytes(YMOpenURLWebViewKindRuntimeAddress,
                                     YMOpenURLWebViewKindOriginalBytes,
                                     sizeof(YMOpenURLWebViewKindOriginalBytes),
                                     "open url GetUrlWebViewKind",
                                     "restore original");
}

static BOOL YMOpenURLReapplyWebViewKindHook(void) {
    if (!YMOpenURLWebViewKindRuntimeAddress) {
        return NO;
    }

    return YMGroupExitWriteCodeBytes(YMOpenURLWebViewKindRuntimeAddress,
                                     YMOpenURLWebViewKindHookBytes,
                                     sizeof(YMOpenURLWebViewKindHookBytes),
                                     "open url GetUrlWebViewKind",
                                     "reapply hook");
}

static int64_t YMOpenURLCallOriginalWebViewKind(void *a1, int64_t a2, int a3, int64_t a4) {
    if (!YMOpenURLWebViewKindRuntimeAddress) {
        return 0;
    }

    if (YMOpenURLCallingOriginalWebViewKind.exchange(true)) {
        YMLog(@"[OpenURLSystemBrowser] recursive original GetUrlWebViewKind call suppressed");
        return 0;
    }

    BOOL restored = YMOpenURLRestoreOriginalWebViewKind();
    if (!restored) {
        YMLog(@"[OpenURLSystemBrowser] restore original GetUrlWebViewKind failed");
        YMOpenURLCallingOriginalWebViewKind.store(false);
        return 0;
    }

    YMOpenURLWebViewKindFunc Original = (YMOpenURLWebViewKindFunc)YMOpenURLWebViewKindRuntimeAddress;

    int64_t result = 0;
    try {
        result = Original(a1, a2, a3, a4);
    } catch (...) {
        YMLog(@"[OpenURLSystemBrowser] exception while calling original GetUrlWebViewKind");
    }

    YMOpenURLReapplyWebViewKindHook();
    YMOpenURLCallingOriginalWebViewKind.store(false);
    return result;
}

static NSString *YMOpenURLReadMaybeStdString(int64_t value) {
    if (value == 0 || (uintptr_t)value < 0x100000000ULL) {
        return @"";
    }

    NSString *text = YMNSStringFromLibcppStringObject((const void *)(uintptr_t)value);
    if (text.length > 0) {
        return text;
    }

    return @"";
}

static BOOL YMOpenURLTextHasAnyKeyword(NSString *text, NSArray<NSString *> *keywords) {
    if (text.length == 0 || keywords.count == 0) {
        return NO;
    }

    NSString *lower = text.lowercaseString;
    for (NSString *keyword in keywords) {
        if (keyword.length == 0) {
            continue;
        }
        if ([lower containsString:keyword.lowercaseString]) {
            return YES;
        }
    }

    return NO;
}

static BOOL YMOpenURLShouldKeepWeChatLogic(NSString *urlText, NSString *moduleText) {
    NSArray<NSString *> *internalKeywords = @[
        @"weixin://",
        @"wechat://",
        @"wxapp",
        @"wxa",
        @"appbrand",
        @"miniapp",
        @"miniprogram",
        @"servicewechat.com",
        @"wxawap",
        @"search.weixin",
        @"soso",
        @"sogou",
        @"game.weixin",
        @"gamecenter",
        @"channels.weixin",
        @"finder.weixin",
        @"mmfinder",
        @"finder",
        @"videochannel",
        @"channels",
        @"wechatgame"
    ];

    if (YMOpenURLTextHasAnyKeyword(urlText, internalKeywords) ||
        YMOpenURLTextHasAnyKeyword(moduleText, internalKeywords)) {
        return YES;
    }

    return NO;
}

static int64_t YMOpenURLWebViewKindHook(void *a1, int64_t a2, int a3, int64_t a4) {
    @autoreleasepool {
        int64_t originalKind = YMOpenURLCallOriginalWebViewKind(a1, a2, a3, a4);
        int64_t finalKind = originalKind;

        /*
         不能直接return 3,会导致小程序/搜一搜/游戏中心/视频号异常。
         */
        NSString *urlText = YMOpenURLReadMaybeStdString(a2);
        NSString *moduleText = YMOpenURLReadMaybeStdString(a4);

        BOOL looksLikeHTTP = [urlText.lowercaseString hasPrefix:@"http://"] ||
                             [urlText.lowercaseString hasPrefix:@"https://"];

        if (YMIsOpenURLWithSystemBrowserEnabled() &&
            originalKind == 0 &&
            looksLikeHTTP &&
            !YMOpenURLShouldKeepWeChatLogic(urlText, moduleText)) {
            finalKind = 3;
        }

        if (finalKind != originalKind || YMOpenURLShouldKeepWeChatLogic(urlText, moduleText)) {
            YMLog(@"[OpenURLSystemBrowser] GetUrlWebViewKind original=%lld final=%lld a3=%d url=%@ module=%@",
                  (long long)originalKind,
                  (long long)finalKind,
                  a3,
                  urlText ?: @"",
                  moduleText ?: @"");
        }

        return finalKind;
    }
}

static BOOL YMPatchOpenURLWithSystemBrowserWithSlide(intptr_t slide, NSString *source) {
    if (YMHasPatchedOpenURLWithSystemBrowser) {
        YMLog(@"open url system browser already patched, skip. source=%@", source ?: @"");
        return YES;
    }

    if (!YMIsTargetWeChatVersion()) {
        YMLog(@"open url system browser unsupported version, skip. source=%@", source ?: @"");
        return NO;
    }

    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();
    if (!profile || profile->openURLWebViewKindVA == 0) {
        YMLog(@"open url system browser address is zero, skip. profile=%s", profile ? profile->displayName : "NULL");
        return NO;
    }

    YMWeChatDylibSlide = (uintptr_t)slide;

    uintptr_t address = YMRuntimeAddress(profile->openURLWebViewKindVA);
    uintptr_t hookAddress = (uintptr_t)&YMOpenURLWebViewKindHook;

    YMLog(@"try install open url selective system browser patch from %@, profile=%s, slide=0x%lx, GetUrlWebViewKind=0x%lx, hook=0x%lx",
          source ?: @"",
          profile->displayName,
          (unsigned long)YMWeChatDylibSlide,
          (unsigned long)address,
          (unsigned long)hookAddress);

    if (address == 0 || hookAddress == 0) {
        YMLog(@"open url selective system browser patch failed: address/hook is zero");
        return NO;
    }

    YMOpenURLWebViewKindRuntimeAddress = address;
    YMGroupExitBuildAbsoluteJump(hookAddress, YMOpenURLWebViewKindHookBytes);

    uint8_t current[16] = {0};
    memcpy(current, (void *)address, sizeof(current));

    if (memcmp(current, YMOpenURLWebViewKindHookBytes, sizeof(current)) == 0) {
        YMLog(@"open url GetUrlWebViewKind already hooked, address=0x%lx", (unsigned long)address);
        YMOpenURLWebViewKindHasSavedOriginalBytes = YES;
        YMHasPatchedOpenURLWithSystemBrowser = YES;
        return YES;
    }

    memcpy(YMOpenURLWebViewKindOriginalBytes, current, sizeof(current));
    YMOpenURLWebViewKindHasSavedOriginalBytes = YES;

    BOOL ok = YMGroupExitWriteCodeBytes(address,
                                        YMOpenURLWebViewKindHookBytes,
                                        sizeof(YMOpenURLWebViewKindHookBytes),
                                        "open url GetUrlWebViewKind selective hook",
                                        "install hook");

    YMHasPatchedOpenURLWithSystemBrowser = ok;

    YMLog(@"open url selective system browser hook result=%@, address=0x%lx",
          ok ? @"OK" : @"FAIL",
          (unsigned long)address);

    return ok;
}

static BOOL YMFindAndPatchLoadedOpenURLWithSystemBrowserDylib(void) {
    uint32_t count = _dyld_image_count();

    YMLog(@"scan dyld images for open url system browser, count=%u", count);

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

        YMLog(@"found Resources/wechat.dylib for open url system browser: index=%u, slide=0x%lx, path=%@",
              i,
              (unsigned long)slide,
              imagePath);

        return YMPatchOpenURLWithSystemBrowserWithSlide(slide, @"dyld image scan");
    }

    YMLog(@"Resources/wechat.dylib not found for open url system browser");
    return NO;
}

static void YMInstallOpenURLWithSystemBrowserPatch(void) {
    if (YMHasPatchedOpenURLWithSystemBrowser) {
        return;
    }

    YMRegisterDyldCallbackIfNeeded();
    YMFindAndPatchLoadedOpenURLWithSystemBrowserDylib();
}


#pragma mark - tool
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

    if (YMIsOpenURLWithSystemBrowserEnabled()) {
        YMPatchOpenURLWithSystemBrowserWithSlide(vmaddr_slide, @"dyld add image callback");
    }

    if (YMIsGroupExitMonitorEnabled()) {
        YMPatchGroupExitMonitorWithSlide(vmaddr_slide, @"dyld add image callback");
    }

    if (YMIsAntiRevokeEnabled()) {
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
    if (!YMFeatureAntiUpdateEnabled) {
        YMLog(@"anti update disabled, skip");
        return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        YMDisableSparkleAutoUpdateDefaults();
        YMDisableSparkleByRuntimeHook();
    });
}

static void YMInstallAntiRevokeIfNeeded(void) {
    if (!YMIsAntiRevokeEnabled()) {
        YMLog(@"anti revoke disabled, skip");
        return;
    }

    YMRegisterDyldCallbackIfNeeded();
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

static void YMInstallGroupExitMonitorIfNeeded(void) {
    if (!YMIsGroupExitMonitorEnabled()) {
        YMLog(@"[GroupExitMonitor] disabled, skip");
        YMGroupExitClearRuntimeStateIfDisabled("constructor skip");
        return;
    }

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

static void YMInstallOpenURLWithSystemBrowserIfNeeded(void) {
    if (!YMIsOpenURLWithSystemBrowserEnabled()) {
        YMLog(@"open url system browser disabled, skip");
        return;
    }

    YMInstallOpenURLWithSystemBrowserPatch();

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        YMInstallOpenURLWithSystemBrowserPatch();
    });
}

// 独立解析 wechat.dylib slide（不依赖防撤回是否开启），再安装表情包信息源 hook。
static void YMEmojiResolveSlideIfNeeded(void) {
    if (YMWeChatDylibSlide != 0) {
        return;
    }
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) {
            continue;
        }
        NSString *imagePath = [NSString stringWithUTF8String:name];
        if (YMIsTargetWeChatResourceDylibPath(imagePath)) {
            YMWeChatDylibSlide = (uintptr_t)_dyld_get_image_vmaddr_slide(i);
            YMLog(@"[EmojiSource] resolved wechat.dylib slide=0x%lx", (unsigned long)YMWeChatDylibSlide);
            return;
        }
    }
}

static void YMInstallEmojiSourceIfNeeded(void) {
    // 进程内内存扫描方案：只读扫自己进程的堆找 <emoji>，不 hook、不改字节、不会崩，
    // 也不依赖微信版本/地址。启动后定时增量扫描（按 md5 去重）。
    static dispatch_source_t timer = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // 启动即用最新模板重生成一次页面（不必等新表情），保证打开就是新版页面/工具栏。
        YMEmojiStoreInit();
        dispatch_async(g_ymEmojiQueue, ^{ YMEmojiWriteHTMLLocked(); });

        dispatch_queue_t q = dispatch_queue_create("ym.emoji.scan", DISPATCH_QUEUE_SERIAL);
        timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
        // 启动 5 秒后开始，每 8 秒扫一轮。
        dispatch_source_set_timer(timer,
                                  dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                                  (uint64_t)(8 * NSEC_PER_SEC),
                                  (uint64_t)(1 * NSEC_PER_SEC));
        dispatch_source_set_event_handler(timer, ^{
            if (!g_ymEmojiCaptureEnabled) {
                return;   // 抓取关闭 → 跳过扫描(开销可忽略)
            }
            @autoreleasepool { YMEmojiScanMemoryOnce(); }
        });
        dispatch_resume(timer);
        YMLog(@"[EmojiScan] in-process memory scanner started (every 8s)");
    });
}

// 运行时开/关抓取(菜单调用, 不需重启微信)。开启时立即扫一遍提升响应。
// extern "C": 本文件是 .mm(C++), 而 MenuManager.m 是 .m(C 链接), 需 C 符号才能链上。
extern "C" void YMEmojiSetCaptureEnabled(BOOL enabled) {
    g_ymEmojiCaptureEnabled = enabled;
    YMLog(@"[EmojiScan] capture enabled=%d", enabled);
    if (enabled) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            @autoreleasepool { YMEmojiScanMemoryOnce(); }
        });
    }
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
    // 收消息流水线候选（来自撤回实机 trace 的共享 sync/message 层；普通收到的表情也会过）。
    // 目标：收一个表情→看哪个函数的某入参里能扫到 <emoji（=该函数持有消息对象，即正确 hook 点）。
    { "pipe_3feddc0", 0x3feddc0, 0, {0}, {0}, NO },
    { "pipe_3fdf410", 0x3fdf410, 0, {0}, {0}, NO },
    { "pipe_4006920", 0x4006920, 0, {0}, {0}, NO },
    { "pipe_403a080", 0x403a080, 0, {0}, {0}, NO },
    { "pipe_400e000", 0x400e000, 0, {0}, {0}, NO },
    // 撤回 handler 外层(收到撤回会走；普通消息分支邻近，args 可能也带消息对象)。
    { "h_2bd6250", 0x2bd6250, 0, {0}, {0}, NO },
    { "h_2bd62d0", 0x2bd62d0, 0, {0}, {0}, NO },
    { "h_2bd61b0", 0x2bd61b0, 0, {0}, {0}, NO },
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
            // 限量扫描（前若干次调用），避免持续拖慢。扫 a1..a3 的浅层 std::string 找 <emoji。
            if (seq < 6000) {
                uintptr_t slide = YMWeChatDylibSlide;
                const int64_t args[3] = {a1, a2, a3};
                for (int ai = 0; ai < 3; ai++) {
                    void *obj = (void *)args[ai];
                    if (!obj) {
                        continue;
                    }
                    for (size_t off = 0; off + 24 <= 640; off += 8) {
                        NSString *v = YMNSStringFromLibcppStringObject((uint8_t *)obj + off);
                        if (v.length == 0) {
                            continue;
                        }
                        NSString *low = v.lowercaseString;
                        if (![low containsString:@"<emoji"] && ![low containsString:@"cdnurl"]) {
                            continue;
                        }
                        // 命中！这个函数的 arg[ai]+off 持有表情消息对象 → 正确 hook 点。
                        void *bt[20];
                        int n = backtrace(bt, 20);
                        NSMutableString *chain = [NSMutableString string];
                        BOOL first = YES;
                        for (int i = 1; i < n; i++) {
                            uintptr_t rel = (uintptr_t)bt[i] - slide;
                            if (rel < kYMTextLo || rel > kYMTextHi) {
                                continue;
                            }
                            [chain appendFormat:@"%@0x%lx", (first ? @"" : @" <- "), (unsigned long)rel];
                            first = NO;
                        }
                        NSString *snip = v.length > 220 ? [v substringToIndex:220] : v;
                        YMLog(@"[EmojiHit] %s arg=%d off=%zu len=%lu bt: %@ : %@",
                              e->name, ai, off, (unsigned long)v.length, chain, snip);
                    }
                }
            }
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

#pragma mark - 开关

static void YMLoadFeatureSwitchesFromDefaults(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];

    NSString *loadFlag = [defaults objectForKey:kIsFirstLoad];
    if (loadFlag.length < 3) {
        [defaults setBool:YES forKey:kAntiUpdate];
        [defaults setObject:@"SOVIET" forKey:kIsFirstLoad];
    }

    YMFeatureAntiUpdateEnabled = [defaults boolForKey:kAntiUpdate];
    YMFeatureAntiRevokeEnabled = [defaults boolForKey:kAntiRevoke];
    YMFeatureGroupExitMonitorEnabled = [defaults boolForKey:kExitChatroom];
    YMFeatureOpenURLWithSystemBrowserEnabled = [defaults boolForKey:kUseSystemWeb];

    // 抓取表情包默认关闭(省开销)；用户可在菜单开启。
    [defaults registerDefaults:@{ kEmojiCapture: @NO }];
    g_ymEmojiCaptureEnabled = [defaults boolForKey:kEmojiCapture];
}

#pragma mark - Phase A 诊断：NSWorkspace openURL backtrace（定位 x86 GetUrlWebViewKind）
/*
 GetUrlWebViewKind 是 C++ 函数、无任何引用、加密串逐架构不同，静态定位失败。
 利用：链接消息右键"Open with Default Browser"→最终走 -[NSWorkspace openURL:]。
 swizzle 它(跨架构 ObjC)，打印 wechat.dylib 帧 backtrace。用户右键打开链接一次，
 日志里的 wechat 帧链就暴露 WeChat 的 URL-open / 浏览器处理代码，反推 GetUrlWebViewKind。
*/
static BOOL (*YMOrig_NSWorkspace_openURL)(id, SEL, id) = NULL;
static BOOL YMHook_NSWorkspace_openURL(id self, SEL _cmd, id url) {
    @autoreleasepool {
        void *bt[28];
        int n = backtrace(bt, 28);
        uintptr_t slide = YMWeChatDylibSlide;
        NSMutableString *chain = [NSMutableString string];
        for (int i = 1; i < n; i++) {
            uintptr_t rel = (uintptr_t)bt[i] - slide;
            if (slide && rel >= 0x15000 && rel <= 0x6d9c780) {
                [chain appendFormat:@"0x%lx ", (unsigned long)rel];
            }
        }
        YMLog(@"[OpenURLDiag] openURL:%@ | slide=0x%lx wechat-frames: %@",
              url, (unsigned long)slide, chain.length ? chain : @"(none)");
    }
    if (YMOrig_NSWorkspace_openURL) {
        return YMOrig_NSWorkspace_openURL(self, _cmd, url);
    }
    return NO;
}
// 通用：记录某 ObjC 方法调用时的 wechat 帧 backtrace（捕获左键点击→应用内浏览器路径）。
static void YMDiagLogBacktrace(const char *tag, id arg) {
    @autoreleasepool {
        void *bt[28]; int n = backtrace(bt, 28);
        uintptr_t slide = YMWeChatDylibSlide;
        NSMutableString *chain = [NSMutableString string];
        for (int i = 1; i < n; i++) {
            uintptr_t rel = (uintptr_t)bt[i] - slide;
            if (slide && rel >= 0x15000 && rel <= 0x6d9c780)
                [chain appendFormat:@"0x%lx ", (unsigned long)rel];
        }
        YMLog(@"[OpenURLDiag] %s arg=%@ | wechat-frames: %@", tag, arg, chain.length?chain:@"(none)");
    }
}
static IMP YMOrig_WKWebView_loadRequest = NULL;
static id YMHook_WKWebView_loadRequest(id self, SEL _cmd, id req) {
    YMDiagLogBacktrace("WKWebView.loadRequest:", [req respondsToSelector:@selector(URL)] ? [req performSelector:@selector(URL)] : req);
    return ((id(*)(id,SEL,id))YMOrig_WKWebView_loadRequest)(self,_cmd,req);
}
static IMP YMOrig_NSWC_showWindow = NULL;
static id YMHook_NSWC_showWindow(id self, SEL _cmd, id sender) {
    YMDiagLogBacktrace("NSWindowController.showWindow:", NSStringFromClass([self class]));
    return ((id(*)(id,SEL,id))YMOrig_NSWC_showWindow)(self,_cmd,sender);
}
static void YMSwizzleLog(const char *clsName, const char *selName, IMP newImp, IMP *origOut) {
    Class cls = objc_getClass(clsName);
    if (!cls) { YMLog(@"[OpenURLDiag] class %s not found", clsName); return; }
    Method m = class_getInstanceMethod(cls, sel_registerName(selName));
    if (!m) { YMLog(@"[OpenURLDiag] -[%s %s] not found", clsName, selName); return; }
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
    YMLog(@"[OpenURLDiag] hooked -[%s %s]", clsName, selName);
}
static void YMInstallOpenURLDiag(void) {
    static BOOL installed = NO;
    if (installed) return;
    installed = YES;
    // 1) 系统浏览器路径（右键 Open with Default Browser）
    Class ws = objc_getClass("NSWorkspace");
    Method m = ws ? class_getInstanceMethod(ws, sel_registerName("openURL:")) : NULL;
    if (m) { YMOrig_NSWorkspace_openURL=(BOOL(*)(id,SEL,id))method_getImplementation(m);
             method_setImplementation(m,(IMP)YMHook_NSWorkspace_openURL);
             YMLog(@"[OpenURLDiag] hooked -[NSWorkspace openURL:]"); }
    // 2) 左键点击→应用内浏览器路径（捕获调用 GetUrlWebViewKind 的 click handler）
    YMSwizzleLog("WKWebView", "loadRequest:", (IMP)YMHook_WKWebView_loadRequest, &YMOrig_WKWebView_loadRequest);
    YMSwizzleLog("NSWindowController", "showWindow:", (IMP)YMHook_NSWC_showWindow, &YMOrig_NSWC_showWindow);
}

__attribute__((constructor))
static void YMWeChatAntiRevokePatchEntry(void) {
    @autoreleasepool {
        YMLog(@"constructor called");

        YMLoadFeatureSwitchesFromDefaults();

        YMInstallMultiOpenPatch();

        // Phase A 诊断：仅当用户在菜单开启"使用系统浏览器"时安装(定位 x86 地址用)。
        if (YMIsOpenURLWithSystemBrowserEnabled()) {
            YMInstallOpenURLDiag();
        }

        YMInstallOpenURLWithSystemBrowserIfNeeded();
        YMInstallGroupExitMonitorIfNeeded();
        YMInstallAssistantMenu();
        YMInstallAntiUpdateIfNeeded();
        YMInstallAntiRevokeIfNeeded();
        YMInstallEmojiSourceIfNeeded();

        [YMAutoLogin startIfEnabled];
    }
}
