//
//  AutoLogin.m
//  SovietExtension
//
//  纯 AppKit 自动登陆。移植自 WeChatIntercept(patch.sh) 的自动登陆逻辑。
//

#import "AutoLogin.h"
#import "MenuManager.h"
#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>

#define YMAutoLoginLog(fmt, ...) NSLog(@"[YMAutoLogin] " fmt, ##__VA_ARGS__)

// 登录窗的尺寸上限：超过判定为主窗口，排除。
static const CGFloat kYMLoginWindowMaxWidth  = 420;
static const CGFloat kYMLoginWindowMaxHeight = 520;
// 启动后尝试次数与间隔（窗口/按钮可能稍后才就绪）。
static const NSInteger kYMAutoLoginMaxAttempts = 40;
static const NSTimeInterval kYMAutoLoginInterval = 0.7;

static BOOL gYMAutoLoginEnabled = NO;
static BOOL gYMAutoLoginDone = NO;

#pragma mark - 视图工具

// 递归收集窗口里所有子视图（登录按钮是自定义控件，非 NSButton）。
static void YMCollectViews(NSView *view, NSMutableArray<NSView *> *out) {
    if (!view) {
        return;
    }
    for (NSView *sub in [view subviews]) {
        [out addObject:sub];
        YMCollectViews(sub, out);
    }
}

// 取任意视图可见文案（安全）：title / attributedTitle / AX label / AX title / stringValue。
static NSString *YMViewLabel(NSView *view) {
    @try {
        if ([view respondsToSelector:@selector(title)]) {
            id title = [(id)view title];
            if ([title isKindOfClass:[NSString class]] && [title length]) {
                return title;
            }
        }
    } @catch (__unused id e) {}

    @try {
        if ([view respondsToSelector:@selector(attributedTitle)]) {
            NSAttributedString *attr = [(id)view attributedTitle];
            if ([attr isKindOfClass:[NSAttributedString class]] && attr.string.length) {
                return attr.string;
            }
        }
    } @catch (__unused id e) {}

    @try {
        NSString *ax = [view accessibilityLabel];
        if (ax.length) {
            return ax;
        }
    } @catch (__unused id e) {}

    @try {
        id ax = [view accessibilityTitle];
        if ([ax isKindOfClass:[NSString class]] && [ax length]) {
            return ax;
        }
    } @catch (__unused id e) {}

    @try {
        if ([view respondsToSelector:@selector(stringValue)]) {
            id value = [(id)view stringValue];
            if ([value isKindOfClass:[NSString class]] && [value length]) {
                return value;
            }
        }
    } @catch (__unused id e) {}

    return @"";
}

// 激活一个视图：优先无障碍 press（自定义按钮），否则 NSControl performClick。
static BOOL YMPressView(NSView *view) {
    @try {
        if ([view respondsToSelector:@selector(accessibilityPerformPress)]) {
            if ([view accessibilityPerformPress]) {
                return YES;
            }
        }
    } @catch (__unused id e) {}

    @try {
        if ([view isKindOfClass:[NSControl class]]) {
            [(NSControl *)view performClick:nil];
            return YES;
        }
    } @catch (__unused id e) {}

    return NO;
}

#pragma mark - 登录尝试

// Qt 登录窗：UI 由 Qt 绘制(QNSView)，无 AppKit 子控件可点。
// “Enter Weixin” 是默认按钮 → 向登录尺寸的 Qt 窗口发回车键触发登录。
static BOOL YMTryQtLoginEnter(void) {
    static BOOL seenLoginWindow = NO;

    NSWindow *loginWindow = nil;
    for (NSWindow *window in [NSApp windows]) {
        if (![window isVisible]) {
            continue;
        }
        NSRect frame = [window frame];
        NSString *cls = [NSString stringWithUTF8String:class_getName([window class])];
        BOOL looksQt = [cls hasPrefix:@"QNS"] || [cls rangeOfString:@"Qt"].location != NSNotFound;
        if (!looksQt) {
            continue;
        }
        if (frame.size.width > kYMLoginWindowMaxWidth ||
            frame.size.height > kYMLoginWindowMaxHeight) {
            continue;   // 排除主窗口，仅登录尺寸
        }
        loginWindow = window;
        break;
    }

    if (!loginWindow) {
        if (seenLoginWindow) {
            gYMAutoLoginDone = YES;
            YMAutoLoginLog(@"登录窗已消失，判定登录完成");
        }
        return NO;
    }

    seenLoginWindow = YES;
    YMAutoLoginLog(@"Qt 登录窗 %.0fx%.0f → 发回车",
                   [loginWindow frame].size.width, [loginWindow frame].size.height);
    [loginWindow makeKeyAndOrderFront:nil];

    NSInteger windowNumber = [loginWindow windowNumber];
    NSTimeInterval ts = [[NSProcessInfo processInfo] systemUptime];
    NSEvent *down = [NSEvent keyEventWithType:NSEventTypeKeyDown
                                     location:NSMakePoint(10, 10)
                                modifierFlags:0
                                    timestamp:ts
                                 windowNumber:windowNumber
                                      context:nil
                                   characters:@"\r"
                  charactersIgnoringModifiers:@"\r"
                                    isARepeat:NO
                                      keyCode:36];
    NSEvent *up = [NSEvent keyEventWithType:NSEventTypeKeyUp
                                   location:NSMakePoint(10, 10)
                              modifierFlags:0
                                  timestamp:ts
                               windowNumber:windowNumber
                                    context:nil
                                 characters:@"\r"
                charactersIgnoringModifiers:@"\r"
                                  isARepeat:NO
                                    keyCode:36];
    if (down) {
        [NSApp postEvent:down atStart:YES];
    }
    if (up) {
        [NSApp postEvent:up atStart:NO];
    }

    // 返回 NO 让定时器继续；登录窗消失后才置 done 收尾。
    return NO;
}

// 在所有可见窗口里找登录按钮并点击；找到并点击返回 YES。
static BOOL YMTryAutoLogin(void) {
    @autoreleasepool {
        if (!gYMAutoLoginEnabled || gYMAutoLoginDone || NSApp == nil) {
            return NO;
        }

        NSArray<NSString *> *wants = @[
            @"进入微信", @"登录", @"登 录", @"登錄", @"进入",
            @"Enter Weixin", @"Enter WeChat", @"Weixin", @"Log In", @"Login"
        ];

        for (NSWindow *window in [NSApp windows]) {
            if (![window isVisible]) {
                continue;
            }
            NSMutableArray<NSView *> *views = [NSMutableArray array];
            YMCollectViews([window contentView], views);
            if (views.count == 0) {
                continue;
            }
            for (NSView *view in views) {
                NSString *label = YMViewLabel(view);
                if (label.length == 0) {
                    continue;
                }
                for (NSString *want in wants) {
                    if ([label rangeOfString:want].location == NSNotFound) {
                        continue;
                    }
                    YMAutoLoginLog(@"命中 '%@' cls=%s → press",
                                   label, class_getName([view class]));
                    if (YMPressView(view)) {
                        YMAutoLoginLog(@"完成(press 成功)");
                        gYMAutoLoginDone = YES;
                        return YES;
                    }
                    YMAutoLoginLog(@"press 失败，继续找");
                }
            }
        }

        return YMTryQtLoginEnter();
    }
}

// 启动后反复尝试，命中或超时即停。
static void YMScheduleAutoLogin(NSInteger attemptsLeft) {
    if (attemptsLeft <= 0 || gYMAutoLoginDone || !gYMAutoLoginEnabled) {
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(kYMAutoLoginInterval * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (gYMAutoLoginDone || !gYMAutoLoginEnabled) {
            return;
        }
        if (!YMTryAutoLogin()) {
            YMScheduleAutoLogin(attemptsLeft - 1);
        } else {
            YMAutoLoginLog(@"完成");
        }
    });
}

#pragma mark - Public

@implementation YMAutoLogin

+ (BOOL)isEnabled {
    return [[NSUserDefaults standardUserDefaults] boolForKey:kAutoLogin];
}

+ (void)startIfEnabled {
    gYMAutoLoginEnabled = [self isEnabled];
    YMAutoLoginLog(@"startIfEnabled enabled=%d", gYMAutoLoginEnabled);
    if (!gYMAutoLoginEnabled) {
        return;
    }
    gYMAutoLoginDone = NO;
    dispatch_async(dispatch_get_main_queue(), ^{
        YMScheduleAutoLogin(kYMAutoLoginMaxAttempts);
    });
}

+ (void)setEnabled:(BOOL)enabled {
    gYMAutoLoginEnabled = enabled;
    if (enabled) {
        gYMAutoLoginDone = NO;
        dispatch_async(dispatch_get_main_queue(), ^{
            YMScheduleAutoLogin(kYMAutoLoginMaxAttempts);
        });
    }
}

@end
