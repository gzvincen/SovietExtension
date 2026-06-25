//
//  MenuManager.m
//  SovietExtension
//
//  Created by MustangYM on 2026/6/13.
//

#import "MenuManager.h"
#import "NSMenuItem+Action.h"
#import "NSMenu+Action.h"
#import "YMSwizzledHelper.h"
#import "AutoLogin.h"

@implementation MenuManager

#pragma mark - Singleton

+ (instancetype)shareInstance
{
    static MenuManager *share = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        share = [[self alloc] init];
    });
    return share;
}

#pragma mark - Public

- (void)initAssistantMenuItems
{
    NSMenuItem *antiUpdateMenu = [self ym_toggleMenuItemWithTitle:@"阻止更新"
                                                              key:kAntiUpdate
                                                           action:@selector(onAntiUpdate:)];
    
    NSMenuItem *antiRevokeMenu = [self ym_toggleMenuItemWithTitle:@"消息防撤回"
                                                              key:kAntiRevoke
                                                           action:@selector(onAntiRevoke:)];
    
    NSMenuItem *exitChatroomMenu = [self ym_toggleMenuItemWithTitle:@"退群监控"
                                                                key:kExitChatroom
                                                             action:@selector(onExitChatroom:)];
    
    NSMenuItem *useSystemWebMenu = [self ym_toggleMenuItemWithTitle:@"使用系统浏览器"
                                                                key:kUseSystemWeb
                                                             action:@selector(onUseSystemWeb:)];

    NSMenuItem *autoLoginMenu = [self ym_toggleMenuItemWithTitle:@"自动登陆"
                                                             key:kAutoLogin
                                                          action:@selector(onAutoLogin:)];

    NSMenuItem *viewEmojiSourceMenu = [NSMenuItem menuItemWithTitle:@"查看表情包信息源"
                                                            action:@selector(onViewEmojiSource:)
                                                            target:self
                                                     keyEquivalent:@""
                                                             state:NO];

    NSMenuItem *newWeChatMenu = [NSMenuItem menuItemWithTitle:@"多开"
                                                       action:@selector(onNewWeChat:)
                                                       target:self
                                                keyEquivalent:@""
                                                        state:NO];
    
    NSString *version = [NSString stringWithFormat:@"当前版本 %@", kCurrentVersion];
    NSMenuItem *currentVersionMenu = [NSMenuItem menuItemWithTitle:version
                                                            action:nil
                                                            target:self
                                                     keyEquivalent:@""
                                                             state:NO];
    currentVersionMenu.enabled = NO;
    
    NSMenu *subMenu = [[NSMenu alloc] initWithTitle:@"苏维埃助手"];
    [subMenu addItems:@[
        antiUpdateMenu,
        antiRevokeMenu,
        exitChatroomMenu,
        useSystemWebMenu,
        autoLoginMenu,
        viewEmojiSourceMenu,
        newWeChatMenu,
        currentVersionMenu
    ]];
    
    NSMenuItem *menuItem = [[NSMenuItem alloc] init];
    menuItem.title = @"苏维埃助手";
    menuItem.target = self;
    menuItem.enabled = YES;
    menuItem.submenu = subMenu;
    
    [[[NSApplication sharedApplication] mainMenu] addItem:menuItem];
}

#pragma mark - Menu Actions

- (void)onAntiUpdate:(NSMenuItem *)item
{
    [self ym_confirmToggleMenuItem:item
                   userDefaultsKey:kAntiUpdate
                   informativeText:@"非必要情况千万不要关闭`禁止更新`,否则微信自动更新导致插件失效"];
}

- (void)onAntiRevoke:(NSMenuItem *)item
{
    [self ym_confirmToggleMenuItem:item
                   userDefaultsKey:kAntiRevoke
                   informativeText:@"重启微信生效"];
}

- (void)onExitChatroom:(NSMenuItem *)item
{
    [self ym_showUnsupported];
}

- (void)onUseSystemWeb:(NSMenuItem *)item
{
    [self ym_showUnsupported];
}

// 暂未支持的功能：点击只弹提示，不切换状态、不重启。
- (void)ym_showUnsupported
{
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"提示";
    alert.informativeText = @"暂时不支持此功能";
    [alert addButtonWithTitle:@"好的"];
    [alert runModal];
}

- (void)onNewWeChat:(NSMenuItem *)item
{
    [self executeShellCommand:@"open -n /Applications/WeChat.app"];
}

// 自动登陆即时生效，无需重启微信。
- (void)onAutoLogin:(NSMenuItem *)item
{
    BOOL enabled = item.state != NSControlStateValueOn;
    [self ym_setMenuItem:item enabled:enabled userDefaultsKey:kAutoLogin];
    [YMAutoLogin setEnabled:enabled];
}

// 打开滚动 HTML 查看器（浏览器，每 3 秒自动刷新）。
- (void)onViewEmojiSource:(NSMenuItem *)item
{
    NSString *path = @"/tmp/wechat_emoji_source.html";
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [@"<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=3>"
         @"<body style='font-family:-apple-system;padding:30px;color:#666'>"
         @"暂无表情包信息源。开启「表情包信息源」并重启微信后，收到表情包消息时会自动出现。"
         @"</body>"
            writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    [self executeShellCommand:[NSString stringWithFormat:@"open '%@'", path]];
}

#pragma mark - Menu Helpers

- (NSMenuItem *)ym_toggleMenuItemWithTitle:(NSString *)title
                                       key:(NSString *)key
                                    action:(SEL)action
{
    BOOL enabled = [[NSUserDefaults standardUserDefaults] boolForKey:key];
    
    return [NSMenuItem menuItemWithTitle:title
                                  action:action
                                  target:self
                           keyEquivalent:@""
                                   state:enabled];
}

- (void)ym_confirmToggleMenuItem:(NSMenuItem *)item
                 userDefaultsKey:(NSString *)key
                 informativeText:(NSString *)informativeText
{
    BOOL enabled = item.state != NSControlStateValueOn;
    
    NSAlert *alert = [NSAlert alertWithMessageText:@"警告"
                                     defaultButton:@"取消"
                                   alternateButton:@"确定重启"
                                       otherButton:nil
                         informativeTextWithFormat:@"%@", informativeText];
    
    NSUInteger action = [alert runModal];
    if (action != NSAlertAlternateReturn) {
        return;
    }
    
    [self ym_setMenuItem:item enabled:enabled userDefaultsKey:key];
    [self ym_restartWeChatAfterDelay:0.5];
}

- (void)ym_setMenuItem:(NSMenuItem *)item
               enabled:(BOOL)enabled
       userDefaultsKey:(NSString *)key
{
    item.state = enabled ? NSControlStateValueOn : NSControlStateValueOff;
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setBool:enabled forKey:key];
    [defaults synchronize];
}

#pragma mark - WeChat

- (void)ym_restartWeChatAfterDelay:(NSTimeInterval)delay
{
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [self restartWeChat];
    });
}

- (void)restartWeChat
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *cmd = @"killall WeChat; sleep 0.5; open /Applications/WeChat.app";
        [self executeShellCommand:cmd];
    });
}

#pragma mark - Shell

- (NSString *)executeShellCommand:(NSString *)cmd
{
    if (cmd.length == 0) {
        return @"";
    }
    
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/bin/bash";
    task.arguments = @[@"-c", cmd];
    
    NSPipe *pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    task.standardError = pipe;
    
    NSFileHandle *fileHandle = [pipe fileHandleForReading];
    
    @try {
        [task launch];
    } @catch (NSException *exception) {
        return exception.reason ?: @"";
    }
    
    NSData *data = [fileHandle readDataToEndOfFile];
    [task waitUntilExit];
    
    NSString *result = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return result ?: @"";
}

@end
