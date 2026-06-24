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
    [self ym_confirmToggleMenuItem:item
                   userDefaultsKey:kExitChatroom
                   informativeText:@"重启微信生效"];
}

- (void)onUseSystemWeb:(NSMenuItem *)item
{
    [self ym_confirmToggleMenuItem:item
                   userDefaultsKey:kUseSystemWeb
                   informativeText:@"重启微信生效"];
}

- (void)onNewWeChat:(NSMenuItem *)item
{
    [self executeShellCommand:@"open -n /Applications/WeChat.app"];
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
