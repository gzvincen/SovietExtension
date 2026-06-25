//
//  AutoLogin.h
//  SovietExtension
//
//  自动登陆：微信启动后停在登录窗口，需手动点一次“进入微信”。
//  开启后自动找该按钮并点击；Qt 登录窗无 AppKit 子控件时改发回车兜底。
//  纯 AppKit 实现，不依赖任何逆向地址。
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface YMAutoLogin : NSObject

// 读取开关；开启则启动定时尝试。构造函数里调用。
+ (void)startIfEnabled;

// 菜单切换时调用：打开则重置状态并重新开始尝试。
+ (void)setEnabled:(BOOL)enabled;

+ (BOOL)isEnabled;

@end

NS_ASSUME_NONNULL_END
