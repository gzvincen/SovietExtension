//
//  MenuManager.h
//  SovietExtension
//
//  Created by MustangYM on 2026/6/13.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
static NSString *kAntiUpdate = @"kAntiUpdate.SOVIET";
static NSString *kAntiRevoke = @"kAntiRevoke.SOVIET";
static NSString *kExitChatroom = @"kExitChatroom.SOVIET";
static NSString *kUseSystemWeb = @"kUseSystemWeb.SOVIET";
static NSString *kIsFirstLoad = @"kIsFirstLoad.SOVIET";
static NSString *kCurrentVersion = @"1.0.6";

@interface MenuManager : NSObject
+ (void)hook;
+ (instancetype)shareInstance;
- (void)initAssistantMenuItems;
@end

NS_ASSUME_NONNULL_END
