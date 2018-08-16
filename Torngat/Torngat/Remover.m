//  Torngat Remover
//  Written by 1GamerDev

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include "Remover.h"
#include "SSZipArchive.h"
#include "Post/ku.h"
#include "rootfs_remount.h"
#include "Post/post.h"
#include "kmem.h"

#define SYSTEM_VERSION_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_GREATER_THAN(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)

@implementation NSFileManager(defaultManager)
- (BOOL)removeDirectoryAtPath:(NSString *)path {
    BOOL isDir;
    BOOL ret = [[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDir];
    if (ret && isDir) {
        NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtPath:path];
        NSString *file;
        while (file = [enumerator nextObject]) {
            NSError *error = nil;
            BOOL r = [[NSFileManager defaultManager] removeItemAtPath:[path stringByAppendingPathComponent:file] error:&error];
            if (r || error) {
                return false;
            }
        }
        NSError *error;
        BOOL r = [[NSFileManager defaultManager] removeItemAtPath:path error:&error];
        if (r || error) {
            return false;
        }
        return true;
    }
    return false;
}
@end

@interface RemoverInternal : NSObject
+ (void)defaultResolution;
+ (void)defaultModuleSettings;
+ (void)fixDefaultModules;
+ (void)removeDefaultModulesFromConfiguration;
+ (void)revertIconMaskModifications;
+ (void)revertBootlogoModifications;
+ (void)revertEmojiModifications;
+ (void)revertIconBadgeModifications;
+ (void)revertDockSeparatorModifications;
+ (void)unblockRevokes;
+ (void)unblockUpdates;
+ (void)removeDoubleNewlinesFromHosts;
@end

@implementation RemoverInternal : NSObject
+ (void)defaultResolution {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/private/var/mobile/Library/Preferences/com.apple.iokit.IOMobileGraphicsFamily.plist"]) {
        [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Library/Preferences/com.apple.iokit.IOMobileGraphicsFamily.plist" error:nil];
    }
}
+ (void)defaultModuleSettings {
    NSString *from = [[NSBundle mainBundle] pathForResource:@"DefaultModuleSettings" ofType:@"plist"];
    NSString *to = ((UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) ? @"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~ipad.plist" : @"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~iphone.plist");
    [[NSFileManager defaultManager] removeItemAtPath:to error:nil];
    [[NSFileManager defaultManager] copyItemAtPath:from toPath:to error:nil];
}
+ (void)fixDefaultModules {
    NSString *path = ((UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) ? @"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipad.plist" : @"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~iphone.plist");
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:path];
    if (![[plist objectForKey:@"fixed"] isEqual:@[]]) return;
    NSArray *fixed = @[@"com.apple.control-center.ConnectivityModule", @"com.apple.mediaremote.controlcenter.nowplaying", @"com.apple.control-center.DisplayModule", @"com.apple.control-center.AudioModule", @"com.apple.mediaremote.controlcenter.airplaymirroring", @"com.apple.control-center.OrientationLockModule", @"com.apple.control-center.MuteModule", @"com.apple.control-center.DoNotDisturbModule"];
    [plist setObject:fixed forKey:@"fixed"];
    NSArray *ue = [plist objectForKey:@"user-enabled"];
    NSArray *arr = @[];
    if (ue.count == 0) {
        arr = @[];
    }
    for (unsigned long i = 0; i < ue.count; ++i) {
        if (![fixed containsObject:[ue objectAtIndex:i]]) {
            arr = [arr arrayByAddingObject:[ue objectAtIndex:i]];
        }
    }
    [plist setObject:arr forKey:@"user-enabled"];
    [plist writeToFile:path atomically:YES];
}
+ (void)removeDefaultModulesFromConfiguration {
    NSString *path = @"/private/var/mobile/Library/ControlCenter/ModuleConfiguration.plist";
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:path];
    NSArray *fixed = @[@"com.apple.control-center.ConnectivityModule", @"com.apple.mediaremote.controlcenter.nowplaying", @"com.apple.control-center.DisplayModule", @"com.apple.control-center.AudioModule", @"com.apple.mediaremote.controlcenter.airplaymirroring", @"com.apple.control-center.OrientationLockModule", @"com.apple.control-center.MuteModule", @"com.apple.control-center.DoNotDisturbModule"];
    NSArray *mi = [plist objectForKey:@"module-identifiers"];
    if (![mi containsObject:@"com.apple.control-center.ConnectivityModule"]) return;
    NSArray *arr = @[];
    if (mi.count == 0) {
        arr = @[];
    }
    for (unsigned long i = 0; i < mi.count; ++i) {
        if (![fixed containsObject:[mi objectAtIndex:i]]) {
            arr = [arr arrayByAddingObject:[mi objectAtIndex:i]];
        }
    }
    [plist setObject:arr forKey:@"module-identifiers"];
    [plist writeToFile:path atomically:YES];
}
+ (void)revertIconMaskModifications {
    [SSZipArchive unzipFileAtPath:[[NSBundle mainBundle] pathForResource:((UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) ? @"iPadDefault" : @"iPhoneDefault") ofType:@"zip"] toDestination:@"/private/var/mobile/Torngat_TMP_Mask_DIR/"];
    BOOL isDir;
    NSString *oPath = @"/private/var/mobile/Torngat_TMP_Mask_DIR/";
    [[NSFileManager defaultManager] fileExistsAtPath:oPath isDirectory:&isDir];
    if (isDir) {
        NSArray *contentOfDirectory = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:oPath error:NULL];
        int contentcount = (int)[contentOfDirectory count];
        for (int i = 0; i < contentcount; i++) {
            NSString *fileName = [[contentOfDirectory objectAtIndex:i] stringByReplacingOccurrencesOfString:@"/" withString:@""];
            BOOL isDir = false;
            BOOL ret = [[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithFormat:@"/System/Library/PrivateFrameworks/MobileIcons.framework/%@", fileName] isDirectory:&isDir];
            if (ret && !isDir) {
                NSString *origPath = [NSString stringWithFormat:@"%@%@", oPath, fileName];
                [[NSFileManager defaultManager] removeItemAtPath:[NSString stringWithFormat:@"/System/Library/PrivateFrameworks/MobileIcons.framework/%@", fileName] error:nil];
                [[NSFileManager defaultManager] copyItemAtPath:origPath toPath:[NSString stringWithFormat:@"/System/Library/PrivateFrameworks/MobileIcons.framework/%@", fileName] error:nil];
            }
        }
    }
    [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Torngat_TMP_Mask_DIR/" error:nil];    [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.lsd.iconscache/Library/Caches/com.apple.IconsCache/" error:nil];
    [[NSFileManager defaultManager] createDirectoryAtPath:@"/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.lsd.iconscache/Library/Caches/com.apple.IconsCache/" withIntermediateDirectories:false attributes:nil error:nil];
}
+ (void)revertBootlogoModifications {
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        [SSZipArchive unzipFileAtPath:[[NSBundle mainBundle] pathForResource:@"iPadProgressUI" ofType:@"zip"] toDestination:@"/private/var/mobile/Torngat_TMP_ProgressUI_DIR/"];
    } else {
        [SSZipArchive unzipFileAtPath:[[NSBundle mainBundle] pathForResource:@"iPhoneProgressUI" ofType:@"zip"] toDestination:@"/private/var/mobile/Torngat_TMP_ProgressUI_DIR/"];
    }
    BOOL isDir;
    NSString *oPath = @"/private/var/mobile/Torngat_TMP_ProgressUI_DIR/";
    [[NSFileManager defaultManager] fileExistsAtPath:oPath isDirectory:&isDir];
    if (isDir) {
        NSArray *contentOfDirectory = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:oPath error:NULL];
        int contentcount = (int)[contentOfDirectory count];
        for (int i = 0; i < contentcount; i++) {
            NSString *fileName = [[contentOfDirectory objectAtIndex:i] stringByReplacingOccurrencesOfString:@"/" withString:@""];
            NSString *origPath = [NSString stringWithFormat:@"%@%@", oPath, fileName];
            if ([[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithFormat:@"/System/Library/PrivateFrameworks/ProgressUI.framework/%@", fileName] isDirectory:nil]) {
                [[NSFileManager defaultManager] removeItemAtPath:[NSString stringWithFormat:@"/System/Library/PrivateFrameworks/ProgressUI.framework/%@", fileName] error:nil];
                [[NSFileManager defaultManager] copyItemAtPath:origPath toPath:[NSString stringWithFormat:@"/System/Library/PrivateFrameworks/ProgressUI.framework/%@", fileName] error:nil];
            }
        }
    }
    [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Torngat_TMP_ProgressUI_DIR/" error:nil];
}
+ (void)revertEmojiModifications {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" isDirectory:nil]) {
        [[NSFileManager defaultManager] removeItemAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" error:nil];
        [[NSFileManager defaultManager] moveItemAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" toPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" error:nil];
    }
}
+ (void)revertIconBadgeModifications {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/private/var/mobile/Library/Caches/MappedImageCache/Persistent/SBIconBadgeView.BadgeBackground.cpbitmap" isDirectory:nil]) {
        [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Library/Caches/MappedImageCache/Persistent/SBIconBadgeView.BadgeBackground.cpbitmap" error:nil];
    }
}
+ (void)revertDockSeparatorModifications {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/private/var/mobile/Library/Caches/MappedImageCache/Persistent/highlight-0.05a-0.5h.cpbitmap" isDirectory:nil]) {
        [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Library/Caches/MappedImageCache/Persistent/highlight-0.05a-0.5h.cpbitmap" error:nil];
    }
}
+ (void)unblockRevokes {
    if ([[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] containsString:@"donteditthisentry.torngat.1gamerdev.rf.gd"]) {
        [[[[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] stringByReplacingOccurrencesOfString:@"127.0.0.1 donteditthisentry.torngat.1gamerdev.rf.gd ocsp.apple.com oscp.apple.com" withString:@"127.0.0.1 ocsp.apple.com\n"] stringByReplacingOccurrencesOfString:@"127.0.0.1 donteditthisentry.torngat.1gamerdev.rf.gd disabledblockrevokes.apple.com" withString:@""] writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    if ([[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] containsString:@"127.0.0.1 ocsp.apple.com\n"]) {
        [[[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] stringByReplacingOccurrencesOfString:@"127.0.0.1 ocsp.apple.com\n" withString:@""] writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}
+ (void)unblockUpdates {
    if ([[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] containsString:@"donteditthisentry.torngat.1gamerdev.rf.gd"]) {
        [[[[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] stringByReplacingOccurrencesOfString:@"127.0.0.1 donteditthisentry.torngat.1gamerdev.rf.gd mesu.apple.com" withString:@""] stringByReplacingOccurrencesOfString:@"127.0.0.1 donteditthisentry.torngat.1gamerdev.rf.gd disabledblockupdates.apple.com" withString:@""] writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    if ([[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] containsString:@"127.0.0.1 mesu.apple.com\n"]) {
        [[[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] stringByReplacingOccurrencesOfString:@"127.0.0.1 mesu.apple.com\n" withString:@""] writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}
+ (void)removeDoubleNewlinesFromHosts {
    NSString *hosts = [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil];
    if (![hosts containsString:@"\n\n"]) return;
    while ([hosts containsString:@"\n\n"]) {
        hosts = [hosts stringByReplacingOccurrencesOfString:@"\n\n" withString:@"\n"];
    }
    [hosts writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
}
@end

@implementation Remover : NSObject
+ (BOOL)undoChanges {
    [RemoverInternal defaultResolution];
    [RemoverInternal defaultModuleSettings];
    [RemoverInternal fixDefaultModules];
    [RemoverInternal removeDefaultModulesFromConfiguration];
    [RemoverInternal revertIconMaskModifications];
    [RemoverInternal revertBootlogoModifications];
    [RemoverInternal revertEmojiModifications];
    [RemoverInternal revertIconBadgeModifications];
    [RemoverInternal revertDockSeparatorModifications];
    [RemoverInternal unblockRevokes];
    [RemoverInternal unblockUpdates];
    [RemoverInternal removeDoubleNewlinesFromHosts];
    return true;
}
+ (BOOL)remove {
    if (![self undoChanges]) return false;
    return true;
}
@end
