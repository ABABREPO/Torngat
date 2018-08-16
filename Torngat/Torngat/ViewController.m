/*
 *
 *   Torngat
 *   Made by 1GamerDev
 *   * MY * code is licensed under DBAD
 *   (c) 2018
 *
 */

//  COMING SOON - Code Cleanup

//  Credits:
//  Torngat - 1GamerDev
//  empty_list - Ian Beer
//  Remount - CoolStar
//  liboffsetfinder64 - tihmstar
//  Kernel Utilities - theninjaprawn
//  patchfinder64 - xerub

#import "ViewController.h"
#include "kmem.h"
#import "enterprise_codesigning_credits.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#import <sys/utsname.h>
#import "ZipArchive.h"
#import "SSZipArchive.h"
#import "SSZipCommon.h"
#include "empty_list/sploit.h"
#include "post.h"
#include "ku.h"
#include "Reachability.h"
#import "add.h"
#include <spawn.h>
#include <sys/sysctl.h>
#import "guionly.h"
#include "Remover.h"

NSString *___URL;

NSString *springboard = @"/System/Library/CoreServices/SpringBoard.app";

CGFloat bottomOfLowestContent(UIView *view) {
    CGFloat lowestPoint = 0.0;
    BOOL restoreHorizontal = NO;
    BOOL restoreVertical = NO;
    if ([view respondsToSelector:@selector(setShowsHorizontalScrollIndicator:)] && [view respondsToSelector:@selector(setShowsVerticalScrollIndicator:)]) {
        if ([(UIScrollView*)view showsHorizontalScrollIndicator]) {
            restoreHorizontal = YES;
            [(UIScrollView*)view setShowsHorizontalScrollIndicator:NO];
        }
        if ([(UIScrollView*)view showsVerticalScrollIndicator]) {
            restoreVertical = YES;
            [(UIScrollView*)view setShowsVerticalScrollIndicator:NO];
        }
    }
    for (UIView *subView in view.subviews) {
        if (!subView.hidden) {
            CGFloat maxY = CGRectGetMaxY(subView.frame);
            if (maxY > lowestPoint) {
                lowestPoint = maxY;
            }
        }
    }
    if ([view respondsToSelector:@selector(setShowsHorizontalScrollIndicator:)] && [view respondsToSelector:@selector(setShowsVerticalScrollIndicator:)]) {
        if (restoreHorizontal) {
            [(UIScrollView*)view setShowsHorizontalScrollIndicator:YES];
        }
        if (restoreVertical) {
            [(UIScrollView*)view setShowsVerticalScrollIndicator:YES];
        }
    }
    return lowestPoint;
}

#define RESIZE_SCROLLVIEW_0(id, wid, add) {\
CGRect __contentRect = CGRectZero;\
for (UIView *__view in id.subviews) {\
__contentRect = CGRectUnion(__contentRect, __view.frame);\
}\
__contentRect.size.width = wid;\
__contentRect.size.height = __contentRect.size.height + add;\
id.contentSize = __contentRect.size; id.alwaysBounceVertical = true;\
}
#define RESIZE_SCROLLVIEW_1(id, width, add) {\
id.contentSize = CGSizeMake(width, bottomOfLowestContent(id) + add); id.alwaysBounceVertical = true;\
}

//  NSNumber
NSString *PID_KEY = @"pid";
//  NSString
NSString *EXECUTABLE_KEY = @"executable";
//  NSString
NSString *DOCUMENTS_KEY = @"documents";
//  NSString
NSString *NAME_KEY = @"name";
//  NSNumber
NSString *APPEX_KEY = @"appex";
//  NSNumber
NSString *OWNER_KEY = @"owner";
//  NSNumber
NSString *USER_KEY = @"user";
//  NSNumber
NSString *TASK_KEY = @"task";
NSArray *allProcesses() {
    static int maxArgumentSize = 0;
    if (maxArgumentSize == 0) {
        size_t size = sizeof(maxArgumentSize);
        if (sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &maxArgumentSize, &size, NULL, 0) == -1) {
            maxArgumentSize = 4096;
        }
    }
    NSMutableArray *processes = [NSMutableArray array];
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    struct kinfo_proc *info;
    size_t length;
    int count;
    if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0)
        return nil;
    if (!(info = malloc(length)))
        return nil;
    if (sysctl(mib, 3, info, &length, NULL, 0) < 0) {
        free(info);
        return nil;
    }
    count = (int)length / sizeof(struct kinfo_proc);
    for (int i = 0; i < count; i++) {
        pid_t pid = info[i].kp_proc.p_pid;
        if (pid == 0) {
            continue;
        }
        size_t size = maxArgumentSize;
        char *buffer = (char *)malloc(length);
        if (sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, pid }, 3, buffer, &size, NULL, 0) == 0) {
            NSString *executable = [NSString stringWithCString:(buffer+sizeof(int)) encoding:NSUTF8StringEncoding];
            mach_port_name_t tfp;
            task_for_pid(mach_task_self(), pid, &tfp);
            uid_t uid = info[i].kp_eproc.e_pcred.p_ruid;
            int user = 0;
            if ([executable hasPrefix:@"/var/"] || [executable hasPrefix:@"/private/var"]) {
                user = 1;
            }
            int appex = 0;
            if ([executable containsString:@".appex/"]) {
                appex = 1;
            }
            [processes addObject:[NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:pid], @"pid", executable, @"executable", [[executable stringByDeletingLastPathComponent] stringByAppendingString:@"Documents"], @"documents", [executable lastPathComponent], @"name", [NSNumber numberWithInt:appex], @"appex", [NSNumber numberWithInt:uid], @"owner", [NSNumber numberWithInt:user], @"user", [NSNumber numberWithInt:tfp], @"task", nil]];
        }
        free(buffer);
    }
    free(info);
    return processes;
}

NSString *keyValueForName(NSString *name, NSString *key) {
    NSArray *p = allProcesses();
    for (uint64_t i = 0; i < p.count; ++i) {
        if ([[p objectAtIndex:i][@"name"] isEqual:name]) {
            if (![[[p objectAtIndex:i] allKeys] containsObject:key]) {
                return false;
            }
            return [p objectAtIndex:i][key];
        }
    }
    return false;
}

NSString *keyValueForPID(pid_t PID, NSString *key) {
    NSArray *p = allProcesses();
    for (uint64_t i = 0; i < p.count; ++i) {
        if ([[p objectAtIndex:i][@"pid"] isEqual:[NSNumber numberWithInt:PID]]) {
            if (![[[p objectAtIndex:i] allKeys] containsObject:key]) {
                return false;
            }
            return [NSString stringWithFormat:@"%@", [p objectAtIndex:i][key]];
        }
    }
    return false;
}

pid_t noU(NSString *PID) {
    return [PID intValue];
}

BOOL weAreUnsandboxed() {
    NSError *no;
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/.write_test"]) {
        [[NSFileManager defaultManager] removeItemAtPath:@"/var/mobile/.write_test" error:nil];
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/.write_test"]) {
            return false;
        }
    }
    [[NSFileManager defaultManager] createFileAtPath:@"/var/mobile/.write_test" contents:nil attributes:nil];
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/.write_test"]) {
        [[NSFileManager defaultManager] removeItemAtPath:@"/var/mobile/.write_test" error:&no];
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/.write_test"] || no) {
            return false;
        } else {
            return true;
        }
    } else {
        return false;
    }
}

// used in if statements to compare the user's iOS version
#define SYSTEM_VERSION_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_GREATER_THAN(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)

// hex to rgb
#define hex(hex, alphaVal) [UIColor colorWithRed:((float)((hex & 0xFF0000) >> 16))/255.0 green:((float)((hex & 0xFF00) >> 8))/255.0 blue:((float)(hex & 0xFF))/255.0 alpha:alphaVal]

// used in if statements to check if the user is disconnected from the internet
#define noWiFi [[Reachability reachabilityForInternetConnection] currentReachabilityStatus] == NotReachable

// button colours
#define bgDisabledColour setBackgroundColor:hex(0xB8B8B8, 1.0)
#define bgBlueColour setBackgroundColor:hex(0x007AFF, 1.0)

// respringDevice(); to respring the user's device
#define respringDevice() [[UIApplication sharedApplication] setStatusBarHidden:YES withAnimation:UIStatusBarAnimationFade]; UIViewController *r = [self.storyboard instantiateViewControllerWithIdentifier:@"respringv"]; [self presentViewController:r animated:YES completion:nil]

#define system(arg) popen(arg, "r")

// define unsint as an unsigned int
typedef unsigned int unsint;

BOOL file_exist(char *file) {
    NSString *f = [NSString stringWithFormat:@"%s", file];
    BOOL dir;
    BOOL exist = [[NSFileManager defaultManager] fileExistsAtPath:f isDirectory:&dir];
    return exist && !dir;
}

BOOL dontRespring = FALSE;
NSString *documentsDirectory;
NSString *getDocumentsDirectory() {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    documentsDirectory = [paths objectAtIndex:0];
    return documentsDirectory;
}
void writeToLocalFile(NSString *name, NSString *contents) {
    getDocumentsDirectory();
    NSString *fileName = [NSString stringWithFormat:@"%@/%@", documentsDirectory, name];
    [contents writeToFile:fileName atomically:NO encoding:NSUTF8StringEncoding error:nil];
}
void removeLocalFile(NSString *name) {
    getDocumentsDirectory();
    NSString *fileName = [NSString stringWithFormat:@"%@/%@", documentsDirectory, name];
    unlink(fileName.UTF8String);
}
void createLocalDirectory(NSString *name) {
    getDocumentsDirectory();
    [[NSFileManager defaultManager] createDirectoryAtPath:[NSString stringWithFormat:@"%@/%@", documentsDirectory, name] withIntermediateDirectories:NO attributes:nil error:nil];
}
NSString *stringWithContentsOfLocalFile(NSString *daName) {
    getDocumentsDirectory();
    return [NSString stringWithContentsOfFile:[NSString stringWithFormat:@"%@/%@", documentsDirectory, daName] encoding:NSUTF8StringEncoding error:nil];
}
NSString *stringWithPathOfLocalFile(NSString *daName) {
    return [NSString stringWithFormat:@"%@/%@", getDocumentsDirectory(), daName];
}
BOOL darkModeIsEnabled(void) {
    getDocumentsDirectory();
    if([[NSString stringWithContentsOfFile:[NSString stringWithFormat:@"%@/darkMode", documentsDirectory] encoding:NSUTF8StringEncoding error:nil] isEqual: @"yes"]) {
        return true;
    } else {
        return false;
    }
}
BOOL remounted(void);
void freeze() {
    kill(noU(keyValueForName(@"SpringBoard", PID_KEY)), SIGSTOP);
}
void unfreeze() {
    kill(noU(keyValueForName(@"SpringBoard", PID_KEY)), SIGCONT);
}
NSString *versionNumber = @"Version 2.1.0";
NSString *NSVN = @"2.1.0";

NSString *bigFullscreenBoiTitle = @"Loading";
NSString *bigFullscreenBoiText = @"Please Wait";

NSString *usedExploit = @"";

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UIButton *gobtn;
@property (strong, nonatomic) IBOutlet UIWebView *web;
@property (strong, nonatomic) IBOutlet UIProgressView *progress;
@property (strong, nonatomic) IBOutlet UIActivityIndicatorView *loader;
@property (strong, nonatomic) IBOutlet UIView *alert;
@property (strong, nonatomic) IBOutlet UIButton *infoBtn;
@property (strong, nonatomic) IBOutlet UILabel *btnTxt;

@end

@implementation ViewController

int autoExploit = 0;

- (void)urlScheme {
    if (![___URL isEqual:@"NULL"] && ![___URL isEqual:@"(null)"]) {
        NSString *____URL = [NSString stringWithFormat:@"%@", ___URL];
        ___URL = @"NULL";
        Done *vc = [[Done alloc] init];
        [vc _urlScheme:____URL];
    }
}

- (void)viewWillAppear:(BOOL)animated {
    NSLog(@"%@", getDocumentsDirectory());
    NSLog(@"%@", [[NSBundle mainBundle] bundlePath]);
    if (SYSTEM_VERSION_LESS_THAN(@"11.0")) {
        exit(0);
    }
    if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"11.0") && SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(@"11.1.2")) {
        usedExploit = @"empty_list";
    }
    if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"11.2") && SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(@"11.3.1")) {
        usedExploit = @"empty_list";
    }
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
#ifdef INTEL86
    UIAlertController *unsupported = [UIAlertController alertControllerWithTitle:@"Unsupported Architecture" message:@"Torngat does not support 32bit devices." preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:unsupported animated:YES completion:nil];
#endif
}

BOOL exploitationComplete = false;

- (BOOL)exploit {
    if (exploitationComplete) {
        return true;
    }
    if (getuid() == 0 && weAreUnsandboxed() && remounted()) {
        return true;
    }
    mach_port_t tfp0 = 0;
    host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfp0);  // just in case
    printf("tfp0: %i\n", tfp0);
    if (tfp0 != 0 && tfp0 != -1) {
        if (post_exploitation(tfp0)) {
            exploitationComplete = true;
            return true;
        }
        return false;
    }
    if ([usedExploit isEqual:@"empty_list"]) {
        tfp0 = run_empty_list();
    } else {
        return false;
    }
    if (tfp0 == 0) {
        return false;
    } else {
        if (post_exploitation(tfp0)) {
            exploitationComplete = true;
            return true;
        }
        return false;
    }
}

NSTimer *timer = nil;

- (void)viewDidLoad {
    [super viewDidLoad];
    /* URL Schemes */
    timer = [NSTimer scheduledTimerWithTimeInterval:1.0f target:self selector:@selector(urlScheme) userInfo:nil repeats:YES];
    [timer fire];
    /*  View  */
    [_alert setHidden:YES];
    [_alert setAlpha:0.0f];
    [_loader setAlpha:0.0f];
    [_progress setAlpha:0.0f];
    [_progress setHidden:YES];
    self.gobtn.backgroundColor = [UIColor colorWithRed:171 green:178 blue:186 alpha:1.0f];
    self.gobtn.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
    self.gobtn.layer.shadowOffset = CGSizeMake(0, 0);
    self.gobtn.layer.shadowOpacity = 1.0f;
    self.gobtn.layer.shadowRadius = 5;
    self.gobtn.layer.masksToBounds = YES;
    self.gobtn.layer.cornerRadius = 25.0f;
    self.gobtn.exclusiveTouch = YES;
    /*  Setup  */
    documentsDirectory = getDocumentsDirectory();
    if (![[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithFormat:@"%@/darkMode", documentsDirectory]]) {
        writeToLocalFile(@"darkMode", @"no");;
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithFormat:@"%@/showLoader", documentsDirectory]]) {
        writeToLocalFile(@"showLoader", @"yes");
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithFormat:@"%@/autoExploit", documentsDirectory]]) {
        writeToLocalFile(@"autoExploit", @"no");
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithFormat:@"%@/resizeBootlogos", documentsDirectory]]) {
        writeToLocalFile(@"resizeBootlogos", @"no");
    }
    /*  Updates  */
    [_web loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"http://1gamerdev.github.io/Torngat-Files/update.html?exploit=empty_list&version=%@", NSVN]]]];
    /*  Credits  */
    if (SYSTEM_VERSION_LESS_THAN(@"11.0")) {
        exit(0);
    }
    if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"11.0") && SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(@"11.1.2")) {
        usedExploit = @"empty_list";
    }
    if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"11.2") && SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(@"11.3.1")) {
        usedExploit = @"empty_list";
    }
    /*  perhaps we e x p l o o t 🔥😎👌  */
    if ([stringWithContentsOfLocalFile(@"autoExploit") isEqual:@"yes"]) {
        autoExploit = 1;
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            if ([self exploit]) {
                autoExploit = 0;
            } else {
                autoExploit = -1;
            }
        });
    }
}

NSInteger btnMem = 0;
- (IBAction)infoBtn:(id)sender {
    if (btnMem == 0) {
        [_infoBtn setTitle:versionNumber forState:UIControlStateNormal];
        btnMem = 1;
    } else if (btnMem == 1) {
        [_infoBtn setTitle:@"iOS 11 - 11.3.1" forState:UIControlStateNormal];
        btnMem = 0;
    } else {
        [_infoBtn setTitle:@"iOS 11 - 11.3.1" forState:UIControlStateNormal];
        btnMem = 0;
    }
}
void doNothing(int arg) { arg += 1; return; }
- (IBAction)go:(id)sender {
#ifdef guionly
    [timer invalidate];
    timer = nil;
    exploitationComplete = true;
    if (darkModeIsEnabled()) {
        [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent];
    } else {
        [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault];
    }
    UIViewController *Done = [self.storyboard instantiateViewControllerWithIdentifier:@"Done"];
    [self presentViewController:Done animated:YES completion:nil];
    return;
#endif
    // keeps away users on unsupported ios versions
    if ([usedExploit isEqual:@""]) {
        UIAlertController *unsupported = [UIAlertController alertControllerWithTitle:@"Unsupported iOS version" message:[NSString stringWithFormat:@"Your iOS version (%@) is unsupported by Torngat.", [[UIDevice currentDevice] systemVersion]] preferredStyle:UIAlertControllerStyleAlert];
        [self presentViewController:unsupported animated:YES completion:nil];
        return;
    }
    UIAlertControllerStyle style;
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        style = UIAlertControllerStyleAlert;
    } else {
        style = UIAlertControllerStyleActionSheet;
    }
    UIAlertController *ca = [UIAlertController alertControllerWithTitle:@"Warning" message:@"By using Torngat, you agree that if it causes any damage to your device, you are responsible." preferredStyle:style];
    UIAlertAction *ok = [UIAlertAction actionWithTitle:@"Continue" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        [_gobtn setEnabled:NO];
        [_btnTxt setText:@"Please Wait"];
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [NSThread sleepForTimeInterval:1.0f];
            dispatch_async(dispatch_get_main_queue(), ^{
                BOOL skip = false;
            waitok:;
                if (autoExploit == 1) {
                    skip = true;
                    goto waitok;
                }
                if (skip) {
                    [timer invalidate];
                    timer = nil;
                    if (darkModeIsEnabled()) {
                        [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent];
                    } else {
                        [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault];
                    }
                    [self presentViewController:[self.storyboard instantiateViewControllerWithIdentifier:@"Done"] animated:YES completion:nil];
                    return;
                }
                if ([self exploit]) {
                    [timer invalidate];
                    timer = nil;
                    if (darkModeIsEnabled()) {
                        [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent];
                    } else {
                        [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault];
                    }
                    [self presentViewController:[self.storyboard instantiateViewControllerWithIdentifier:@"Done"] animated:YES completion:nil];
                    return;
                }
            });
        });
    }];
    [ca addAction:ok];
    [ca addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) { exit(0); }]];
    [self presentViewController:ca animated:YES completion:nil];
}

@end

BOOL applyingMask = false;

@interface Done ()
@property (strong, nonatomic) IBOutlet UIView *tweaks;
@property (strong, nonatomic) IBOutlet UIView *credits;
@property (strong, nonatomic) IBOutlet UITabBar *tabBar;
@property (strong, nonatomic) IBOutlet UITabBarItem *homeTab;
@property (strong, nonatomic) IBOutlet UITabBarItem *creditsTab;
@property (strong, nonatomic) IBOutlet UITabBarItem *aboutTab;
@property (strong, nonatomic) IBOutlet UIView *about;
@property (strong, nonatomic) IBOutlet UIView *settings;
@property (strong, nonatomic) IBOutlet UITabBarItem *settingsTab;
@property (strong, nonatomic) IBOutlet UIImageView *bg;

@end

@implementation Done

- (void)respring {
    respringDevice();
}

- (void)visualStyle {
    [_tabBar setValue:@(YES) forKeyPath:@"hidesShadow"];
    if (darkModeIsEnabled()) {
        _tabBar.barStyle = UIBarStyleBlack;
        _tabBar.tintColor = hex(0xFF8500, 1.0);
        _tabBar.barTintColor = hex(0x1B2737, 1.0);
    } else {
        _tabBar.barStyle = UIBarStyleDefault;
        _tabBar.tintColor = hex(0x007AFF, 1.0);
        _tabBar.barTintColor = hex(0xF2F2F2, 1.0);
    }
}

- (void)viewWillAppear:(BOOL)animated {
    ___URL = @"NULL";
    [NSTimer scheduledTimerWithTimeInterval:1.0f target:self selector:@selector(urlScheme) userInfo:nil repeats:YES];
    [self.tweaks setHidden:NO];
    [self.credits setHidden:YES];
    [self.about setHidden:YES];
    [self.settings setHidden:YES];
    _tabBar.delegate = self;
    [_tabBar setSelectedItem:_homeTab];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(visualStyle)     name:@"updatedVisualStyle" object:nil];
    [self visualStyle];
    UIImage *bg = [UIImage imageWithContentsOfFile:@"/private/var/mobile/Library/SpringBoard/LockBackgroundThumbnail.jpg"];
    [_bg setImage:bg];
}

- (void)tabBar:(UITabBar *)tabBar didSelectItem:(UITabBarItem *)item {
    if (item == _homeTab) {
        [self.tweaks setHidden:NO];
        [self.credits setHidden:YES];
        [self.about setHidden:YES];
        [self.settings setHidden:YES];
    } else if (item == _creditsTab) {
        [self.tweaks setHidden:YES];
        [self.credits setHidden:NO];
        [self.about setHidden:YES];
        [self.settings setHidden:YES];
    } else if (item == _aboutTab) {
        [self.tweaks setHidden:YES];
        [self.credits setHidden:YES];
        [self.about setHidden:NO];
        [self.settings setHidden:YES];
    } else if (item == _settingsTab) {
        [self.tweaks setHidden:YES];
        [self.credits setHidden:YES];
        [self.about setHidden:YES];
        [self.settings setHidden:NO];
    } else {
        exit(0);
    }
}

#define spinAlert() {\
UIAlertController *pending = [UIAlertController alertControllerWithTitle:nil message:@"Please Wait\n\n" preferredStyle:UIAlertControllerStyleAlert];\
UIActivityIndicatorView *indicator = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];\
indicator.color = [UIColor blackColor];\
indicator.translatesAutoresizingMaskIntoConstraints=NO;\
[pending.view addSubview:indicator];\
NSDictionary *views = @{@"pending" : pending.view, @"indicator" : indicator};\
NSArray *constraintsVertical = [NSLayoutConstraint constraintsWithVisualFormat:@"V:[indicator]-(20)-|" options:0 metrics:nil views:views];\
NSArray *constraintsHorizontal = [NSLayoutConstraint constraintsWithVisualFormat:@"H:|[indicator]|" options:0 metrics:nil views:views];\
NSArray *constraints = [constraintsVertical arrayByAddingObjectsFromArray:constraintsHorizontal];\
[pending.view addConstraints:constraints];\
[indicator setUserInteractionEnabled:NO];\
[indicator startAnimating];\
[self presentViewController:pending animated:YES completion:nil];\
}

- (void)_urlScheme:(NSString *)url {
    if (![url hasPrefix:@"torngat:/"]) {
        return;
    }
    NSLog(@"got url scheme");
    url = [url substringFromIndex:7];
    url = [NSString stringWithFormat:@"torngat%@", url];
    while ([url hasPrefix:@"torngat:///"]) {
        url = [url stringByReplacingOccurrencesOfString:@"torngat:///" withString:@"torngat://"];
    }
    if ([url hasPrefix:@"torngat:"] && ![url hasPrefix:@"torngat:/"]) {
        url = [url substringFromIndex:8];
        url = [NSString stringWithFormat:@"torngat://%@", url];
    }
    if ([url hasPrefix:@"torngat:/"] && ![url hasPrefix:@"torngat://"]) {
        url = [url substringFromIndex:9];
        url = [NSString stringWithFormat:@"torngat://%@", url];
    }
    NSLog(@"%@", url);
    BOOL darkModeSwitch;
    BOOL loaderSwitch;
    BOOL autoExploitSwitch;
    BOOL resizeBootlogosSwitch;
    if ([stringWithContentsOfLocalFile(@"darkMode") isEqual: @"yes"]) {
        darkModeSwitch = true;
    } else {
        darkModeSwitch = false;
    }
    if ([stringWithContentsOfLocalFile(@"showLoader") isEqual: @"yes"]) {
        loaderSwitch = true;
    } else {
        loaderSwitch = false;
    }
    if ([stringWithContentsOfLocalFile(@"autoExploit") isEqual: @"yes"]) {
        autoExploitSwitch = true;
    } else {
        autoExploitSwitch = false;
    }
    if([stringWithContentsOfLocalFile(@"resizeBootlogos") isEqual: @"yes"]) {
        resizeBootlogosSwitch = true;
    } else {
        resizeBootlogosSwitch = false;
    }
    if ([url.lowercaseString isEqual:@"torngat://toggledarkmode"]) {
        [self.navigationController.navigationBar setValue:@(YES) forKeyPath:@"hidesShadow"];
        if (!darkModeSwitch) {
            writeToLocalFile(@"darkMode", @"yes");
            settings *sc = [[settings alloc] init];
            [sc enableDarkMode];
            [[NSNotificationCenter defaultCenter] postNotificationName:@"sVS" object:self];
        } else {
            writeToLocalFile(@"darkMode", @"no");
            settings *sc = [[settings alloc] init];
            [sc disableDarkMode];
            [[NSNotificationCenter defaultCenter] postNotificationName:@"sVS" object:self];
        }
        settings *sc = [[settings alloc] init];
        sc.darkModeSwitch.on = !darkModeSwitch;
        return;
    }
    if ([url.lowercaseString isEqual:@"torngat://toggleautoexploit"]) {
        if (!autoExploitSwitch) {
            writeToLocalFile(@"autoExploit", @"yes");
        } else {
            writeToLocalFile(@"autoExploit", @"no");
        }
        settings *sc = [[settings alloc] init];
        sc.autoExploitSwitch.on = !autoExploitSwitch;
        return;
    }
    if ([url.lowercaseString isEqual:@"torngat://toggleloader"]) {
        if (!loaderSwitch) {
            writeToLocalFile(@"showLoader", @"yes");
        } else {
            writeToLocalFile(@"showLoader", @"no");
        }
        settings *sc = [[settings alloc] init];
        sc.loaderSwitch.on = !loaderSwitch;
        return;
    }
    if ([url.lowercaseString isEqual:@"torngat://toggleresizebootlogos"] && remounted()) {
        if (!resizeBootlogosSwitch) {
            writeToLocalFile(@"resizeBootlogos", @"yes");
        } else {
            writeToLocalFile(@"resizeBootlogos", @"no");
        }
        settings *sc = [[settings alloc] init];
        sc.resizeBootlogosSwitch.on = !resizeBootlogosSwitch;
        return;
    }
    if (!exploitationComplete) {
        if (![url.lowercaseString isEqual:@"torngat://"]) {
            abort();
        }
        return;
    }
    if (!applyingMask && [url.lowercaseString hasPrefix:@"torngat://applymask/"] && ([url.lowercaseString hasSuffix:@".zip"] || [url.lowercaseString hasSuffix:@".tgm"] || [url.lowercaseString hasSuffix:@".mask"])) {
        NSString *URL = [url substringFromIndex:@"torngat://applyMask/".length];
        NSLog(@"%@", URL);
        if ([URL.lowercaseString hasPrefix:@"http:"] || [URL.lowercaseString hasPrefix:@"https:"]) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Apply Mask?" message:[NSString stringWithFormat:@"Would you like to download and apply the icon mask at %@?", URL] preferredStyle:UIAlertControllerStyleAlert];
            UIAlertAction *no = [UIAlertAction actionWithTitle:@"No" style:UIAlertActionStyleCancel handler:nil];
            UIAlertAction *yes = [UIAlertAction actionWithTitle:@"Yes" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
                applyingMask = true;
                spinAlert();
                freeze();
                NSData *urlData = [NSData dataWithContentsOfURL:[NSURL URLWithString:URL]];
                if (urlData) {
                    [urlData writeToFile:@"/private/var/mobile/Torngat_TMP_Mask_Files.zip" atomically:YES];
                    [[NSFileManager defaultManager] createDirectoryAtPath:@"/private/var/mobile/Torngat_TMP_Mask_DIR/" withIntermediateDirectories:NO attributes:nil error:nil];
                    if (![SSZipArchive unzipFileAtPath:@"/private/var/mobile/Torngat_TMP_Mask_Files.zip" toDestination:@"/private/var/mobile/Torngat_TMP_Mask_DIR/"]) {
                        [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Torngat_TMP_Mask_Files.zip" error:nil];
                        [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Torngat_TMP_Mask_DIR/" error:nil];
                        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Failed" message:@"The mask is corrupted." preferredStyle:UIAlertControllerStyleAlert];
                        UIAlertAction *action = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleCancel handler:nil];
                        [alert addAction:action];
                        unfreeze();
                        [self.presentedViewController dismissViewControllerAnimated:YES completion:^{
                            [self presentViewController:alert animated:YES completion:nil];
                        }];
                        applyingMask = false;
                        return;
                    }
                    [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Torngat_TMP_Mask_Files.zip" error:nil];
                    {
                        BOOL isDir;
                        NSString *oPath = @"/private/var/mobile/Torngat_TMP_Mask_DIR/";
                        [[NSFileManager defaultManager] fileExistsAtPath:oPath isDirectory:&isDir];
                        if(isDir) {
                            NSArray *contentOfDirectory = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:oPath error:NULL];
                            int contentcount = (int)[contentOfDirectory count];
                            for(int i = 0; i < contentcount; i++) {
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
                    }
                    [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Torngat_TMP_Mask_DIR/" error:nil];
                    [[NSFileManager defaultManager] removeItemAtPath:@"/var/containers/Shared/SystemGroup/systemgroup.com.apple.lsd.iconscache/Library/Caches/com.apple.IconsCache/" error:nil];
                    [[NSFileManager defaultManager] createDirectoryAtPath:@"/var/containers/Shared/SystemGroup/systemgroup.com.apple.lsd.iconscache/Library/Caches/com.apple.IconsCache/" withIntermediateDirectories:false attributes:nil error:nil];
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Success" message:@"Please respring your device." preferredStyle:UIAlertControllerStyleAlert];
                    UIAlertAction *dismiss = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleCancel handler:nil];
                    UIAlertAction *respring = [UIAlertAction actionWithTitle:@"Respring" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
                        respringDevice();
                    }];
                    [alert addAction:dismiss];
                    if (!dontRespring) { [alert addAction:respring]; }
                    unfreeze();
                    [self.presentedViewController dismissViewControllerAnimated:YES completion:^{
                        [self presentViewController:alert animated:YES completion:nil];
                    }];
                    applyingMask = false;
                } else {
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Failed" message:@"No data was received." preferredStyle:UIAlertControllerStyleAlert];
                    UIAlertAction *action = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleCancel handler:nil];
                    [alert addAction:action];
                    unfreeze();
                    [self.presentedViewController dismissViewControllerAnimated:YES completion:^{
                        [self presentViewController:alert animated:YES completion:nil];
                    }];
                    applyingMask = false;
                }
            }];
            [alert addAction:no];
            [alert addAction:yes];
            [self presentViewController:alert animated:YES completion:nil];
            if (self.presentingViewController && self.presentedViewController != alert) {
                [self.presentedViewController dismissViewControllerAnimated:YES completion:^{
                    if (darkModeIsEnabled()) {
                        [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent];
                    } else {
                        [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault];
                    }
                    [self presentViewController:alert animated:YES completion:nil];
                }];
            }
        }
    }
}

- (void)urlScheme {
    if (![___URL isEqual:@"NULL"] && ![___URL isEqual:@"(null)"]) {
        NSString *____URL = [NSString stringWithFormat:@"%@", ___URL];
        ___URL = @"NULL";
        [self _urlScheme:____URL];
    }
}

@end

@interface tweaksView ()
@property (strong, nonatomic) IBOutlet UIButton *resbtn;
@property (strong, nonatomic) IBOutlet UIButton *cc;
@property (strong, nonatomic) IBOutlet UIButton *rebootbtn;
@property (strong, nonatomic) IBOutlet UIButton *brb;
@property (strong, nonatomic) IBOutlet UIButton *bub;
@property (strong, nonatomic) IBOutlet UIWebView *web;
@property (strong, nonatomic) IBOutlet UIButton *maskBtn;
@property (strong, nonatomic) IBOutlet UIButton *bootlogo;
@property (strong, nonatomic) IBOutlet UIButton *fontsBtn;
@property (strong, nonatomic) IBOutlet UIButton *badgeBtn;
@property (strong, nonatomic) IBOutlet UIScrollView *scroll;
@property (strong, nonatomic) IBOutlet UIView *sticky;
@property (strong, nonatomic) IBOutlet UIButton *dscb;
@property (strong, nonatomic) IBOutlet UIButton *exit;
@property (strong, nonatomic) IBOutlet UIView *resview;
@property (strong, nonatomic) IBOutlet UIView *brview;
@property (strong, nonatomic) IBOutlet UIView *buview;
@property (strong, nonatomic) IBOutlet UIView *maskview;
@property (strong, nonatomic) IBOutlet UIView *bootlogoview;
@property (strong, nonatomic) IBOutlet UIView *dscbview;
@property (strong, nonatomic) IBOutlet UIView *ccview;
@property (strong, nonatomic) IBOutlet UIView *badgeview;
@property (strong, nonatomic) IBOutlet UIView *fontsview;
@property (strong, nonatomic) IBOutlet UIView *cncv;
@property (strong, nonatomic) IBOutlet UIButton *cncb;

@end

@implementation tweaksView

- (NSString *)getFE:(NSURL *)url{
    NSString *urlString = [url absoluteString];
    NSArray *componentsArray = [urlString componentsSeparatedByString:@"."];
    NSString *fileExtension = [componentsArray lastObject];
    return fileExtension;
}

- (IBAction)bootlogo:(id)sender {
    [self sVC:@"bootlogo"];
}

- (IBAction)exit:(id)sender {
    respringDevice();
}

- (IBAction)dscb:(id)sender {
    [self sVC:@"dockLine"];
}

- (void)applyBtn:(UIButton*)buttonIdentifier really:(int)really c:(int)c {
    if (really == 1) {
        if (darkModeIsEnabled()) {
            buttonIdentifier.backgroundColor = hex(0x544D45, 1.0);
            [buttonIdentifier setTitleColor:hex(0xFFFFFF, 1.0) forState:UIControlStateNormal];
        } else {
            buttonIdentifier.backgroundColor = [UIColor colorWithRed:171 green:178 blue:186 alpha:1.0f];
            [buttonIdentifier setTitleColor:hex(0x000000, 1.0) forState:UIControlStateNormal];
        }
        buttonIdentifier.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
        buttonIdentifier.layer.shadowOffset = CGSizeMake(0, 0);
        buttonIdentifier.layer.shadowOpacity = 1.0f;
        buttonIdentifier.layer.shadowRadius = 5;
        buttonIdentifier.layer.masksToBounds = NO;
        buttonIdentifier.layer.cornerRadius = 10.0f;
    }
    buttonIdentifier.exclusiveTouch = YES;
    if (c == 1) {
        if (darkModeIsEnabled())
            [buttonIdentifier setTitleColor:[UIColor darkTextColor] forState:UIControlStateNormal];
        else
            [buttonIdentifier setTitleColor:hex(0x007AFF, 1.0) forState:UIControlStateNormal];
    }
#ifndef guionly
    struct utsname u;
    uname(&u);
    NSString *device = [NSString stringWithFormat:@"%s", u.machine];
    if ([device isEqual:@"iPhone10,3"] || [device isEqual:@"iPhone10,6"]) {
        [_dscb setEnabled:NO];
        [_dscb bgDisabledColour];
        [_dscbview setAlpha:0.5f];
    }
    if (SYSTEM_VERSION_LESS_THAN(@"11.1")) {
        [_fontsBtn setEnabled:NO];
        [_fontsBtn bgDisabledColour];
        [_fontsview setAlpha:0.5f];
    }
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        [_dscb setEnabled:NO];
        [_dscb bgDisabledColour];
        [_dscbview setAlpha:0.5f];
    }
    if (!remounted()) {
        [_brb setEnabled:NO];
        [_brb bgDisabledColour];
        [_maskBtn setEnabled:NO];
        [_maskBtn bgDisabledColour];
        [_bootlogo setEnabled:NO];
        [_bootlogo bgDisabledColour];
        [_fontsBtn setEnabled:NO];
        [_fontsBtn bgDisabledColour];
        [_cc setEnabled:NO];
        [_cc bgDisabledColour];
        //[_sticky setHidden:YES];
        //[_rebootbtn setHidden:YES];
        [_brview setAlpha:0.5f];
        [_maskview setAlpha:0.5f];
        [_bootlogoview setAlpha:0.5f];
        [_fontsview setAlpha:0.5f];
        [_ccview setAlpha:0.5f];
    }
#endif
}

- (void)av:(UIView*)viewID {
    if (darkModeIsEnabled()) {
        viewID.backgroundColor = hex(0xD9D9D9, 1.0);
    } else {
        viewID.backgroundColor = hex(0xE0E0E0, 1.0);
    }
    viewID.layer.masksToBounds = YES;
    viewID.layer.cornerRadius = 10.0f;
}

- (void)visualStyle {
    [self.navigationController.navigationBar setValue:@(YES) forKeyPath:@"hidesShadow"];
    if (darkModeIsEnabled()) {
        [_scroll setIndicatorStyle:UIScrollViewIndicatorStyleWhite];
        [self.navigationController.navigationBar setBarStyle:UIBarStyleBlack];
        [self.navigationController.navigationBar setBarTintColor:hex(0x1B2737, 1.0)];
        [self.view setBackgroundColor:hex(0x151E29, 1.0)];
        [_sticky setBackgroundColor:hex(0x708090, 0.65)];
    } else {
        [_scroll setIndicatorStyle:UIScrollViewIndicatorStyleBlack];
        [self.navigationController.navigationBar setBarStyle:UIBarStyleDefault];
        //  [self.navigationController.navigationBar setBarTintColor:nil];
        [self.navigationController.navigationBar setBarTintColor:hex(0xF2F2F2, 1.0)];
        [self.view setBackgroundColor:hex(0xFAFAFA, 1.0)];
        [self.sticky setBackgroundColor:hex(0xEBEBF1, 0.65)];
    }
    [self applyBtn:_resbtn really:0 c:1];
    [self applyBtn:_cc really:0 c:1];
    [self applyBtn:_rebootbtn really:1 c:0];
    [self applyBtn:_brb really:0 c:1];
    [self applyBtn:_bub really:0 c:1];
    [self applyBtn:_maskBtn really:0 c:1];
    [self applyBtn:_bootlogo really:0 c:1];
    [self applyBtn:_badgeBtn really:0 c:1];
    [self applyBtn:_dscb really:0 c:1];
    [self applyBtn:_cncb really:0 c:1];
    [self applyBtn:_exit really:1 c:0];
    [self av:_resview];
    [self av:_brview];
    [self av:_buview];
    [self av:_ccview];
    [self av:_dscbview];
    [self av:_maskview];
    [self av:_badgeview];
    [self av:_fontsview];
    [self av:_bootlogoview];
    [self av:_cncv];
    [_exit setBackgroundColor:[UIColor redColor]];
    [_exit setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    if (!file_exist("/System/Library/Fonts/Core/AppleColorEmoji.ttc") && !file_exist("/System/Library/Fonts/Core/AppleColorEmoji@1x.ttc") && file_exist("/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc") && !file_exist("/System/Library/Fonts/Core/AppleColorEmoji@3x.ttc")) {
        [self applyBtn:_fontsBtn really:0 c:1];
    } else {
        [_fontsBtn setEnabled:NO];
        [_fontsBtn bgDisabledColour];
        [_fontsview setAlpha:0.5f];
    }
}

- (void)viewWillAppear:(BOOL)animated {
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(visualStyle)     name:@"updatedVisualStyle" object:nil];
    [self visualStyle];
}

- (void)sVC:(NSString*)vc {
    UIViewController *viewController = [self.storyboard instantiateViewControllerWithIdentifier:vc];
    viewController.providesPresentationContextTransitionStyle = YES;
    viewController.definesPresentationContext = YES;
    [viewController setModalPresentationStyle:UIModalPresentationOverFullScreen];
    [self presentViewController:viewController animated:YES completion:nil];
}

- (void)viewDidLoad {
    [super viewDidLoad];
}

- (IBAction)changeResolution:(id)sender {
    [self sVC:@"res"];
}

- (IBAction)blockRevokes:(id)sender {
    [self sVC:@"blockRevokes"];
}

- (IBAction)blockUpdates:(id)sender {
    [self sVC:@"blockUpdates"];
}

- (IBAction)masks:(id)sender {
    [self sVC:@"Masks"];
}

- (IBAction)badge:(id)sender {
    [self sVC:@"badges"];
}

- (IBAction)fonts:(id)sender {
    [self sVC:@"fonts"];
}

- (IBAction)cnc:(id)sender {
    [self sVC:@"layout"];
}

- (IBAction)exitApp:(id)sender {
    setgid(501);
    setuid(501);
    setegid(501);
    seteuid(501);
    exit(0);
    assert(NO);
}

- (void)request:(NSString *)address {
    NSURL *url = [NSURL URLWithString:address];
    NSURLRequest *urlRequest = [NSURLRequest requestWithURL:url];
    [_web loadRequest:urlRequest];
}

- (void)viewDidLayoutSubviews {
    /*if (dontRespring == FALSE) {
        self.scroll.contentSize = CGSizeMake(self.scroll.frame.size.width, (_resview.frame.size.height * 10) + 44 + _sticky.frame.size.height + _exit.frame.size.height + _rebootbtn.frame.size.height);
    } else {
        self.scroll.contentSize = CGSizeMake(self.scroll.frame.size.width, (_resview.frame.size.height * 10) + 44 + _exit.frame.size.height + _rebootbtn.frame.size.height);
    }*/
    RESIZE_SCROLLVIEW_0(_scroll, self.view.frame.size.width, [_rebootbtn superview].bounds.size.height - 18);
}

@end

@interface blockRevokes ()
@property (strong, nonatomic) IBOutlet UIView *alert;
@property (strong, nonatomic) IBOutlet UILabel *alertTitle;
@property (strong, nonatomic) IBOutlet UITextView *alertText;
@property (strong, nonatomic) IBOutlet UIButton *dismissAlertBtn;

@end

@implementation blockRevokes

- (void)calert:(NSString*)alertTitle alertMessage:(NSString*)alertMessage dismissButton:(NSString*)dismissButton buttonVis:(int)buttonVis dismissBtnAction:(SEL)dismissBtnAction {
    [_dismissAlertBtn setExclusiveTouch:YES];
    [_cancel setEnabled:NO];
    [_alert setAlpha:0.0]; [_X setAlpha:0.0];
    [_alertTitle setText:alertTitle];
    [_alertText setText:alertMessage];
    if (buttonVis == 0) {
        [_dismissAlertBtn setHidden:YES];
    } else if (buttonVis == 1) {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:@selector(calertd) forControlEvents:UIControlEventTouchUpInside];
    } else {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:dismissBtnAction forControlEvents:UIControlEventTouchUpInside];
    }
    [_alert setHidden:NO]; [_X setHidden:NO];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:1.0f]; [_X setAlpha:1.0f];
    }];
}

- (void)calertd {
    [_alert setAlpha:1.0f];
    [_X setAlpha:1.0f];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:0.0f];
        [_X setAlpha:0.0f];
    }];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{[_alert setHidden:YES];[_X setHidden:YES];});});
    [_cancel setEnabled:YES];
}

- (IBAction)xBtnPressed:(id)sender {
    [self calertd];
}

- (void)check {
    if ([[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] containsString:@"127.0.0.1 ocsp.apple.com\n"]) {
        [_block setTitle:@"Unblock" forState:UIControlStateNormal];
    } else {
        [_block setTitle:@"Block" forState:UIControlStateNormal];
    }
}

- (void)applyBtn:(UIButton*)btnId {
    btnId.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
    btnId.layer.shadowOffset = CGSizeMake(0, 0);
    btnId.layer.shadowOpacity = 1.0f;
    btnId.layer.shadowRadius = 5;
    btnId.layer.masksToBounds = NO;
    btnId.layer.cornerRadius = 10.0f;
    btnId.exclusiveTouch = YES;
}

- (void)fixOld {
    if (![[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] containsString:@"donteditthisentry.torngat.1gamerdev.rf.gd"]) return;
    NSLog(@"%@", [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil]);
    [[[[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] stringByReplacingOccurrencesOfString:@"127.0.0.1 donteditthisentry.torngat.1gamerdev.rf.gd ocsp.apple.com oscp.apple.com" withString:@"127.0.0.1 ocsp.apple.com\n"] stringByReplacingOccurrencesOfString:@"127.0.0.1 donteditthisentry.torngat.1gamerdev.rf.gd disabledblockrevokes.apple.com" withString:@""] writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"%@", [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil]);
}

- (void)viewWillAppear:(BOOL)animated {
    [self fixOld];
    [self applyBtn:_block];
    [self applyBtn:_cancel];
    [self check];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
}

- (IBAction)cancel:(id)sender {
    if(!darkModeIsEnabled()){[[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault animated:YES];}
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (IBAction)block:(id)sender {
    if ([[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] containsString:@"127.0.0.1 ocsp.apple.com\n"]) {
        [[[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] stringByReplacingOccurrencesOfString:@"127.0.0.1 ocsp.apple.com\n" withString:@""] writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [self calert:@"Success" alertMessage:@"Enterprise revocations have been unblocked." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
        [self check];
    } else {
        NSString *b = @"\n";
        if ([[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] hasSuffix:@"\n"]) {
            b = @"";
        }
        NSString *str = [NSString stringWithFormat:@"%@%@127.0.0.1 ocsp.apple.com\n", [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil], b];
        [str writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [self calert:@"Success" alertMessage:@"Enterprise revocations have been blocked." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
        [self check];
    }
}

@end

@interface blockUpdates ()
@property (strong, nonatomic) IBOutlet UIView *alert;
@property (strong, nonatomic) IBOutlet UILabel *alertTitle;
@property (strong, nonatomic) IBOutlet UITextView *alertText;
@property (strong, nonatomic) IBOutlet UIButton *dismissAlertBtn;
@property (strong, nonatomic) IBOutlet UITextView *desc;
@property (strong, nonatomic) IBOutlet UIButton *tvOSBTN;

@end

@implementation blockUpdates

- (void)calert:(NSString*)alertTitle alertMessage:(NSString*)alertMessage dismissButton:(NSString*)dismissButton buttonVis:(int)buttonVis dismissBtnAction:(SEL)dismissBtnAction {
    [_dismissAlertBtn setExclusiveTouch:YES];
    [_cancel setEnabled:NO];
    [_alert setAlpha:0.0]; [_X setAlpha:0.0];
    [_alertTitle setText:alertTitle];
    [_alertText setText:alertMessage];
    if (buttonVis == 0) {
        [_dismissAlertBtn setHidden:YES];
    } else if (buttonVis == 1) {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:@selector(calertd) forControlEvents:UIControlEventTouchUpInside];
    } else {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:dismissBtnAction forControlEvents:UIControlEventTouchUpInside];
    }
    [_alert setHidden:NO]; [_X setHidden:NO];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:1.0f]; [_X setAlpha:1.0f];
    }];
}

- (void)calertd {
    [_alert setAlpha:1.0f];
    [_X setAlpha:1.0f];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:0.0f];
        [_X setAlpha:0.0f];
    }];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{[_alert setHidden:YES];[_X setHidden:YES];});});
    [_cancel setEnabled:YES];
}

- (IBAction)xBtnPressed:(id)sender {
    [self calertd];
}

- (void)applyBtn:(UIButton*)btnId {
    btnId.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
    btnId.layer.shadowOffset = CGSizeMake(0, 0);
    btnId.layer.shadowOpacity = 1.0f;
    btnId.layer.shadowRadius = 5;
    btnId.layer.masksToBounds = NO;
    btnId.layer.cornerRadius = 10.0f;
    btnId.exclusiveTouch = YES;
}

- (IBAction)tvOSShit:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/1GamerDev/Torngat-Files/raw/master/tvOS.mobileconfig"]];
    [self calert:@"Success" alertMessage:@"OTA Updates have been blocked." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
}

- (void)check {
    if (!remounted()) {
        return;
    }
    if ([[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] containsString:@"127.0.0.1 mesu.apple.com\n"]) {
        [_block setTitle:@"Unblock" forState:UIControlStateNormal];
    } else {
        [_block setTitle:@"Block" forState:UIControlStateNormal];
    }
}

- (void)fixOld {
    if (![[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] containsString:@"donteditthisentry.torngat.1gamerdev.rf.gd"]) return;
    NSLog(@"%@", [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil]);
    [[[[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] stringByReplacingOccurrencesOfString:@"127.0.0.1 donteditthisentry.torngat.1gamerdev.rf.gd mesu.apple.com" withString:@"127.0.0.1 mesu.apple.com\n"] stringByReplacingOccurrencesOfString:@"127.0.0.1 donteditthisentry.torngat.1gamerdev.rf.gd disabledblockupdates.apple.com" withString:@""] writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"%@", [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil]);
}

- (void)viewWillAppear:(BOOL)animated {
    [self fixOld];
    [self applyBtn:_block];
    if (!remounted()) {
        [_block bgDisabledColour];
        [_block setEnabled:NO];
    }
    [self applyBtn:_tvOSBTN];
    [self applyBtn:_cancel];
    [self check];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
}

- (IBAction)cancel:(id)sender {
    if(!darkModeIsEnabled()){[[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault animated:YES];}
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (IBAction)block:(id)sender {
    if ([[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] containsString:@"127.0.0.1 mesu.apple.com\n"]) {
        [[[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] stringByReplacingOccurrencesOfString:@"127.0.0.1 mesu.apple.com\n" withString:@""] writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [self calert:@"Success" alertMessage:@"OTA Updates have been unblocked." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
        [self check];
    } else {
        NSString *b = @"\n";
        if ([[NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil] hasSuffix:@"\n"]) {
            b = @"";
        }
        NSString *str = [NSString stringWithFormat:@"%@%@127.0.0.1 mesu.apple.com\n", [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil], b];
        [str writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [self calert:@"Success" alertMessage:@"OTA Updates have been blocked." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
        [self check];
    }
}

@end

@interface res ()
@property (strong, nonatomic) IBOutlet UITextField *h;
@property (strong, nonatomic) IBOutlet UITextField *w;
@property (strong, nonatomic) IBOutlet UIView *alert;
@property (strong, nonatomic) IBOutlet UILabel *alertTitle;
@property (strong, nonatomic) IBOutlet UITextView *alertText;
@property (strong, nonatomic) IBOutlet UIButton *dismissAlertBtn;
@property (strong, nonatomic) IBOutlet UIButton *xBtn;

@end

@implementation res

- (void)calert:(NSString*)alertTitle alertMessage:(NSString*)alertMessage dismissButton:(NSString*)dismissButton buttonVis:(int)buttonVis dismissBtnAction:(SEL)dismissBtnAction {
    [_dismissAlertBtn setExclusiveTouch:YES];
    [_cancel setEnabled:NO];
    [_alert setAlpha:0.0]; [_X setAlpha:0.0];
    [_alertTitle setText:alertTitle];
    [_alertText setText:alertMessage];
    if (buttonVis == 0) {
        [_dismissAlertBtn setHidden:YES];
    } else if (buttonVis == 1) {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:@selector(calertd) forControlEvents:UIControlEventTouchUpInside];
    } else {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:dismissBtnAction forControlEvents:UIControlEventTouchUpInside];
    }
    [_alert setHidden:NO]; [_X setHidden:NO];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:1.0f]; [_X setAlpha:1.0f];
    }];
}

- (void)calertd {
    [_alert setAlpha:1.0f];
    [_X setAlpha:1.0f];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:0.0f];
        [_X setAlpha:0.0f];
    }];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{[_alert setHidden:YES];[_X setHidden:YES];});});
    [_cancel setEnabled:YES];
}

- (IBAction)xBtnPressed:(id)sender {
    [self calertd];
}

- (IBAction)dismissKeyboard:(id)sender {
    [self.view endEditing:YES];
}

- (void)applyBtn:(UIButton*)btnId {
    btnId.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
    btnId.layer.shadowOffset = CGSizeMake(0, 0);
    btnId.layer.shadowOpacity = 1.0f;
    btnId.layer.shadowRadius = 5;
    btnId.layer.masksToBounds = NO;
    btnId.layer.cornerRadius = 10.0f;
    btnId.exclusiveTouch = YES;
}

- (NSString *)machineName {
    struct utsname systemInfo;
    uname(&systemInfo);
    return [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];
}

- (void)viewWillAppear:(BOOL)animated {
    [self applyBtn:_change];
    [self applyBtn:_cancel];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    if (file_exist("/var/mobile/Library/Preferences/com.apple.iokit.IOMobileGraphicsFamily.plist")) {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.iokit.IOMobileGraphicsFamily.plist"];
        _w.text = [NSString stringWithFormat:@"%@", [d valueForKey:@"canvas_width"]];
        _h.text = [NSString stringWithFormat:@"%@", [d valueForKey:@"canvas_height"]];
    } else {
        _w.text = [NSString stringWithFormat:@"Width"];
        _h.text = [NSString stringWithFormat:@"Height"];
    }
}

- (IBAction)cancel:(id)sender {
    if(!darkModeIsEnabled()){[[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault animated:YES];}
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)continueChangeRes {
    [self calertd];
    if (file_exist("/var/mobile/Library/Preferences/com.apple.iokit.IOMobileGraphicsFamily.plist")) {
    NSString *width = _w.text;
    NSString *height = _h.text;
    width = [width stringByReplacingOccurrencesOfString:@"px" withString:@""];
    height = [height stringByReplacingOccurrencesOfString:@"px" withString:@""];
    NSMutableDictionary *res = [NSMutableDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.iokit.IOMobileGraphicsFamily.plist"];
    [res setValue:height forKey:@"canvas_height"];
    [res setValue:width forKey:@"canvas_width"];
    [res writeToFile:@"/var/mobile/Library/Preferences/com.apple.iokit.IOMobileGraphicsFamily.plist" atomically:YES];
    [self calertd];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [NSThread sleepForTimeInterval:0.6f];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self calert:@"Success" alertMessage:@"Please reboot your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
        });
    });
    } else {
        NSString *width = _w.text;
        NSString *height = _h.text;
        width = [width stringByReplacingOccurrencesOfString:@"px" withString:@""];
        height = [height stringByReplacingOccurrencesOfString:@"px" withString:@""];
        NSString *res = [NSString stringWithFormat:@"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>canvas_height</key><integer>%@</integer><key>canvas_width</key><integer>%@</integer></dict></plist>", height, width];
        [self calertd];
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [NSThread sleepForTimeInterval:0.6f];
            dispatch_async(dispatch_get_main_queue(), ^{
                [self calert:@"Success" alertMessage:@"Please reboot your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
            });
        });
    }
}

- (IBAction)change:(id)sender {
    NSString *width = _w.text;
    NSString *height = _h.text;
    width = [width stringByReplacingOccurrencesOfString:@"px" withString:@""];
    height = [height stringByReplacingOccurrencesOfString:@"px" withString:@""];
    if (width != NULL && height != NULL && ![width isEqual: @""] && ![height isEqual: @""]) {
        NSCharacterSet *notDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
        if ([width rangeOfCharacterFromSet:notDigits].location == NSNotFound && [height rangeOfCharacterFromSet:notDigits].location == NSNotFound) {
            if (![width containsString:@"."] && ![height containsString:@"."]) {
                [self calert:@"Confirmation" alertMessage:@"Changing your resolution may cause unintended side-effects or even stop your device from functioning.  Are you sure you'd like to continue?  (Please make sure you have a backup of your data, because if something goes wrong, you'll have to restore your device via iCloud then load the backup)" dismissButton:@"Continue" buttonVis:2 dismissBtnAction:@selector(continueChangeRes)];
            } else {
                [self calert:@"Error" alertMessage:@"Your width / height may not contain a decimal point." dismissButton:@"Dismiss" buttonVis:0 dismissBtnAction:nil];
            }
        } else {
            [self calert:@"Error" alertMessage:@"Your width / height may only be numeric." dismissButton:@"Dismiss" buttonVis:0 dismissBtnAction:nil];
        }
    } else {
        [self calert:@"Error" alertMessage:@"Please provide the width and height of your new resolution." dismissButton:@"Dismiss" buttonVis:0 dismissBtnAction:nil];
    }
}

@end

NSString *resizeIdentifier;

@interface resizeViewController ()
@property (weak, nonatomic) IBOutlet UILabel *resizeLabel;
@property (weak, nonatomic) IBOutlet UISlider *heightSlider;
@property (weak, nonatomic) IBOutlet UISlider *widthSlider;
@property (weak, nonatomic) IBOutlet UILabel *heightLabel;
@property (weak, nonatomic) IBOutlet UILabel *widthLabel;
@property (weak, nonatomic) IBOutlet UIButton *saveButton;
@property (weak, nonatomic) IBOutlet UILabel *h;
@property (weak, nonatomic) IBOutlet UILabel *w;

@end

@implementation resizeViewController

- (IBAction)heightChanged:(id)sender {
    _heightLabel.text = [NSString stringWithFormat:@"%i", (int)_heightSlider.value];
}

- (IBAction)widthChanged:(id)sender {
    _widthLabel.text = [NSString stringWithFormat:@"%i", (int)_widthSlider.value];
}

- (void)calert {
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    UIViewController *viewController = [self.storyboard instantiateViewControllerWithIdentifier:@"bigFullscreenBoi"];
    viewController.providesPresentationContextTransitionStyle = YES;
    viewController.definesPresentationContext = YES;
    [viewController setModalPresentationStyle:UIModalPresentationOverFullScreen];
    [self presentViewController:viewController animated:NO completion:nil];
}

- (void)applyBtn:(UIButton*)btnId {
    btnId.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
    btnId.layer.shadowOffset = CGSizeMake(0, 0);
    btnId.layer.shadowOpacity = 1.0f;
    btnId.layer.shadowRadius = 5;
    btnId.layer.masksToBounds = NO;
    btnId.layer.cornerRadius = 10.0f;
    btnId.exclusiveTouch = YES;
}

- (void)visualStyle {
    [self.navigationController.navigationBar setValue:@(YES) forKeyPath:@"hidesShadow"];
    if (darkModeIsEnabled()) {
        _resizeLabel.textColor = [UIColor lightTextColor];
        _h.textColor = [UIColor lightTextColor];
        _w.textColor = [UIColor lightTextColor];
        _heightLabel.textColor = [UIColor lightTextColor];
        _widthLabel.textColor = [UIColor lightTextColor];
        [self.navigationController.navigationBar setBarStyle:UIBarStyleBlack];
        [self.view setBackgroundColor:hex(0x151E29, 1.0)];
        [self.navigationController.navigationBar setBarTintColor:hex(0x1B2737, 1.0)];
    } else {
        _resizeLabel.textColor = [UIColor darkTextColor];
        _h.textColor = [UIColor darkTextColor];
        _w.textColor = [UIColor darkTextColor];
        _heightLabel.textColor = [UIColor darkTextColor];
        _widthLabel.textColor = [UIColor darkTextColor];
        [self.navigationController.navigationBar setBarStyle:UIBarStyleDefault];
        [self.navigationController.navigationBar setBarTintColor:hex(0xF2F2F2, 1.0)];
        [self.view setBackgroundColor:hex(0xFAFAFA, 1.0)];
    }
}

- (void)viewWillAppear:(BOOL)animated {
    [self applyBtn:_saveButton];
    [self visualStyle];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(visualStyle)     name:@"updatedVisualStyle" object:nil];
    _resizeLabel.text = [NSString stringWithFormat:@"Resize %@", resizeIdentifier];
#ifndef guionly
    NSString *path;
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~iphone.plist"]) {
        path = @"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~iphone.plist";
    } else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~ipad.plist"]) {
        path = @"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~ipad.plist";
    } else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~ipod.plist"]) {
        path = @"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~ipod.plist";
    } else {
        bigFullscreenBoiTitle = @"Error";
        bigFullscreenBoiText = nil;
        [self calert];
        return;
    }
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:path];
    NSLog(@"%@", plist);
    NSMutableDictionary *ri = [plist objectForKey:resizeIdentifier];
    NSMutableDictionary *size = [ri objectForKey:@"size"];
    int height = [[size valueForKey:@"height"] intValue];
    int width = [[size valueForKey:@"width"] intValue];
    _heightSlider.value = height;
    _widthSlider.value = width;
    _heightLabel.text = [NSString stringWithFormat:@"%i", height];
    _widthLabel.text = [NSString stringWithFormat:@"%i", width];
#endif
}

- (IBAction)save:(id)sender {
    NSString *path;
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~iphone.plist"]) {
        path = @"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~iphone.plist";
    } else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~ipad.plist"]) {
        path = @"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~ipad.plist";
    } else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~ipod.plist"]) {
        path = @"/System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~ipod.plist";
    } else {
        bigFullscreenBoiTitle = @"Error";
        bigFullscreenBoiText = nil;
        [self calert];
        return;
    }
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:path];
    NSMutableDictionary *ri = [plist objectForKey:resizeIdentifier];
    if (ri == nil) {
        ri = [NSMutableDictionary dictionary];
        NSMutableDictionary *size = [NSMutableDictionary dictionary];
        if ((int)_heightSlider.value != 0) {
            [size setObject:[NSNumber numberWithInt:(int)_heightSlider.value] forKey:@"height"];
        } else {
            if ([[size allKeys] containsObject:@"height"]) {
                [size removeObjectForKey:@"height"];
            }
        }
        if ((int)_widthSlider.value != 0) {
            [size setObject:[NSNumber numberWithInt:(int)_widthSlider.value] forKey:@"width"];
        } else {
            if ([[size allKeys] containsObject:@"width"]) {
                [size removeObjectForKey:@"width"];
            }
        }
        if ([[size allKeys] isEqual:@[]]) {
            bigFullscreenBoiTitle = @"Success";
            bigFullscreenBoiText = @"Please respring your device.";
            [self calert];
            return;
        } else {
            [ri setObject:size forKey:@"size"];
            [plist setObject:ri forKey:resizeIdentifier];
        }
        bigFullscreenBoiTitle = @"Success";
        bigFullscreenBoiText = @"Please respring your device.";
        [self calert];
        return;
    }
    NSMutableDictionary *size = [ri objectForKey:@"size"];
    if ((int)_heightSlider.value != 0) {
        [size setObject:[NSNumber numberWithInt:(int)_heightSlider.value] forKey:@"height"];
    } else {
        if ([[size allKeys] containsObject:@"height"]) {
            [size removeObjectForKey:@"height"];
        }
    }
    if ((int)_widthSlider.value != 0) {
        [size setObject:[NSNumber numberWithInt:(int)_widthSlider.value] forKey:@"width"];
    } else {
        if ([[size allKeys] containsObject:@"width"]) {
            [size removeObjectForKey:@"width"];
        }
    }
    if ([[size allKeys] isEqual:@[]]) {
        [plist removeObjectForKey:resizeIdentifier];
    } else {
        [ri setObject:size forKey:@"size"];
        [plist setObject:ri forKey:resizeIdentifier];
    }
    [plist writeToFile:path atomically:YES];
    bigFullscreenBoiTitle = @"Success";
    bigFullscreenBoiText = @"Please respring your device.";
    [self calert];
}

@end

@interface cc ()
@property (weak, nonatomic) IBOutlet UILabel *customisationLabel;
@property (weak, nonatomic) IBOutlet UITextView *customisationDescription;
@property (weak, nonatomic) IBOutlet UILabel *resizeLabel;
@property (weak, nonatomic) IBOutlet UITextView *resizeDescription;
@property (strong, nonatomic) IBOutlet UIButton *e1btn;
@property (strong, nonatomic) IBOutlet UIButton *d1btn;
@property (strong, nonatomic) IBOutlet UIButton *e2btn;
@property (strong, nonatomic) IBOutlet UIScrollView *scroll;
@property (strong, nonatomic) IBOutlet UIView *alert;
@property (strong, nonatomic) IBOutlet UILabel *shortDesc;
@property (strong, nonatomic) IBOutlet UILabel *desc;
@property (weak, nonatomic) IBOutlet UITableView *resizeTableView;
@property (strong,nonatomic) NSArray *tv1c;

@end

@implementation cc

- (void)calert {
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    UIViewController *viewController = [self.storyboard instantiateViewControllerWithIdentifier:@"bigFullscreenBoi"];
    viewController.providesPresentationContextTransitionStyle = YES;
    viewController.definesPresentationContext = YES;
    [viewController setModalPresentationStyle:UIModalPresentationOverFullScreen];
    [self presentViewController:viewController animated:NO completion:nil];
}

- (void)e1go:(NSString *)path {
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:path];
    [plist setObject:@[] forKey:@"fixed"];
    NSArray *fixed = @[@"com.apple.control-center.ConnectivityModule", @"com.apple.mediaremote.controlcenter.nowplaying", @"com.apple.control-center.DisplayModule", @"com.apple.control-center.AudioModule", @"com.apple.mediaremote.controlcenter.airplaymirroring", @"com.apple.control-center.OrientationLockModule", @"com.apple.control-center.MuteModule", @"com.apple.control-center.DoNotDisturbModule"];
    NSArray *arr = [NSArray arrayWithArray:fixed];
    NSArray *u = [plist objectForKey:@"user-enabled"];
    if (![u isEqual:@[]] && u != nil) {
        arr = [arr arrayByAddingObjectsFromArray:u];
    }
    [plist setObject:arr forKey:@"user-enabled"];
    [plist writeToFile:path atomically:YES];
    plist = [NSMutableDictionary dictionaryWithContentsOfFile:@"/private/var/mobile/Library/ControlCenter/ModuleConfiguration.plist"];
    NSArray *mi = [NSArray arrayWithArray:fixed];
    NSArray *m = [plist objectForKey:@"module-identifiers"];
    if (![mi isEqual:@[]] && mi != nil) {
        mi = [mi arrayByAddingObjectsFromArray:m];
    }
    [plist setObject:mi forKey:@"module-identifiers"];
    [plist writeToFile:@"/private/var/mobile/Library/ControlCenter/ModuleConfiguration.plist" atomically:YES];
    bigFullscreenBoiTitle = @"Success NO_RESPRING";
    bigFullscreenBoiText = @"Control centre module customisation has been enabled.";
    [self calert];
    [self s1];
}

- (void)d1go:(NSString *)path {
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:path];
    NSArray *fixed = @[@"com.apple.control-center.ConnectivityModule", @"com.apple.mediaremote.controlcenter.nowplaying", @"com.apple.control-center.DisplayModule", @"com.apple.control-center.AudioModule", @"com.apple.mediaremote.controlcenter.airplaymirroring", @"com.apple.control-center.OrientationLockModule", @"com.apple.control-center.MuteModule", @"com.apple.control-center.DoNotDisturbModule"];
    [plist setObject:fixed forKey:@"fixed"];
    NSArray *ue = [plist objectForKey:@"user-enabled"];
    NSArray *arr = [ue arrayByRemovingObjectsFromArray:fixed];
    [plist setObject:arr forKey:@"user-enabled"];
    [plist writeToFile:path atomically:YES];
    plist = [NSMutableDictionary dictionaryWithContentsOfFile:@"/private/var/mobile/Library/ControlCenter/ModuleConfiguration.plist"];
    NSArray *mi = [plist objectForKey:@"module-identifiers"];
    NSLog(@"%@", mi);
    mi = [mi arrayByRemovingObjectsFromArray:fixed];
    NSLog(@"%@", mi);
    [plist setObject:mi forKey:@"module-identifiers"];
    [plist writeToFile:@"/private/var/mobile/Library/ControlCenter/ModuleConfiguration.plist" atomically:YES];
    bigFullscreenBoiTitle = @"Success NO_RESPRING";
    bigFullscreenBoiText = @"Control centre module customisation has been disabled.";
    [self calert];
    [self s1];
}

- (IBAction)e1:(id)sender {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~iphone.plist"]) {
        [self e1go:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~iphone.plist"];
    } else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipad.plist"]) {
        [self e1go:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipad.plist"];
    } else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipod.plist"]) {
        [self e1go:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipod.plist"];
    } else {
        bigFullscreenBoiTitle = @"Error";
        bigFullscreenBoiText = nil;
        [self calert];
    }
}

- (IBAction)d1:(id)sender {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~iphone.plist"]) {
        [self d1go:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~iphone.plist"];
    } else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipad.plist"]) {
        [self d1go:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipad.plist"];
    } else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipod.plist"]) {
        [self d1go:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipod.plist"];
    } else {
        bigFullscreenBoiTitle = @"Error";
        bigFullscreenBoiText = nil;
        [self calert];
    }
}

- (void)applyBtn:(UIButton*)btnId {
    btnId.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
    btnId.layer.shadowOffset = CGSizeMake(0, 0);
    btnId.layer.shadowOpacity = 1.0f;
    btnId.layer.shadowRadius = 5;
    btnId.layer.masksToBounds = NO;
    btnId.layer.cornerRadius = 10.0f;
    btnId.exclusiveTouch = YES;
}

- (BOOL)i1e {
    NSString *path;
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~iphone.plist"]) {
        path = @"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~iphone.plist";
    } else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipad.plist"]) {
        path = @"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipad.plist";
    } else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipod.plist"]) {
        path = @"/System/Library/PrivateFrameworks/ControlCenterServices.framework/DefaultModuleOrder~ipod.plist";
    }
    NSLog(@"%@", [[NSMutableDictionary dictionaryWithContentsOfFile:path] objectForKey:@"fixed"]);
    return [[[NSMutableDictionary dictionaryWithContentsOfFile:path] objectForKey:@"fixed"] isEqual:@[]];
}

- (void)s1 {
    if ([self i1e]) {
        [_e1btn setEnabled:NO];
        [_d1btn setEnabled:YES];
        [UIView animateWithDuration:0.5f animations:^{
            [_e1btn setBackgroundColor:hex(0xB8B8B8, 1.0)]; [_d1btn setBackgroundColor:hex(0xFF0033, 1.0)];
        }];
    } else {
        [_e1btn setEnabled:YES];
        [_d1btn setEnabled:NO];
        [UIView animateWithDuration:0.5f animations:^{
            [_e1btn setBackgroundColor:hex(0x007AFF, 1.0)]; [_d1btn setBackgroundColor:hex(0xB8B8B8, 1.0)];
        }];
    }
}

- (void)visualStyle {
    [self.navigationController.navigationBar setValue:@(YES) forKeyPath:@"hidesShadow"];
    if (darkModeIsEnabled()) {
        [_resizeTableView reloadData];
        _customisationLabel.textColor = [UIColor lightTextColor];
        _customisationDescription.textColor = [UIColor lightTextColor];
        _resizeLabel.textColor = [UIColor lightTextColor];
        _resizeDescription.textColor = [UIColor lightTextColor];
        [self.navigationController.navigationBar setBarStyle:UIBarStyleBlack];
        [self.view setBackgroundColor:hex(0x151E29, 1.0)];
        [self.navigationController.navigationBar setBarTintColor:hex(0x1B2737, 1.0)];
    } else {
        [_resizeTableView reloadData];
        _customisationLabel.textColor = [UIColor darkTextColor];
        _customisationDescription.textColor = [UIColor darkTextColor];
        _resizeLabel.textColor = [UIColor darkTextColor];
        _resizeDescription.textColor = [UIColor darkTextColor];
        [self.navigationController.navigationBar setBarStyle:UIBarStyleDefault];
        [self.navigationController.navigationBar setBarTintColor:hex(0xF2F2F2, 1.0)];
        [self.view setBackgroundColor:hex(0xFAFAFA, 1.0)];
    }
}

- (void)tableViewStuff {
    _resizeTableView.delegate = self;
    _resizeTableView.dataSource = self;
    _tv1c = @[@"gd.rf.1gamerdev.Torngat.placeholderModule"];
#ifndef guionly
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:@"/private/var/mobile/Library/ControlCenter/ModuleConfiguration.plist"];
    NSLog(@"%@", plist);
    _tv1c = @[@"com.apple.control-center.ConnectivityModule", @"com.apple.mediaremote.controlcenter.nowplaying", @"com.apple.control-center.DisplayModule", @"com.apple.control-center.AudioModule", @"com.apple.mediaremote.controlcenter.airplaymirroring", @"com.apple.control-center.OrientationLockModule", @"com.apple.control-center.MuteModule", @"com.apple.control-center.DoNotDisturbModule"];
#endif
}

- (void)viewWillAppear:(BOOL)animated {
    [self tableViewStuff];
    [self applyBtn:_e1btn];
    [self applyBtn:_d1btn];
    [self applyBtn:_e2btn];
    if ([self i1e]) {
        [_e1btn setEnabled:NO];
        [_d1btn setEnabled:YES];
        [_e1btn setBackgroundColor:hex(0xB8B8B8, 1.0)];
        [_d1btn setBackgroundColor:hex(0xFF0033, 1.0)];
    } else {
        [_e1btn setEnabled:YES];
        [_d1btn setEnabled:NO];
        [_e1btn setBackgroundColor:hex(0x007AFF, 1.0)];
        [_d1btn setBackgroundColor:hex(0xB8B8B8, 1.0)];
    }
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(visualStyle)     name:@"updatedVisualStyle" object:nil];
    [self visualStyle];
}

- (void)viewDidLayoutSubviews {
    RESIZE_SCROLLVIEW_0(_scroll, self.view.frame.size.width, 0);
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (tableView.tag == 0) {
        return _tv1c.count;
    }
    return 0;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (tableView.tag == 0) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@""];
        cell.textLabel.text =  [_tv1c objectAtIndex:indexPath.row];
        cell.textLabel.textColor = [UIColor blackColor];
        if (darkModeIsEnabled()) {
            cell.textLabel.textColor = [UIColor whiteColor];
        }
        cell.backgroundColor = [UIColor clearColor];
        cell.exclusiveTouch = true;
        cell.layer.cornerRadius = 5.0f;
        cell.layer.masksToBounds = true;
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        return cell;
    }
    return nil;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    if (tableView.tag == 0) {
        resizeIdentifier = [_tv1c objectAtIndex:indexPath.row];
        UIViewController *viewController = [self.storyboard instantiateViewControllerWithIdentifier:@"resizeViewController_"];
        [self.navigationController pushViewController:viewController animated:YES];
    }
}

@end

@interface Masks ()
@property (strong, nonatomic) IBOutlet UIView *alert;
@property (strong, nonatomic) IBOutlet UILabel *alertTitle;
@property (strong, nonatomic) IBOutlet UITextView *alertText;
@property (strong, nonatomic) IBOutlet UIButton *dismissAlertBtn;
@property (strong, nonatomic) IBOutlet UITextField *custommaskurl;
@property (strong, nonatomic) IBOutlet UIView *urlalert;
@property (strong, nonatomic) IBOutlet UIView *wait;
@property (strong, nonatomic) IBOutlet UIButton *respringBtn;

@end

@implementation Masks

- (IBAction)respringAction:(id)sender {
    respringDevice();
}

- (void)waitK {
    applyingMask = true;
    freeze();
    if ([stringWithContentsOfLocalFile(@"showLoader") isEqual: @"yes"]) {
        [_wait setHidden:NO];
        [_wait setAlpha:0.0f];
        [UIView animateWithDuration:0.5f animations:^{
            [_wait setAlpha:1.0f]; [_X setAlpha:1.0f];
        }];
    }
}

- (void)doneWaiting {
    if ([stringWithContentsOfLocalFile(@"showLoader") isEqual: @"yes"]) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
            [_wait setAlpha:1.0f];
            [UIView animateWithDuration:0.5f animations:^{
                [_wait setAlpha:0.0f]; [_X setAlpha:0.0f];
            } completion:^(BOOL finished) {
                [_wait setHidden:YES];
                applyingMask = false;
                unfreeze();
            }];
        });});
    }
}

- (void)calert:(NSString*)alertTitle alertMessage:(NSString*)alertMessage dismissButton:(NSString*)dismissButton buttonVis:(int)buttonVis dismissBtnAction:(SEL)dismissBtnAction {
    [_dismissAlertBtn setExclusiveTouch:YES];
    [_cancel setEnabled:NO];
    [_alert setAlpha:0.0]; [_X setAlpha:0.0];
    [_alertTitle setText:alertTitle];
    [_alertText setText:alertMessage];
    if (buttonVis == 0) {
        [_dismissAlertBtn setHidden:YES];
    } else if (buttonVis == 1) {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:@selector(calertd) forControlEvents:UIControlEventTouchUpInside];
    } else {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:dismissBtnAction forControlEvents:UIControlEventTouchUpInside];
    }
    [_alert setHidden:NO]; [_X setHidden:NO];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:1.0f]; [_X setAlpha:1.0f];
    }];
}

- (void)calertd {
    [_alert setAlpha:1.0f];
    [_X setAlpha:1.0f];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:0.0f];
        [_X setAlpha:0.0f];
    } completion:^(BOOL finished) {
        [_respringBtn setHidden:YES];
    }];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{[_alert setHidden:YES];[_X setHidden:YES];});});
    [_cancel setEnabled:YES];
}

- (IBAction)xBtnPressed:(id)sender {
    [self calertd];
}

- (NSString *)getFE:(NSURL *)url{
    NSString *urlString = [url absoluteString];
    NSArray *componentsArray = [urlString componentsSeparatedByString:@"."];
    NSString *fileExtension = [componentsArray lastObject];
    return fileExtension;
}

- (void)applyBtn:(UIButton*)btnId {
    btnId.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
    btnId.layer.shadowOffset = CGSizeMake(0, 0);
    btnId.layer.shadowOpacity = 1.0f;
    btnId.layer.shadowRadius = 5;
    btnId.layer.masksToBounds = NO;
    btnId.layer.cornerRadius = 10.0f;
    btnId.exclusiveTouch = YES;
}

- (void)checkWiFiC {
    if (noWiFi) {
        [UIView animateWithDuration:0.5f animations:^{
            [_custom bgDisabledColour];
        }];
        [_custom setEnabled:NO];
    } else {
        [UIView animateWithDuration:0.5f animations:^{
            [_custom bgBlueColour];
        }];
        [_custom setEnabled:YES];
    }
}

- (void)viewWillAppear:(BOOL)animated {
    [self applyBtn:_custom];
    [self applyBtn:_change];
    [self applyBtn:_cancel];
    [_respringBtn setHidden:YES];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    if (noWiFi) {
        [_custom bgDisabledColour];
        [_custom setEnabled:NO];
    }
    [NSTimer scheduledTimerWithTimeInterval:0.5 target:self selector:@selector(checkWiFiC) userInfo:nil repeats:YES];
}

- (IBAction)cancel:(id)sender {
    if(!darkModeIsEnabled()){[[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault animated:YES];}
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)applyMask:(NSString *)zipName {
    [SSZipArchive unzipFileAtPath:[[NSBundle mainBundle] pathForResource:zipName ofType:@"zip"] toDestination:@"/private/var/mobile/Torngat_TMP_Mask_DIR/"];
    NSLog(@"moving files");
    [self moveFiles];
    NSLog(@"removing");
    [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Torngat_TMP_Mask_DIR/" error:nil];    [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.lsd.iconscache/Library/Caches/com.apple.IconsCache/" error:nil];
    [[NSFileManager defaultManager] createDirectoryAtPath:@"/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.lsd.iconscache/Library/Caches/com.apple.IconsCache/" withIntermediateDirectories:false attributes:nil error:nil];
    NSLog(@"success");
    if (dontRespring == FALSE){[_respringBtn setHidden:NO];}
    [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
}

- (IBAction)change:(id)sender {
    NSInteger selectedSegment = _o.selectedSegmentIndex;
    if (selectedSegment == 0) {
        if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
            [self applyMask:@"iPadDefault"];
        } else {
            [self applyMask:@"iPhoneDefault"];
        }
    } else if (selectedSegment == 1) {
        [self applyMask:@"Circle"];
    } else if (selectedSegment == 2) {
        [self applyMask:@"PuffyCircle"];
    } else if (selectedSegment == 3) {
        [self applyMask:@"Tag"];
    } else {
        [self calert:@"Failed" alertMessage:@"Please select a mask." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
    }
}

- (void)moveFiles {
    BOOL isDir;
    NSString *oPath = @"/private/var/mobile/Torngat_TMP_Mask_DIR/";
    [[NSFileManager defaultManager] fileExistsAtPath:oPath isDirectory:&isDir];
    if(isDir) {
        NSArray *contentOfDirectory = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:oPath error:NULL];
        int contentcount = (int)[contentOfDirectory count];
        for(int i = 0; i < contentcount; i++) {
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
}

- (IBAction)continueCustom:(id)sender {
    [_urlalert setAlpha:1.0f];
    [_X setAlpha:1.0f];
    [self.view endEditing:YES];
    [_cancel setEnabled:NO];
    [_custom setEnabled:NO];
    [_change setEnabled:NO];
    [_o setEnabled:NO];
    [UIView animateWithDuration:0.5f animations:^{
        [_urlalert setAlpha:0.0f]; [_X setAlpha:0.0f];
    } completion:^(BOOL finished){[self.view endEditing:YES];_custommaskurl.text = @"";[self.view endEditing:YES];}];
    NSURL *url = [NSURL URLWithString:_custommaskurl.text];
    NSUInteger length = [_custommaskurl.text length];
    if (length == 0) {
        [self calert:@"Failed" alertMessage:@"No URL was supplied." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
        [_cancel setEnabled:YES];
        [_custom setEnabled:YES];
        [_change setEnabled:YES];
        [_o setEnabled:YES];
        return;
    } else {
        [self waitK];
    }
    NSLog(@"URL: ==>%@<==", url);
    //if (length != 0) {
        if ([[[self getFE:url] lowercaseString] isEqual: @"zip"] || [[[self getFE:url] lowercaseString] isEqual: @"tgm"] || [[[self getFE:url] lowercaseString] isEqual: @"mask"]) {
            NSData *urlData = [NSData dataWithContentsOfURL:url];
            if (urlData) {
                [urlData writeToFile:@"/private/var/mobile/Torngat_TMP_Mask_Files.zip" atomically:YES];
                [[NSFileManager defaultManager] createDirectoryAtPath:@"/private/var/mobile/Torngat_TMP_Mask_DIR/" withIntermediateDirectories:NO attributes:nil error:nil];
                if (![SSZipArchive unzipFileAtPath:@"/private/var/mobile/Torngat_TMP_Mask_Files.zip" toDestination:@"/private/var/mobile/Torngat_TMP_Mask_DIR/"]) {
                    [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Torngat_TMP_Mask_Files.zip" error:nil];
                    [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Torngat_TMP_Mask_DIR/" error:nil];
                    [self doneWaiting];
                    [self calert:@"Failed" alertMessage:@"The mask is corrupted." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
                    return;
                }
                [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Torngat_TMP_Mask_Files.zip" error:nil];
                [self moveFiles];
                [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Torngat_TMP_Mask_DIR/" error:nil];
                [[NSFileManager defaultManager] removeItemAtPath:@"/var/containers/Shared/SystemGroup/systemgroup.com.apple.lsd.iconscache/Library/Caches/com.apple.IconsCache/" error:nil];
                [[NSFileManager defaultManager] createDirectoryAtPath:@"/var/containers/Shared/SystemGroup/systemgroup.com.apple.lsd.iconscache/Library/Caches/com.apple.IconsCache/" withIntermediateDirectories:false attributes:nil error:nil];
                if (dontRespring == FALSE){[_respringBtn setHidden:NO];}
                [self doneWaiting];
                [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
                [_cancel setEnabled:YES];
                [_custom setEnabled:YES];
                [_change setEnabled:YES];
                [_o setEnabled:YES];
            } else {
                [self doneWaiting];
                [self calert:@"Failed" alertMessage:@"No data was received." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
                [_cancel setEnabled:YES];
                [_custom setEnabled:YES];
                [_change setEnabled:YES];
                [_o setEnabled:YES];
            }
        } else {
            [self calert:@"Failed" alertMessage:@"Unsupported file format." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
            [_cancel setEnabled:YES];
            [_custom setEnabled:YES];
            [_change setEnabled:YES];
            [_o setEnabled:YES];
        }/*} else {
            [self calert:@"Failed" alertMessage:@"No URL was supplied." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
            [_cancel setEnabled:YES];
            [_custom setEnabled:YES];
            [_change setEnabled:YES];
            [_o setEnabled:YES];
        }*/
    [self.view endEditing:YES];
}

- (IBAction)custom:(id)sender {
    [_urlalert setAlpha:0.0];
    [_X setAlpha:0.0];
    [_urlalert setHidden:NO];
    [_X setHidden:NO];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [UIView animateWithDuration:0.5f animations:^{
        [_urlalert setAlpha:1.0f]; [_X setAlpha:1.0f];
    }];
}

- (IBAction)closeURLAlert:(id)sender {
    [self.view endEditing:YES];
    [_urlalert setAlpha:1.0f];
    [UIView animateWithDuration:0.7f animations:^{
        [_urlalert setAlpha:0.0f];
    } completion:^(BOOL finished){[self.view endEditing:YES];_custommaskurl.text = @"";[self.view endEditing:YES];}];
}

@end

@interface bootlogo ()
@property (strong, nonatomic) IBOutlet UIView *alert;
@property (strong, nonatomic) IBOutlet UILabel *alertTitle;
@property (strong, nonatomic) IBOutlet UITextView *alertText;
@property (strong, nonatomic) IBOutlet UIButton *dismissAlertBtn;
@property (strong, nonatomic) IBOutlet UIView *wait;

@end

@implementation bootlogo

- (void)waitK {
    freeze();
    if ([stringWithContentsOfLocalFile(@"showLoader") isEqual: @"yes"]) {
        [_wait setHidden:NO];
        [_wait setAlpha:0.0f];
        [UIView animateWithDuration:0.5f animations:^{
            [_wait setAlpha:1.0f]; [_X setAlpha:1.0f];
        }];
    }
}

- (void)doneWaiting {
    if ([stringWithContentsOfLocalFile(@"showLoader") isEqual: @"yes"]) {
        [_wait setAlpha:1.0f];
        [UIView animateWithDuration:0.5f animations:^{
            [_wait setAlpha:0.0f]; [_X setAlpha:0.0f];
        } completion:^(BOOL finished) {
            [_wait setHidden:YES];
            unfreeze();
        }];
    }
}

- (void)calert:(NSString*)alertTitle alertMessage:(NSString*)alertMessage dismissButton:(NSString*)dismissButton buttonVis:(int)buttonVis dismissBtnAction:(SEL)dismissBtnAction {
    [_dismissAlertBtn setExclusiveTouch:YES];
    [_cancel setEnabled:NO];
    [_alert setAlpha:0.0]; [_X setAlpha:0.0];
    [_alertTitle setText:alertTitle];
    [_alertText setText:alertMessage];
    if (buttonVis == 0) {
        [_dismissAlertBtn setHidden:YES];
    } else if (buttonVis == 1) {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:@selector(calertd) forControlEvents:UIControlEventTouchUpInside];
    } else {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:dismissBtnAction forControlEvents:UIControlEventTouchUpInside];
    }
    [_alert setHidden:NO]; [_X setHidden:NO];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:1.0f]; [_X setAlpha:1.0f];
    }];
}

- (void)calertd {
    [_alert setAlpha:1.0f];
    [_X setAlpha:1.0f];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:0.0f];
        [_X setAlpha:0.0f];
    }];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{[_alert setHidden:YES];[_X setHidden:YES];});});
    [_cancel setEnabled:YES];
}

- (IBAction)xBtnPressed:(id)sender {
    [self calertd];
}

- (NSString *)getFE:(NSURL *)url{
    NSString *urlString = [url absoluteString];
    NSArray *componentsArray = [urlString componentsSeparatedByString:@"."];
    NSString *fileExtension = [componentsArray lastObject];
    return fileExtension;
}

- (void)applyBtn:(UIButton*)btnId {
    btnId.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
    btnId.layer.shadowOffset = CGSizeMake(0, 0);
    btnId.layer.shadowOpacity = 1.0f;
    btnId.layer.shadowRadius = 5;
    btnId.layer.masksToBounds = NO;
    btnId.layer.cornerRadius = 10.0f;
    btnId.exclusiveTouch = YES;
}

- (void)revertBtn {
    [_revert setEnabled:YES];
    [_revert setBackgroundColor:hex(0x007AFF, 1.0)];
}

- (void)viewWillAppear:(BOOL)animated {
    [self applyBtn:_revert];
    [self applyBtn:_change];
    [self applyBtn:_cancel];
    [self revertBtn];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    UILongPressGestureRecognizer *longPress = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(customImage:)];
    [_change addGestureRecognizer:longPress];
}

- (IBAction)customImage:(id)sender {
    if (noWiFi && sender != _change) return;
    UIImagePickerController *pickerController = [[UIImagePickerController alloc] init];
    pickerController.delegate = self;
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault];
    [self presentViewController:pickerController animated:YES completion:nil];
}

- (void)imagePickerController:(UIImagePickerController *)picker didFinishPickingImage:(UIImage *)image editingInfo:(NSDictionary *)editingInfo {
    if([stringWithContentsOfLocalFile(@"resizeBootlogos") isEqual:@"yes"]) {
        [self writeBootlogoWithSize:UIImagePNGRepresentation(image)];
        [self doneWaiting];
        [self calert:@"Success" alertMessage:@"Your bootlogo was successfully changed." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
        [self revertBtn];
    } else {
        [self writeBootlogo:UIImagePNGRepresentation(image)];
        [self doneWaiting];
        [self calert:@"Success" alertMessage:@"Your bootlogo was successfully changed." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
        [self revertBtn];
    }
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent];
    [self dismissModalViewControllerAnimated:YES];
}

- (void)imagePickerControllerDidCancel:(UIImagePickerController *)picker {
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent];
    [self dismissModalViewControllerAnimated:YES];
}

- (IBAction)cancel:(id)sender {
    if(!darkModeIsEnabled()){[[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault animated:YES];}
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (BOOL)writeBootlogo:(NSData*)urlData {
    BOOL BOOLEAN_RET = FALSE;
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        [urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo@2x~ipad.png" atomically:YES];
        [urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo-black@2x~ipad.png" atomically:YES];
        //[urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo@3x~ipad.png" atomically:YES];
        //[urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo-black@3x~ipad.png" atomically:YES];
        BOOLEAN_RET = TRUE;
    } else {
        [urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo@2x~iphone.png" atomically:YES];
        [urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo-black@2x~iphone.png" atomically:YES];
        [urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo@3x~iphone.png" atomically:YES];
        [urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo-black@3x~iphone.png" atomically:YES];
        BOOLEAN_RET = TRUE;
    }
    [self doneWaiting];
    [self calert:@"Success" alertMessage:@"Your bootlogo was successfully changed." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
    [self revertBtn];
    return BOOLEAN_RET;
}

- (BOOL)writeBootlogoWithSize:(NSData*)urlData {
    BOOL BOOLEAN_RET = FALSE;
    NSLog(@"%ld", lround([UIScreen mainScreen].scale));
    UIImage *bootlogoToResize = [UIImage imageWithData:urlData];
    CGSize cgsize;
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        if (lround([UIScreen mainScreen].scale) == 2) {
            cgsize = CGSizeMake(225.0, 278.0);
        } else if (lround([UIScreen mainScreen].scale) == 3) {
            cgsize = CGSizeMake(339.0, 417.0);
        } else {
            cgsize = CGSizeMake(113.0, 139.0);
        }
    } else {
        if (lround([UIScreen mainScreen].scale) == 2) {
            cgsize = CGSizeMake(129.0, 158.0);
        } else if (lround([UIScreen mainScreen].scale) == 3) {
            cgsize = CGSizeMake(194.0, 237.0);
        } else {
            cgsize = CGSizeMake(65.0, 79.0);
        }
    }
    UIGraphicsBeginImageContextWithOptions(cgsize, NO, 0.0);
    [bootlogoToResize drawInRect:CGRectMake(0, 0, cgsize.width, cgsize.height)];
    bootlogoToResize = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    urlData = UIImagePNGRepresentation(bootlogoToResize);
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        [urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo@2x~ipad.png" atomically:YES];
        [urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo-black@2x~ipad.png" atomically:YES];
        //[urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo@3x~ipad.png" atomically:YES];
        //[urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo-black@3x~ipad.png" atomically:YES];
        BOOLEAN_RET = TRUE;
    } else {
        [urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo@2x~iphone.png" atomically:YES];
        [urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo-black@2x~iphone.png" atomically:YES];
        [urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo@3x~iphone.png" atomically:YES];
        [urlData writeToFile:@"/System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo-black@3x~iphone.png" atomically:YES];
        BOOLEAN_RET = TRUE;
    }
    return BOOLEAN_RET;
}

- (IBAction)change:(id)sender {
    if (noWiFi) {
        [self customImage:sender];
        return;
    }
    [self waitK];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if ([stringWithContentsOfLocalFile(@"showLoader") isEqual: @"yes"]) { [NSThread sleepForTimeInterval:0.5f]; }
        dispatch_async(dispatch_get_main_queue(), ^{
                NSURL *url = [NSURL URLWithString:_urlf.text];
                if (![_urlf.text isEqual: @""]) {
                    if ([[[self getFE:url] lowercaseString] isEqual: @"jpg"] || [[[self getFE:url] lowercaseString] isEqual: @"jpeg"] || [[[self getFE:url] lowercaseString] isEqual: @"png"] || [[[self getFE:url] lowercaseString] isEqual: @"ico"]) {
                        NSData *urlData = [NSData dataWithContentsOfURL:url];
                        if (urlData) {
                            if([stringWithContentsOfLocalFile(@"resizeBootlogos") isEqual: @"yes"]) {
                                [self writeBootlogoWithSize:urlData];
                                [self doneWaiting];
                                [self calert:@"Success" alertMessage:@"Your bootlogo was successfully changed." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
                                [self revertBtn];
                            } else {
                                [self writeBootlogo:urlData];
                                [self doneWaiting];
                                [self calert:@"Success" alertMessage:@"Your bootlogo was successfully changed." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
                                [self revertBtn];
                            }
                        } else {
                            [self doneWaiting];
                            [self calert:@"Failed" alertMessage:@"No data was received." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
                        }
                    } else {
                        [self doneWaiting];
                        [self calert:@"Failed" alertMessage:@"Unsupported file format." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
                    }
                } else {
                    [self doneWaiting];
                    [self calert:@"Failed" alertMessage:@"No URL was supplied." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
                }
        });
    });
}

- (IBAction)revert:(id)sender {
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        [SSZipArchive unzipFileAtPath:[[NSBundle mainBundle] pathForResource:@"iPadProgressUI" ofType:@"zip"] toDestination:@"/private/var/mobile/Torngat_TMP_ProgressUI_DIR/"];
    } else {
        [SSZipArchive unzipFileAtPath:[[NSBundle mainBundle] pathForResource:@"iPhoneProgressUI" ofType:@"zip"] toDestination:@"/private/var/mobile/Torngat_TMP_ProgressUI_DIR/"];
    }
    BOOL isDir;
    NSString *oPath = @"/private/var/mobile/Torngat_TMP_ProgressUI_DIR/";
    [[NSFileManager defaultManager] fileExistsAtPath:oPath isDirectory:&isDir];
    if(isDir) {
        NSArray *contentOfDirectory = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:oPath error:NULL];
        int contentcount = (int)[contentOfDirectory count];
        int i;
        for(i = 0; i < contentcount; i++) {
            NSString *fileName = [[contentOfDirectory objectAtIndex:i] stringByReplacingOccurrencesOfString:@"/" withString:@""];
            NSString *origPath = [NSString stringWithFormat:@"%@%@", oPath, fileName];
            if ([[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithFormat:@"/System/Library/PrivateFrameworks/ProgressUI.framework/%@", fileName] isDirectory:nil]) {
                [[NSFileManager defaultManager] removeItemAtPath:[NSString stringWithFormat:@"/System/Library/PrivateFrameworks/ProgressUI.framework/%@", fileName] error:nil];
                [[NSFileManager defaultManager] copyItemAtPath:origPath toPath:[NSString stringWithFormat:@"/System/Library/PrivateFrameworks/ProgressUI.framework/%@", fileName] error:nil];
            }
        }
    }
    [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/mobile/Torngat_TMP_ProgressUI_DIR/" error:nil];
    [self calert:@"Success" alertMessage:@"Your bootlogo was successfully changed." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
}

- (IBAction)keybtn:(id)sender {
    [self.view endEditing:YES];
}

@end

@interface respringv ()
@property (strong, nonatomic) IBOutlet UIActivityIndicatorView *loader;

@end

@implementation respringv

- (void)viewWillAppear:(BOOL)animated {
    [_loader startAnimating];
}

- (void)actuallyDoIt {
    kill(noU(keyValueForName(@"SpringBoard", PID_KEY)), SIGKILL);
    exit(0);
}

- (void)viewDidLayoutSubviews {
    [self performSelector:@selector(actuallyDoIt) withObject:nil afterDelay:0.8];
}

@end

@interface credits ()
@property (strong, nonatomic) IBOutlet UILabel *exploit;
@property (strong, nonatomic) IBOutlet UILabel *exploitDev;
@property (strong, nonatomic) IBOutlet UILabel *exploitFork;
@property (strong, nonatomic) IBOutlet UILabel *exploitForkDev;
@property (strong, nonatomic) IBOutlet UIImageView *exploitDevImg;
@property (strong, nonatomic) IBOutlet UIImageView *exploitForkDevImg;
@property (strong, nonatomic) IBOutlet UIImageView *me;
@property (strong, nonatomic) IBOutlet UIImageView *skitty;
@property (strong, nonatomic) IBOutlet UIImageView *b;
@property (strong, nonatomic) IBOutlet UIImageView *enterpriseCodeSignerIcon;
@property (strong, nonatomic) IBOutlet UIView *lol;
@property (strong, nonatomic) IBOutlet UIView *official;
@property (strong, nonatomic) IBOutlet UILabel *codesignerName;
@property (strong, nonatomic) IBOutlet UIView *seven;
@property (strong, nonatomic) IBOutlet UILabel *officialURL;

@end

@implementation credits

- (void)modid:(UIView*)identifier {
    //if (darkModeIsEnabled()) {
        
    //} else {
        identifier.backgroundColor = hex(0xEBEBF1, 1.0);
    //}
    identifier.layer.cornerRadius = 10.0f;
    identifier.layer.borderColor = hex(0xEBEBF1, 1.0).CGColor;
    identifier.layer.borderWidth = 0.5f;
}

- (void)visualStyle {
    [self.navigationController.navigationBar setValue:@(YES) forKeyPath:@"hidesShadow"];
    if (darkModeIsEnabled()) {
        [_scroll setIndicatorStyle:UIScrollViewIndicatorStyleWhite];
        [self.navigationController.navigationBar setBarStyle:UIBarStyleBlack];
        [self.navigationController.navigationBar setBarTintColor:hex(0x1B2737, 1.0)];
        [self.view setBackgroundColor:hex(0x151E29, 1.0)];
        [_official setBackgroundColor:hex(0x151E29, 1.0)];
        [_officialURL setTextColor:[UIColor whiteColor]];
    } else {
        [_scroll setIndicatorStyle:UIScrollViewIndicatorStyleBlack];
        [self.navigationController.navigationBar setBarStyle:UIBarStyleDefault];
        [self.navigationController.navigationBar setBarTintColor:hex(0xF2F2F2, 1.0)];
        [self.view setBackgroundColor:hex(0xFAFAFA, 1.0)];
        [_official setBackgroundColor:hex(0xFAFAFA, 1.0)];
        [_officialURL setTextColor:[UIColor blackColor]];
    }
}

- (void)viewWillAppear:(BOOL)animated {
    [self modid:_one];
    [self modid:_two];
    [self modid:_three];
    [self modid:_four];
    [self modid:_five];
    [self modid:_six];
    if (![codesigner isEqual: @"Your username / alias"]) {
        [self modid:_seven];
    } else {
        _seven.layer.cornerRadius = 10.0f;
    }
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(visualStyle)     name:@"updatedVisualStyle" object:nil];
    [self visualStyle];
}

NSData *imageData;

BOOL WiFi;

NSString *exploitDevIconURL = @"";
NSString *exploitForkDevIconURL = @"";
NSString *exploitDev = @"";
NSString *exploitForkDev = @"";
NSString *exploit = @"";
NSString *exploitFork = @"";
NSTimer *timer;

- (void)checkWiFiC {
    if (WiFi == YES) {
        return;
    } else {
        if (noWiFi) {
            return;
        } else {
            if (noWiFi) {
                return;
            } else {
                NSLog(@"got wifi, updating...");
                dispatch_async(dispatch_get_global_queue(0,0), ^{
                    imageData = [[NSData alloc] initWithContentsOfURL: [NSURL URLWithString:exploitDevIconURL]];
                    dispatch_async(dispatch_get_main_queue(), ^{
                        _exploitDevImg.image = [UIImage imageWithData:imageData];
                        dispatch_async(dispatch_get_global_queue(0,0), ^{
                            imageData = [[NSData alloc] initWithContentsOfURL: [NSURL URLWithString:exploitForkDevIconURL]];
                            dispatch_async(dispatch_get_main_queue(), ^{
                                _exploitForkDevImg.image = [UIImage imageWithData:imageData];
                                dispatch_async(dispatch_get_global_queue(0,0), ^{
                                    imageData = [[NSData alloc] initWithContentsOfURL: [NSURL URLWithString:@"https://twitter.com/1GamerDev/profile_image?size=original"]];
                                    dispatch_async(dispatch_get_main_queue(), ^{
                                        _me.image = [UIImage imageWithData:imageData];
                                        dispatch_async(dispatch_get_global_queue(0,0), ^{
                                            imageData = [[NSData alloc] initWithContentsOfURL: [NSURL URLWithString: @"https://twitter.com/Skittyblock/profile_image?size=original"]];
                                            dispatch_async(dispatch_get_main_queue(), ^{
                                                _skitty.image = [UIImage imageWithData:imageData];
                                                dispatch_async(dispatch_get_global_queue(0,0), ^{
                                                    imageData = [[NSData alloc] initWithContentsOfURL: [NSURL URLWithString: @"https://twitter.com/B1n4r1b01/profile_image?size=original"]];
                                                    dispatch_async(dispatch_get_main_queue(), ^{
                                                        _b.image = [UIImage imageWithData:imageData];
                                                        dispatch_async(dispatch_get_main_queue(), ^{
                                                            _b.image = [UIImage imageWithData:imageData];
                                                            dispatch_async(dispatch_get_global_queue(0,0), ^{
                                                                imageData = [[NSData alloc] initWithContentsOfURL:[NSURL URLWithString:@"https://maxcdn.icons8.com/Share/icon/color/Logos/icons8_logo1600.png"]];
                                                                dispatch_async(dispatch_get_main_queue(), ^{
                                                                    _icons8.image = [UIImage imageWithData:imageData];
                                                                    dispatch_async(dispatch_get_global_queue(0,0), ^{
                                                                        if (![codesigner isEqual: @"Your username / alias"]) {
                                                                            imageData = [[NSData alloc] initWithContentsOfURL: [NSURL URLWithString: codesignerIcon]];
                                                                            dispatch_async(dispatch_get_main_queue(), ^{
                                                                                _enterpriseCodeSignerIcon.image = [UIImage imageWithData:imageData];
                                                                                imageData = NULL;
                                                                            });
                                                                        } else {
                                                                            dispatch_async(dispatch_get_main_queue(), ^{
                                                                                imageData = NULL;
                                                                            });
                                                                        }
                                                                        [timer invalidate];
                                                                        timer = nil;
                                                                    });
                                                                });
                                                            });
                                                        });
                                                    });
                                                });
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            }}
    }
}

- (void)roundCredits {
    _one.layer.masksToBounds = YES;
    _two.layer.masksToBounds = YES;
    _three.layer.masksToBounds = YES;
    _four.layer.masksToBounds = YES;
    _five.layer.masksToBounds = YES;
    _six.layer.masksToBounds = YES;
    _seven.layer.masksToBounds = YES;
    _one.clipsToBounds = YES;
    _two.clipsToBounds = YES;
    _three.clipsToBounds = YES;
    _four.clipsToBounds = YES;
    _five.clipsToBounds = YES;
    _six.clipsToBounds = YES;
    _seven.clipsToBounds = YES;
}

- (void)viewDidLoad {
    if ([usedExploit isEqual:@"empty_list"]) {
        exploitForkDevIconURL = @"https://twitter.com/coolstarorg/profile_image?size=original";
        exploitDevIconURL = @"https://twitter.com/i41nbeer/profile_image?size=original";
        exploitDev = @"i41nbeer";
        exploitForkDev = @"CoolStar";
        exploit = @"empty_list";
        exploitFork = @"Remount";
    }
    [_exploitDev setText:exploitDev];
    [_exploitForkDev setText:exploitForkDev];
    [_exploit setText:exploit];
    [_exploitFork setText:exploitFork];
    if (![codesigner isEqual: @"Your username / alias"]) {
        [_codesignerName setText:codesigner];
        [_official setHidden:YES];
    }
    if (noWiFi) {
        _exploitDevImg.image = [UIImage imageNamed:@"q.png"];
        _exploitForkDevImg.image = [UIImage imageNamed:@"q.png"];
        _me.image = [UIImage imageNamed:@"q.png"];
        _skitty.image = [UIImage imageNamed:@"q.png"];
        _b.image = [UIImage imageNamed:@"q.png"];
        _enterpriseCodeSignerIcon.image = [UIImage imageNamed:@"q.png"];
        _icons8.image = [UIImage imageNamed:@"q.png"];
        WiFi = NO;
        timer = [NSTimer scheduledTimerWithTimeInterval:0.5 target:self selector:@selector(checkWiFiC) userInfo:nil repeats:YES];
        [timer fire];
    } else {
        dispatch_async(dispatch_get_global_queue(0,0), ^{
            imageData = [[NSData alloc] initWithContentsOfURL: [NSURL URLWithString:exploitDevIconURL]];
            dispatch_async(dispatch_get_main_queue(), ^{
                _exploitDevImg.image = [UIImage imageWithData:imageData];
                dispatch_async(dispatch_get_global_queue(0,0), ^{
                    imageData = [[NSData alloc] initWithContentsOfURL: [NSURL URLWithString:exploitForkDevIconURL]];
                    dispatch_async(dispatch_get_main_queue(), ^{
                        _exploitForkDevImg.image = [UIImage imageWithData:imageData];
                        dispatch_async(dispatch_get_global_queue(0,0), ^{
                            imageData = [[NSData alloc] initWithContentsOfURL: [NSURL URLWithString: @"https://twitter.com/1GamerDev/profile_image?size=original"]];
                            dispatch_async(dispatch_get_main_queue(), ^{
                                _me.image = [UIImage imageWithData:imageData];
                                dispatch_async(dispatch_get_global_queue(0,0), ^{
                                    imageData = [[NSData alloc] initWithContentsOfURL: [NSURL URLWithString: @"https://twitter.com/Skittyblock/profile_image?size=original"]];
                                    dispatch_async(dispatch_get_main_queue(), ^{
                                        _skitty.image = [UIImage imageWithData:imageData];
                                        dispatch_async(dispatch_get_global_queue(0,0), ^{
                                            imageData = [[NSData alloc] initWithContentsOfURL: [NSURL URLWithString: @"https://twitter.com/B1n4r1b01/profile_image?size=original"]];
                                            dispatch_async(dispatch_get_main_queue(), ^{
                                                _b.image = [UIImage imageWithData:imageData];
                                                dispatch_async(dispatch_get_main_queue(), ^{
                                                    _b.image = [UIImage imageWithData:imageData];
                                                    dispatch_async(dispatch_get_global_queue(0,0), ^{
                                                        imageData = [[NSData alloc] initWithContentsOfURL:[NSURL URLWithString:@"https://maxcdn.icons8.com/Share/icon/color/Logos/icons8_logo1600.png"]];
                                                        dispatch_async(dispatch_get_main_queue(), ^{
                                                            _icons8.image = [UIImage imageWithData:imageData];
                                                            dispatch_async(dispatch_get_global_queue(0,0), ^{
                                                                if (![codesigner isEqual: @"Your username / alias"]) {
                                                                    imageData = [[NSData alloc] initWithContentsOfURL: [NSURL URLWithString: codesignerIcon]];
                                                                    dispatch_async(dispatch_get_main_queue(), ^{
                                                                        _enterpriseCodeSignerIcon.image = [UIImage imageWithData:imageData];
                                                                        imageData = NULL;
                                                                    });
                                                                } else {
                                                                    dispatch_async(dispatch_get_main_queue(), ^{
                                                                        imageData = NULL;
                                                                    });
                                                                }
                                                            });
                                                        });
                                                    });
                                                });
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    }
    [NSTimer scheduledTimerWithTimeInterval:0.5 target:self selector:@selector(roundCredits) userInfo:nil repeats:YES];
}

- (void)viewDidLayoutSubviews {
    RESIZE_SCROLLVIEW_0(_scroll, self.view.frame.size.width, 0);
}

@end

@interface fonts ()
@property (strong, nonatomic) IBOutlet UIView *alert;
@property (strong, nonatomic) IBOutlet UILabel *alertTitle;
@property (strong, nonatomic) IBOutlet UITextView *alertText;
@property (strong, nonatomic) IBOutlet UIButton *dismissAlertBtn;
@property (strong, nonatomic) IBOutlet UITextField *urlf;
@property (strong, nonatomic) IBOutlet UIButton *change;
@property (strong, nonatomic) IBOutlet UISegmentedControl *o;
@property (strong, nonatomic) IBOutlet UIButton *cancel;
@property (strong, nonatomic) IBOutlet UIView *wait;
@property (strong, nonatomic) IBOutlet UIButton *respringBtn;
@property (strong, nonatomic) IBOutlet UIButton *revertBtn;

@end

@implementation fonts

- (void)waitK {
    freeze();
    if ([stringWithContentsOfLocalFile(@"showLoader") isEqual: @"yes"]) {
        [_wait setHidden:NO];
        [_wait setAlpha:0.0f];
        [UIView animateWithDuration:0.5f animations:^{
            [_wait setAlpha:1.0f]; [_X setAlpha:1.0f];
        }];
    }
}

- (void)doneWaiting {
    if ([stringWithContentsOfLocalFile(@"showLoader") isEqual: @"yes"]) {
        [_wait setAlpha:1.0f];
        [UIView animateWithDuration:0.5f animations:^{
            [_wait setAlpha:0.0f]; [_X setAlpha:0.0f];
        } completion:^(BOOL finished) {
            [_wait setHidden:YES];
            unfreeze();
        }];
    }
}

- (IBAction)respringDevice:(id)sender {
    respringDevice();
}

- (void)calert:(NSString*)alertTitle alertMessage:(NSString*)alertMessage dismissButton:(NSString*)dismissButton buttonVis:(int)buttonVis dismissBtnAction:(SEL)dismissBtnAction {
    [_dismissAlertBtn setExclusiveTouch:YES];
    if ([alertTitle isEqual: @"Success"]) {
        if (dontRespring == FALSE){[_respringBtn setHidden:NO];}
    } else {
        [_respringBtn setHidden:YES];
    }
    [_cancel setEnabled:NO];
    [_alert setAlpha:0.0]; [_X setAlpha:0.0];
    [_alertTitle setText:alertTitle];
    [_alertText setText:alertMessage];
    if (buttonVis == 0) {
        [_dismissAlertBtn setHidden:YES];
    } else if (buttonVis == 1) {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:@selector(calertd) forControlEvents:UIControlEventTouchUpInside];
    } else {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:dismissBtnAction forControlEvents:UIControlEventTouchUpInside];
    }
    [_alert setHidden:NO]; [_X setHidden:NO];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:1.0f]; [_X setAlpha:1.0f];
    }];
}

- (void)calertd {
    [_alert setAlpha:1.0f];
    [_X setAlpha:1.0f];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:0.0f];
        [_X setAlpha:0.0f];
    } completion:^(BOOL finished) {
        [_respringBtn setHidden:YES];
    }];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{[_alert setHidden:YES];[_X setHidden:YES];});});
    [_cancel setEnabled:YES];
}

- (IBAction)xBtnPressed:(id)sender {
    [self calertd];
}

- (NSString *)getFE:(NSURL *)url{
    NSString *urlString = [url absoluteString];
    NSArray *componentsArray = [urlString componentsSeparatedByString:@"."];
    NSString *fileExtension = [componentsArray lastObject];
    return fileExtension;
}

- (void)applyBtn:(UIButton*)btnId {
    btnId.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
    btnId.layer.shadowOffset = CGSizeMake(0, 0);
    btnId.layer.shadowOpacity = 1.0f;
    btnId.layer.shadowRadius = 5;
    btnId.layer.masksToBounds = NO;
    btnId.layer.cornerRadius = 10.0f;
    btnId.exclusiveTouch = YES;
}

- (void)canRevert {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" isDirectory:nil]) {
        [UIView animateWithDuration:0.5f animations:^{
            [_revertBtn bgBlueColour];
        }];
        [_revertBtn setEnabled:YES];
    } else {
        [UIView animateWithDuration:0.5f animations:^{
            [_revertBtn bgDisabledColour];
        }];
        [_revertBtn setEnabled:NO];
    }
}

- (void)checkWiFiC {
    [self canRevert];
    Reachability *reachability = [Reachability reachabilityForInternetConnection];
    [reachability startNotifier];
    if (noWiFi || [reachability currentReachabilityStatus] == ReachableViaWWAN) {
        [UIView animateWithDuration:0.5f animations:^{
            [_change bgDisabledColour];
        }];
        [_change setEnabled:NO];
    } else {
        [UIView animateWithDuration:0.5f animations:^{
            [_change bgBlueColour];
        }];
        [_change setEnabled:YES];
    }
}

NSInteger emoji = -1;

- (void)viewWillAppear:(BOOL)animated {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" isDirectory:nil]) {
        [_revertBtn bgBlueColour];
        [_revertBtn setEnabled:YES];
    } else {
        [_revertBtn bgDisabledColour];
        [_revertBtn setEnabled:NO];
    }
    emoji = -1;
    [self applyBtn:_change];
    [self applyBtn:_cancel];
    [self applyBtn:_revertBtn];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    Reachability *reachability = [Reachability reachabilityForInternetConnection];
    [reachability startNotifier];
    if (noWiFi || [reachability currentReachabilityStatus] == ReachableViaWWAN) {
        [_change bgDisabledColour];
        [_change setEnabled:NO];
    }
    [NSTimer scheduledTimerWithTimeInterval:0.5 target:self selector:@selector(checkWiFiC) userInfo:nil repeats:YES];
}

- (IBAction)revert:(id)sender {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" isDirectory:nil]) {
        [[NSFileManager defaultManager] removeItemAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" error:nil];
        [[NSFileManager defaultManager] moveItemAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" toPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" error:nil];
        [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
    } else {
        [self calert:@"Failed" alertMessage:@"Torngat was unable to locate the old font file." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
    }
}

- (IBAction)cancel:(id)sender {
    if(!darkModeIsEnabled()){[[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault animated:YES];}
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (IBAction)change:(id)sender {
    [self waitK];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
        int failure = 0;
        if ([_o selectedSegmentIndex] == 0) {
            emoji = 0;
        } else if ([_o selectedSegmentIndex] == 1) {
            emoji = 1;
        } else if ([_o selectedSegmentIndex] == 2) {
            emoji = 2;
        } else if ([_o selectedSegmentIndex] == 3) {
            emoji = 3;
        }
    method1:;
        NSLog(@"Method 1");
        if (emoji == 0) {
            NSURL *url = [NSURL URLWithString:@"https://1gamerdev.github.io/Torngat-Files/ios11.3.ttc"];
            NSData *receivedData = [NSData dataWithContentsOfURL:url];
            if (receivedData) {
                [self doneWaiting];
                ![[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" isDirectory:nil] && [[NSFileManager defaultManager] moveItemAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" toPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" error:nil];
                [receivedData writeToFile:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" atomically:YES];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
                    [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
                });});
            } else {
                failure = failure + 1;
                if (failure == 2) {
                    goto out0;
                }
                goto method2;
            }
        } else if (emoji == 1) {
            NSURL *url = [NSURL URLWithString:@"https://dl.dropboxusercontent.com/s/v79f1mgqwxw4puy/androidoreo.ttc"];
            NSData *receivedData = [NSData dataWithContentsOfURL:url];
            if (receivedData) {
                [self doneWaiting];
                ![[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" isDirectory:nil] && [[NSFileManager defaultManager] moveItemAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" toPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" error:nil];
                [receivedData writeToFile:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" atomically:YES];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
                    [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
                });});
            } else {
                failure = failure + 1;
                if (failure == 2) {
                    goto out0;
                }
                goto method2;
            }
        } else if (emoji == 2) {
            NSURL *url = [NSURL URLWithString:@"https://dl.dropboxusercontent.com/s/dss5l6912nbqssj/emojione.ttc"];
            NSData *receivedData = [NSData dataWithContentsOfURL:url];
            if (receivedData) {
                [self doneWaiting];
                ![[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" isDirectory:nil] && [[NSFileManager defaultManager] moveItemAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" toPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" error:nil];
                [receivedData writeToFile:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" atomically:YES];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
                    [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
                });});
            } else {
                failure = failure + 1;
                if (failure == 2) {
                    goto out0;
                }
                goto method2;
            }
        } else if (emoji == 3) {
            NSURL *url = [NSURL URLWithString:@"https://dl.dropboxusercontent.com/s/ttsgje898eybmzi/twitter2.4.ttc"];
            NSData *receivedData = [NSData dataWithContentsOfURL:url];
            if (receivedData) {
                [self doneWaiting];
                ![[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" isDirectory:nil] && [[NSFileManager defaultManager] moveItemAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" toPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" error:nil];
                [receivedData writeToFile:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" atomically:YES];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
                    [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
                });});
            } else {
                failure = failure + 1;
                if (failure == 2) {
                    goto out0;
                }
                goto method2;
            }
        } else {
            [self doneWaiting];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
                [self calert:@"Failed" alertMessage:@"No emoji was selected." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
            });});
        }
        return;
    method2:;
        NSLog(@"Method 2");
        if (emoji == 0) {
            NSURL *url = [NSURL URLWithString:@"https://1gamerdev.github.io/Torngat-Files/ios11.3.ttc"];
            NSData *receivedData = [NSData dataWithContentsOfURL:url];
            if (receivedData) {
                [self doneWaiting];
                ![[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" isDirectory:nil] && [[NSFileManager defaultManager] moveItemAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" toPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" error:nil];
                [receivedData writeToFile:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" atomically:YES];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
                    [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
                });});
            } else {
                failure = failure + 1;
                if (failure == 2) {
                    goto out0;
                }
                goto method1;
            }
        }
        else if (emoji == 1) {
            NSURL *url = [NSURL URLWithString:@"https://1gamerdev.github.io/Torngat-Files/androidoreo.ttc"];
            NSData *receivedData = [NSData dataWithContentsOfURL:url];
            if (receivedData) {
                [self doneWaiting];
                ![[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" isDirectory:nil] && [[NSFileManager defaultManager] moveItemAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" toPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" error:nil];
                [receivedData writeToFile:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" atomically:YES];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
                    [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
                });});
            } else {
                failure = failure + 1;
                if (failure == 2) {
                    goto out0;
                }
                goto method1;
            }
        }
        else if (emoji == 2) {
            NSURL *url = [NSURL URLWithString:@"https://1gamerdev.github.io/Torngat-Files/emojione.ttc"];
            NSData *receivedData = [NSData dataWithContentsOfURL:url];
            if (receivedData) {
                [self doneWaiting];
                ![[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" isDirectory:nil] && [[NSFileManager defaultManager] moveItemAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" toPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" error:nil];
                [receivedData writeToFile:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" atomically:YES];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
                    [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
                });});
            } else {
                failure = failure + 1;
                if (failure == 2) {
                    goto out0;
                }
                goto method1;
            }
        } else if (emoji == 3) {
            NSURL *url = [NSURL URLWithString:@"https://1gamerdev.github.io/Torngat-Files/twitter2.4.ttc"];
            NSData *receivedData = [NSData dataWithContentsOfURL:url];
            if (receivedData) {
                [self doneWaiting];
                ![[NSFileManager defaultManager] fileExistsAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" isDirectory:nil] && [[NSFileManager defaultManager] moveItemAtPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" toPath:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc.old" error:nil];
                [receivedData writeToFile:@"/System/Library/Fonts/Core/AppleColorEmoji@2x.ttc" atomically:YES];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
                    [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
                });});
            } else {
                failure = failure + 1;
                if (failure == 2) {
                    goto out0;
                }
                goto method1;
            }
        } else {
            [self doneWaiting];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
                [self calert:@"Failed" alertMessage:@"No emoji was selected." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
            });});
        }
        return;
    out0:;
        [self doneWaiting];
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{
            [self calert:@"Failed" alertMessage:@"Torngat was unable to download a required file." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
        });});
        return;
    });});
}

- (IBAction)keybtn:(id)sender {
    [self.view endEditing:YES];
}

@end

@interface bigFullscreenBoi ()
@property (strong, nonatomic) IBOutlet UIButton *respringBtn;

@end

@implementation bigFullscreenBoi

- (IBAction)respringDevice:(id)sender {
    respringDevice();
}

- (void)calert {
    [_alert setAlpha:0.0]; [_X setAlpha:0.0];
    [_alert setHidden:NO]; [_X setHidden:NO];
    if(!darkModeIsEnabled()){[[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];}
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:1.0f]; [_X setAlpha:1.0f];
    }];
}

- (void)viewWillAppear:(BOOL)animated {
    [_titleT setText:bigFullscreenBoiTitle];
    if ([bigFullscreenBoiTitle isEqual: @"Success"]) {
        if (dontRespring == FALSE){[_respringBtn setHidden:NO];}
    } else {
        [_respringBtn setHidden:YES];
    }
    if ([bigFullscreenBoiTitle isEqual: @"Success NO_RESPRING"]) {
        [_respringBtn setHidden:YES];
        [_titleT setText:@"Success"];
    }
    [_text setText:bigFullscreenBoiText];
    [self calert];
}

- (IBAction)cyaBruv:(id)sender {
    if(!darkModeIsEnabled()){[[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault animated:YES];}
    [_alert setAlpha:1.0f];
    [_X setAlpha:1.0f];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:0.0f];
        [_X setAlpha:0.0f];
    } completion:^(BOOL finished) {
        [_respringBtn setHidden:YES];
    }];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{[_alert setHidden:YES];[_X setHidden:YES];[self dismissViewControllerAnimated:NO completion:nil];});});
}

@end

@interface badges ()
@property (strong, nonatomic) IBOutlet UIView *alert;
@property (strong, nonatomic) IBOutlet UILabel *alertTitle;
@property (strong, nonatomic) IBOutlet UITextView *alertText;
@property (strong, nonatomic) IBOutlet UIButton *dismissAlertBtn;
@property (strong, nonatomic) IBOutlet UIView *colourDisplay;
@property (strong, nonatomic) IBOutlet UIButton *defaultBtn;
@property (strong, nonatomic) IBOutlet UIButton *transparent;
@property (strong, nonatomic) IBOutlet UIButton *respringBtn;
@property (strong, nonatomic) IBOutlet UISlider *opacitySlider;
@property (strong, nonatomic) IBOutlet UILabel *opacityValue;

@end

@implementation badges

float sliderVal;
NSTimer *cu;

- (void)calert:(NSString*)alertTitle alertMessage:(NSString*)alertMessage dismissButton:(NSString*)dismissButton buttonVis:(int)buttonVis dismissBtnAction:(SEL)dismissBtnAction {
    [_dismissAlertBtn setExclusiveTouch:YES];
    [_cancel setEnabled:NO];
    [_alert setAlpha:0.0]; [_X setAlpha:0.0];
    [_alertTitle setText:alertTitle];
    [_alertText setText:alertMessage];
    if (buttonVis == 0) {
        [_dismissAlertBtn setHidden:YES];
    } else if (buttonVis == 1) {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:@selector(calertd) forControlEvents:UIControlEventTouchUpInside];
    } else {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:dismissBtnAction forControlEvents:UIControlEventTouchUpInside];
    }
    [_alert setHidden:NO]; [_X setHidden:NO];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:1.0f]; [_X setAlpha:1.0f];
    }];
}

- (void)calertd {
    [_alert setAlpha:1.0f];
    [_X setAlpha:1.0f];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:0.0f];
        [_X setAlpha:0.0f];
    } completion:^(BOOL finished) {
        [_respringBtn setHidden:YES];
    }];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{[_alert setHidden:YES];[_X setHidden:YES];});});
    [_cancel setEnabled:YES];
}

- (IBAction)xBtnPressed:(id)sender {
    [self calertd];
}

- (NSString *)getFE:(NSURL *)url{
    NSString *urlString = [url absoluteString];
    NSArray *componentsArray = [urlString componentsSeparatedByString:@"."];
    NSString *fileExtension = [componentsArray lastObject];
    return fileExtension;
}

- (IBAction)changedSliderVal:(id)sender {
    [_opacityValue setText:[NSString stringWithFormat:@"%.01f", _opacitySlider.value]];
}

- (IBAction)useDefault:(id)sender {
    unlink("/var/mobile/Library/Caches/MappedImageCache/Persistent/SBIconBadgeView.BadgeBackground.cpbitmap");
    if (dontRespring == FALSE){[_respringBtn setHidden:NO];}
    [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
}

- (IBAction)respringDevice:(id)sender {
    respringDevice();
}

- (void)applyBtn:(UIButton*)btnId {
    btnId.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
    btnId.layer.shadowOffset = CGSizeMake(0, 0);
    btnId.layer.shadowOpacity = 1.0f;
    btnId.layer.shadowRadius = 5;
    btnId.layer.masksToBounds = NO;
    btnId.layer.cornerRadius = 10.0f;
    btnId.exclusiveTouch = YES;
}

- (int)cbt:(UIImage *)image {
    badge = [UIImage imageWithImage:image scaledToSize:CGSizeMake(24, 24)];
    UIImageView *imageView = [[UIImageView alloc] initWithImage:badge];
    CALayer *layer = [CALayer layer];
    layer = [imageView layer];
    layer.masksToBounds = YES;
    layer.cornerRadius = 12.0f;
    UIGraphicsBeginImageContextWithOptions(imageView.bounds.size, NO, 0.0);
    [layer renderInContext:UIGraphicsGetCurrentContext()];
    badge = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    [badge writeToCPBitmapFile:@"/private/var/mobile/IconBadgeBackground_Torngat.cpbitmap" flags:1];
    NSLog(@"%@", [NSData dataWithContentsOfFile:@"/private/var/mobile/IconBadgeBackground_Torngat.cpbitmap"]);
    unlink("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/SBIconBadgeView.BadgeBackground.cpbitmap");
    NSLog(@"%@", [NSData dataWithContentsOfFile:@"/private/var/mobile/IconBadgeBackground_Torngat.cpbitmap"]);
    int read_fd = open("/private/var/mobile/IconBadgeBackground_Torngat.cpbitmap", O_RDONLY, 0);
    int write_fd = open("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/SBIconBadgeView.BadgeBackground.cpbitmap", O_RDWR | O_CREAT | O_APPEND, 0777);
    if(fdopen(read_fd, "r") == NULL) {
        return -1;
    }
    if(fdopen(write_fd, "wb") == NULL) {
        return -1;
    }
    FILE *read_f = fdopen(read_fd, "r");
    FILE *write_f = fdopen(write_fd, "wb");
    size_t write_size;
    size_t read_size;
    while(feof(read_f) == 0) {
        char buff[100];
        if((read_size = fread(buff, 1, 100, read_f)) != 100) {
            if(ferror(read_f) != 0) {
                return -1;
            }
        }
        if((write_size = fwrite(buff, 1, read_size, write_f)) != read_size) {
            return -1;
        }
    }
    fclose(read_f);
    fclose(write_f);
    close(read_fd);
    close(write_fd);
    if (unlink("/private/var/mobile/IconBadgeBackground_Torngat.cpbitmap") != 0) {
        return -1;
    }
    chown("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/SBIconBadgeView.BadgeBackground.cpbitmap", 501, 501);
    chmod("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/SBIconBadgeView.BadgeBackground.cpbitmap", 0666);
    return 1;
}

- (IBAction)customImage:(id)sender {
    UIImagePickerController *pickerController = [[UIImagePickerController alloc] init];
    pickerController.delegate = self;
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault];
    [self presentViewController:pickerController animated:YES completion:nil];
}

- (void)imagePickerController:(UIImagePickerController *)picker didFinishPickingImage:(UIImage *)image editingInfo:(NSDictionary *)editingInfo {
    int ret = [self cbt:image];
    if (ret == 1) {
        if (dontRespring == FALSE){[_respringBtn setHidden:NO];}
        [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
    } else if (ret == -2) {
        [self calert:@"Failed" alertMessage:@"Torngat could not detect the correct badge size." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
    } else {
        [self calert:@"Failed" alertMessage:@"An error has occurred." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
    }
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent];
    [self dismissModalViewControllerAnimated:YES];
}

- (void)imagePickerControllerDidCancel:(UIImagePickerController *)picker {
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent];
    [self dismissModalViewControllerAnimated:YES];
}

- (void)viewWillAppear:(BOOL)animated {
    [_colourDisplay setBackgroundColor:hex(0xFF0000, 1.0)];
    [self applyBtn:_change];
    [self applyBtn:_cancel];
    [self applyBtn:_defaultBtn];
    [self applyBtn:_transparent];
    UILongPressGestureRecognizer *longPress = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(customImage:)];
    [_change addGestureRecognizer:longPress];
    [_respringBtn setHidden:YES];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    cu = [NSTimer scheduledTimerWithTimeInterval:0.01 target:self selector:@selector(updateColour) userInfo:nil repeats:YES];
    [cu fire];
}

- (void)viewWillDisappear:(BOOL)animated {
    [cu invalidate];
}

- (void)updateColour {
    unsint rgb = 0;
    NSString *hexv = [_hexf.text stringByReplacingOccurrencesOfString:@"#" withString:@""];
    [[NSScanner scannerWithString:[[[NSString stringWithFormat:@"%s", [hexv UTF8String]] lowercaseString] stringByTrimmingCharactersInSet:[[NSCharacterSet characterSetWithCharactersInString:@"abcdef0123456789"] invertedSet]]] scanHexInt:&rgb];
    if ([hexv length] != 6) {
        float alphav = _opacitySlider.value;
        [_colourDisplay setBackgroundColor:hex(0xFF0000, alphav)];
        [UIView animateWithDuration:0.5f animations:^{
            [_colourDisplay setBackgroundColor:hex(0xFF0000, alphav)];
        }];
        return;
    }
    float alphav = _opacitySlider.value;
    [_colourDisplay setBackgroundColor:[[_colourDisplay backgroundColor] colorWithAlphaComponent:alphav]];
    [UIView animateWithDuration:0.5f animations:^{
        [_colourDisplay setBackgroundColor:hex(rgb, alphav)];
    }];
}

- (IBAction)cancel:(id)sender {
    if(!darkModeIsEnabled()){[[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault animated:YES];}
    [self dismissViewControllerAnimated:YES completion:nil];
}

int size() {
    int detected;
    if(UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        detected = 3;
    } else {
        detected = 2;
    }
    return detected;
}

UIImage *badge;

- (int)bc:(const char *)colour transparent:(BOOL)transparent {
    printf("size: %i\n", size());
    /*
     // size 1.  i dont think any device uses this size but i wrote this code just in case.  contact me if (a) device(s) uses size 1 & which device(s) [it/they] [is/are] and i'll uncomment this.
     if (size() == 1) { UIGraphicsBeginImageContextWithOptions(CGRectMake(0, 0, 12, 12).size, NO, 0.0);
     CGContextRef context = UIGraphicsGetCurrentContext();
     CGContextSetFillColorWithColor(context, [[UIColor blackColor] CGColor]);
     CGRect size;
     if (transparent == FALSE) {
     size =  CGRectMake(0, 0, 12, 12);
     } else {
     size = CGRectMake(0, 0, 0, 0);
     }
     CGContextFillRect(context, size);
     badge = UIGraphicsGetImageFromCurrentImageContext();
     UIGraphicsEndImageContext();
     UIGraphicsBeginImageContextWithOptions(CGSizeMake(12.0, 12.0), NO, 0.0);
     CGRect bounds=(CGRect){CGPointZero, CGSizeMake(12.0, 12.0)};
     [[UIBezierPath bezierPathWithRoundedRect:bounds cornerRadius:6.0f] addClip];
     [badge drawInRect:bounds];
     badge = UIGraphicsGetImageFromCurrentImageContext();
     UIGraphicsEndImageContext();
     else */if (size() == 2) {
         UIGraphicsBeginImageContextWithOptions(CGRectMake(0, 0, 24, 24).size, NO, 0.0);
         CGContextRef context = UIGraphicsGetCurrentContext();
         CGContextSetFillColorWithColor(context, [[UIColor blackColor] CGColor]);
         CGRect size;
         if (transparent == FALSE) {
             size =  CGRectMake(0, 0, 24, 24);
         } else {
             size = CGRectMake(0, 0, 0, 0);
         }
         CGContextFillRect(context, size);
         badge = UIGraphicsGetImageFromCurrentImageContext();
         UIGraphicsEndImageContext();
         UIGraphicsBeginImageContextWithOptions(CGSizeMake(24.0, 24.0), NO, 0.0);
         CGRect bounds=(CGRect){CGPointZero, CGSizeMake(24.0, 24.0)};
         [[UIBezierPath bezierPathWithRoundedRect:bounds cornerRadius:12.0f] addClip];
         [badge drawInRect:bounds];
         badge = UIGraphicsGetImageFromCurrentImageContext();
         UIGraphicsEndImageContext();
     } else if (size() == 3) {
         //UIGraphicsBeginImageContextWithOptions(CGRectMake(0, 0, 48, 48).size, NO, 0.0);
         UIGraphicsBeginImageContextWithOptions(CGRectMake(0, 0, 24, 24).size, NO, 0.0);
         CGContextRef context = UIGraphicsGetCurrentContext();
         CGContextSetFillColorWithColor(context, [[UIColor blackColor] CGColor]);
         CGRect size;
         if (transparent == FALSE) {
             size =  CGRectMake(0, 0, 48, 48);
         } else {
             size = CGRectMake(0, 0, 0, 0);
         }
         CGContextFillRect(context, size);
         badge = UIGraphicsGetImageFromCurrentImageContext();
         UIGraphicsEndImageContext();
         //UIGraphicsBeginImageContextWithOptions(CGSizeMake(48.0, 48.0), NO, 0.0);
         //CGRect bounds=(CGRect){CGPointZero, CGSizeMake(48.0, 48.0)};
         //[[UIBezierPath bezierPathWithRoundedRect:bounds cornerRadius:24.0f] addClip];
         UIGraphicsBeginImageContextWithOptions(CGSizeMake(24.0, 24.0), NO, 0.0);
         CGRect bounds=(CGRect){CGPointZero, CGSizeMake(24.0, 24.0)};
         [[UIBezierPath bezierPathWithRoundedRect:bounds cornerRadius:12.0f] addClip];
         [badge drawInRect:bounds];
         badge = UIGraphicsGetImageFromCurrentImageContext();
         UIGraphicsEndImageContext();
     } else {
         return -2;
     }
    unsint rgb = 0;
    [[NSScanner scannerWithString:[[[NSString stringWithFormat:@"%s", colour] lowercaseString] stringByTrimmingCharactersInSet:[[NSCharacterSet characterSetWithCharactersInString:@"abcdef0123456789"] invertedSet]]] scanHexInt:&rgb];
    CGRect rect = CGRectMake(0, 0, badge.size.width, badge.size.height);
    UIGraphicsBeginImageContextWithOptions(rect.size, NO, 0.0);
    CGContextRef context = UIGraphicsGetCurrentContext();
    CGContextClipToMask(context, rect, badge.CGImage);
    CGContextSetFillColorWithColor(context, [hex(rgb, sliderVal) CGColor]);
    CGContextFillRect(context, rect);
    badge = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    [badge writeToCPBitmapFile:@"/private/var/mobile/IconBadgeBackground_Torngat.cpbitmap" flags:1];
    unlink("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/SBIconBadgeView.BadgeBackground.cpbitmap");
    int read_fd = open("/private/var/mobile/IconBadgeBackground_Torngat.cpbitmap", O_RDONLY, 0);
    int write_fd = open("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/SBIconBadgeView.BadgeBackground.cpbitmap", O_RDWR | O_CREAT | O_APPEND, 0777);
    if(fdopen(read_fd, "r") == NULL) {
        return -1;
    }
    if(fdopen(write_fd, "wb") == NULL) {
        return -1;
    }
    FILE *read_f = fdopen(read_fd, "r");
    FILE *write_f = fdopen(write_fd, "wb");
    size_t write_size;
    size_t read_size;
    while(feof(read_f) == 0) {
        char buff[100];
        if((read_size = fread(buff, 1, 100, read_f)) != 100) {
            if(ferror(read_f) != 0) {
                return -1;
            }
        }
        if((write_size = fwrite(buff, 1, read_size, write_f)) != read_size) {
            return -1;
        }
    }
    fclose(read_f);
    fclose(write_f);
    close(read_fd);
    close(write_fd);
    if (unlink("/private/var/mobile/IconBadgeBackground_Torngat.cpbitmap") != 0) {
        return -1;
    }
    chown("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/SBIconBadgeView.BadgeBackground.cpbitmap", 501, 501);
    chmod("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/SBIconBadgeView.BadgeBackground.cpbitmap", 0666);
    return 1;
}

- (IBAction)transparent:(id)sender {
    if ([self bc:"000000" transparent:YES]) {
        if (dontRespring == FALSE){[_respringBtn setHidden:NO];}
        [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
    } else {
        [self calert:@"Failed" alertMessage:@"An error has occurred." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
    }
}

- (IBAction)change:(id)sender {
    NSString *hexv = [_hexf.text stringByReplacingOccurrencesOfString:@"#" withString:@""];
    hexv = [hexv stringByReplacingOccurrencesOfString:@" " withString:@""];
    if (![hexv isEqual: @""]) {
        if ([hexv length] == 6) {
            sliderVal = _opacitySlider.value;
            int ret = [self bc:hexv.UTF8String transparent:FALSE];
            if (ret == 1) {
                if (dontRespring == FALSE){[_respringBtn setHidden:NO];}
                [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
            } else if (ret == -2) {
                [self calert:@"Failed" alertMessage:@"Torngat could not detect the correct badge size." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
            } else {
                [self calert:@"Failed" alertMessage:@"An error has occurred." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
            }
        } else {
            [self calert:@"Failed" alertMessage:@"Invalid hex code." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
        }
    } else {
        [self calert:@"Failed" alertMessage:@"No hex code was supplied." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
    }
}

- (IBAction)keybtn:(id)sender {
    [self.view endEditing:YES];
}

@end

@interface aboutVC ()

@end

@implementation aboutVC

- (void)visualStyle {
    [self.navigationController.navigationBar setValue:@(YES) forKeyPath:@"hidesShadow"];
    if(darkModeIsEnabled()) {
        [_contentDisplay.scrollView setIndicatorStyle:UIScrollViewIndicatorStyleWhite];
        [self.navigationController.navigationBar setBarStyle:UIBarStyleBlack];
        [self.navigationController.navigationBar setBarTintColor:hex(0x1B2737, 1.0)];
        [self.view setBackgroundColor:hex(0x151E29, 1.0)];
        [_contentDisplay loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"darkAbout" ofType:@"html"]]]];
        [_contentDisplay setBackgroundColor:hex(0x151E29, 1.0)];
    } else {
        [_contentDisplay.scrollView setIndicatorStyle:UIScrollViewIndicatorStyleBlack];
        [self.navigationController.navigationBar setBarStyle:UIBarStyleDefault];
        [self.navigationController.navigationBar setBarTintColor:hex(0xF2F2F2, 1.0)];
        [self.view setBackgroundColor:hex(0xFAFAFA, 1.0)];
        [_contentDisplay loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"about" ofType:@"html"]]]];
        [_contentDisplay setBackgroundColor:hex(0xFAFAFA, 1.0)];
    }
}

- (void)viewWillAppear:(BOOL)animated {
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(visualStyle)     name:@"updatedVisualStyle" object:nil];
    [self visualStyle];
}

@end

@interface settings ()
@property (strong, nonatomic) IBOutlet UILabel *darkModeText;
@property (strong, nonatomic) IBOutlet UILabel *loadingSpinnerText;
@property (strong, nonatomic) IBOutlet UILabel *exploitAutomaticallyText;
@property (strong, nonatomic) IBOutlet UITableViewCell *darkModeCell;
@property (strong, nonatomic) IBOutlet UITableViewCell *loadingSpinnerCell;
@property (strong, nonatomic) IBOutlet UITableViewCell *exploitAutomaticallyCell;
@property (strong, nonatomic) IBOutlet UITableViewCell *resizeCell;
@property (strong, nonatomic) IBOutlet UILabel *resizeText;
@property (weak, nonatomic) IBOutlet UITableViewCell *removeCell;
@property (weak, nonatomic) IBOutlet UIButton *removeButton;

@end

@implementation settings

- (IBAction)remove:(id)sender {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Remove" message:@"Do you really want to remove Torngat?" preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *yes = [UIAlertAction actionWithTitle:@"Yes" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        if ([Remover remove]) {
            respringDevice();
        }
    }];
    UIAlertAction *no = [UIAlertAction actionWithTitle:@"No" style:UIAlertActionStyleCancel handler:nil];
    [alert addAction:yes];
    [alert addAction:no];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)viewWillAppear:(BOOL)animated {
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(svs) name:@"sVS" object:nil];
    [self.darkModeCell setTranslatesAutoresizingMaskIntoConstraints:NO];
    [self.loadingSpinnerCell setTranslatesAutoresizingMaskIntoConstraints:NO];
    [self.resizeCell setTranslatesAutoresizingMaskIntoConstraints:NO];
    [self.exploitAutomaticallyCell setTranslatesAutoresizingMaskIntoConstraints:NO];
    if ([stringWithContentsOfLocalFile(@"darkMode") isEqual: @"yes"]) {
        [_darkModeSwitch setOn:YES animated:NO];
    } else {
        [_darkModeSwitch setOn:NO animated:NO];
    }
    if ([stringWithContentsOfLocalFile(@"showLoader") isEqual: @"yes"]) {
        [_loaderSwitch setOn:YES animated:NO];
    } else {
        [_loaderSwitch setOn:NO animated:NO];
    }
    if ([stringWithContentsOfLocalFile(@"autoExploit") isEqual: @"yes"]) {
        [_autoExploitSwitch setOn:YES animated:NO];
    } else {
        [_autoExploitSwitch setOn:NO animated:NO];
    }
    if([stringWithContentsOfLocalFile(@"resizeBootlogos") isEqual: @"yes"]) {
        [_resizeBootlogosSwitch setOn:YES animated:NO];
    } else {
        [_resizeBootlogosSwitch setOn:NO animated:NO];
    }
    [self.navigationController.navigationBar setValue:@(YES) forKeyPath:@"hidesShadow"];
    [self svs];
    if (!remounted()) {
        [_resizeBootlogosSwitch setEnabled:NO];
        [_resizeText setTextColor:[UIColor grayColor]];
    }
    [[NSNotificationCenter defaultCenter] postNotificationName:@"updatedVisualStyle" object:self];
}

- (void)svs {
    [self.navigationController.navigationBar setValue:@(YES) forKeyPath:@"hidesShadow"];
    if (darkModeIsEnabled()) {
        [self.parentViewController.navigationController.navigationBar setBarStyle:UIBarStyleBlack];
        [self.parentViewController.navigationController.navigationBar setBarTintColor:hex(0x1B2737, 1.0)];
        [self.view setBackgroundColor:hex(0x151E29, 1.0)];
        _darkModeText.textColor = [UIColor lightTextColor];
        _loadingSpinnerText.textColor = [UIColor lightTextColor];
        _exploitAutomaticallyText.textColor = [UIColor lightTextColor];
        _resizeText.textColor = [UIColor lightTextColor];
        _darkModeCell.backgroundColor = hex(0x151E29, 1.0);
        _loadingSpinnerCell.backgroundColor = hex(0x151E29, 1.0);
        _exploitAutomaticallyCell.backgroundColor = hex(0x151E29, 1.0);
        _resizeCell.backgroundColor = hex(0x151E29, 1.0);
        _removeCell.backgroundColor = hex(0x151E29, 1.0);
    } else {
        [self.parentViewController.navigationController.navigationBar setBarStyle:UIBarStyleDefault];
        [self.parentViewController.navigationController.navigationBar setBarTintColor:hex(0xF2F2F2, 1.0)];
        [self.view setBackgroundColor:hex(0xFAFAFA, 1.0)];
        _darkModeText.textColor = [UIColor darkTextColor];
        _loadingSpinnerText.textColor = [UIColor darkTextColor];
        _exploitAutomaticallyText.textColor = [UIColor darkTextColor];
        _resizeText.textColor = [UIColor darkTextColor];
        _darkModeCell.backgroundColor = hex(0xFAFAFA, 1.0);
        _loadingSpinnerCell.backgroundColor = hex(0xFAFAFA, 1.0);
        _exploitAutomaticallyCell.backgroundColor = hex(0xFAFAFA, 1.0);
        _resizeCell.backgroundColor = hex(0xFAFAFA, 1.0);
        _removeCell.backgroundColor = hex(0xFAFAFA, 1.0);
    }
}

- (void)enableDarkMode {
    [self.navigationController.navigationBar setValue:@(YES) forKeyPath:@"hidesShadow"];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [UIView animateWithDuration:0.2f animations:^{
        [self.parentViewController.navigationController.navigationBar setBarStyle:UIBarStyleBlack];
        [self.parentViewController.navigationController.navigationBar setBarTintColor:hex(0x1B2737, 1.0)];
        [self.view setBackgroundColor:hex(0x151E29, 1.0)];
        _darkModeText.textColor = [UIColor whiteColor];
        _loadingSpinnerText.textColor = [UIColor whiteColor];
        _exploitAutomaticallyText.textColor = [UIColor whiteColor];
        _resizeText.textColor = [UIColor whiteColor];
        _darkModeCell.backgroundColor = hex(0x151E29, 1.0);
        _loadingSpinnerCell.backgroundColor = hex(0x151E29, 1.0);
        _exploitAutomaticallyCell.backgroundColor = hex(0x151E29, 1.0);
        _resizeCell.backgroundColor = hex(0x151E29, 1.0);
        _removeCell.backgroundColor = hex(0x151E29, 1.0);
    }];
    [[NSNotificationCenter defaultCenter] postNotificationName:@"updatedVisualStyle" object:self];
}

- (void)disableDarkMode {
    [self.navigationController.navigationBar setValue:@(YES) forKeyPath:@"hidesShadow"];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault animated:YES];
    [UIView animateWithDuration:0.2f animations:^{
        [self.parentViewController.navigationController.navigationBar setBarStyle:UIBarStyleDefault];
        [self.parentViewController.navigationController.navigationBar setBarTintColor:hex(0xF2F2F2, 1.0)];
        [self.view setBackgroundColor:hex(0xFAFAFA, 1.0)];
        _darkModeText.textColor = [UIColor blackColor];
        _loadingSpinnerText.textColor = [UIColor blackColor];
        _exploitAutomaticallyText.textColor = [UIColor blackColor];
        _resizeText.textColor = [UIColor blackColor];
        _darkModeCell.backgroundColor = hex(0xFAFAFA, 1.0);
        _loadingSpinnerCell.backgroundColor = hex(0xFAFAFA, 1.0);
        _exploitAutomaticallyCell.backgroundColor = hex(0xFAFAFA, 1.0);
        _resizeCell.backgroundColor = hex(0xFAFAFA, 1.0);
        _removeCell.backgroundColor = hex(0xFAFAFA, 1.0);
    }];
    [[NSNotificationCenter defaultCenter] postNotificationName:@"updatedVisualStyle" object:self];
}

- (IBAction)toggleDarkMode:(id)sender {
    [self.navigationController.navigationBar setValue:@(YES) forKeyPath:@"hidesShadow"];
    if ([_darkModeSwitch isOn]) {
        writeToLocalFile(@"darkMode", @"yes");
        [self enableDarkMode];
    } else {
        writeToLocalFile(@"darkMode", @"no");
        [self disableDarkMode];
    }
}

- (IBAction)toggleLoader:(id)sender {
    if ([_loaderSwitch isOn]) {
        writeToLocalFile(@"showLoader", @"yes");
    } else {
        writeToLocalFile(@"showLoader", @"no");
    }
}

- (IBAction)toggleAutoExploit:(id)sender {
    if ([_autoExploitSwitch isOn]) {
        writeToLocalFile(@"autoExploit", @"yes");
    } else {
        writeToLocalFile(@"autoExploit", @"no");
    }
}

- (IBAction)toggleResizeBootlogos:(id)sender {
    if ([_resizeBootlogosSwitch isOn]) {
        writeToLocalFile(@"resizeBootlogos", @"yes");
    } else {
        writeToLocalFile(@"resizeBootlogos", @"no");
    }
}

@end

@interface dockLine ()
@property (strong, nonatomic) IBOutlet UIView *alert;
@property (strong, nonatomic) IBOutlet UILabel *alertTitle;
@property (strong, nonatomic) IBOutlet UITextView *alertText;
@property (strong, nonatomic) IBOutlet UIButton *dismissAlertBtn;
@property (strong, nonatomic) IBOutlet UIView *colourDisplay;
@property (strong, nonatomic) IBOutlet UIButton *defaultBtn;
@property (strong, nonatomic) IBOutlet UIButton *transparent;
@property (strong, nonatomic) IBOutlet UIButton *respringBtn;
@property (strong, nonatomic) IBOutlet UISlider *heightSlider;
@property (strong, nonatomic) IBOutlet UILabel *heightValue;

@end

@implementation dockLine

float sliderVal_;

- (void)calert:(NSString*)alertTitle alertMessage:(NSString*)alertMessage dismissButton:(NSString*)dismissButton buttonVis:(int)buttonVis dismissBtnAction:(SEL)dismissBtnAction {
    [_dismissAlertBtn setExclusiveTouch:YES];
    [_cancel setEnabled:NO];
    [_alert setAlpha:0.0]; [_X setAlpha:0.0];
    [_alertTitle setText:alertTitle];
    [_alertText setText:alertMessage];
    if (buttonVis == 0) {
        [_dismissAlertBtn setHidden:YES];
    } else if (buttonVis == 1) {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:@selector(calertd) forControlEvents:UIControlEventTouchUpInside];
    } else {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:dismissBtnAction forControlEvents:UIControlEventTouchUpInside];
    }
    [_alert setHidden:NO]; [_X setHidden:NO];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:1.0f]; [_X setAlpha:1.0f];
    }];
}

- (void)calertd {
    [_alert setAlpha:1.0f];
    [_X setAlpha:1.0f];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:0.0f];
        [_X setAlpha:0.0f];
    } completion:^(BOOL finished) {
        [_respringBtn setHidden:YES];
    }];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{[_alert setHidden:YES];[_X setHidden:YES];});});
    [_cancel setEnabled:YES];
}

- (IBAction)xBtnPressed:(id)sender {
    [self calertd];
}

- (NSString *)getFE:(NSURL *)url{
    NSString *urlString = [url absoluteString];
    NSArray *componentsArray = [urlString componentsSeparatedByString:@"."];
    NSString *fileExtension = [componentsArray lastObject];
    return fileExtension;
}

- (IBAction)useDefault:(id)sender {
    unlink("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/highlight-0.05a-0.5h.cpbitmap");
    if (dontRespring == FALSE){[_respringBtn setHidden:NO];}
    [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
}

- (IBAction)respringDevice:(id)sender {
    respringDevice();
}

- (void)applyBtn:(UIButton*)btnId {
    btnId.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
    btnId.layer.shadowOffset = CGSizeMake(0, 0);
    btnId.layer.shadowOpacity = 1.0f;
    btnId.layer.shadowRadius = 5;
    btnId.layer.masksToBounds = NO;
    btnId.layer.cornerRadius = 10.0f;
    btnId.exclusiveTouch = YES;
}

- (void)viewWillAppear:(BOOL)animated {
    [_colourDisplay setBackgroundColor:hex(0x000000, 1.0)];
    [self applyBtn:_change];
    [self applyBtn:_cancel];
    [self applyBtn:_defaultBtn];
    [self applyBtn:_transparent];
    [_respringBtn setHidden:YES];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [NSTimer scheduledTimerWithTimeInterval:0.4 target:self selector:@selector(updateColour) userInfo:nil repeats:YES];
}

- (void)updateColour {
    unsint rgb = 0;
    NSString *hexv = [_hexf.text stringByReplacingOccurrencesOfString:@"#" withString:@""];
    [[NSScanner scannerWithString:[[[NSString stringWithFormat:@"%s", [hexv UTF8String]] lowercaseString] stringByTrimmingCharactersInSet:[[NSCharacterSet characterSetWithCharactersInString:@"abcdef0123456789"] invertedSet]]] scanHexInt:&rgb];
    if ([hexv length] != 6) {
        [UIView animateWithDuration:0.5f animations:^{
            [_colourDisplay setBackgroundColor:hex(0x000000, 1.0)];
        }];
        return;
    }
    [UIView animateWithDuration:0.5f animations:^{
        [_colourDisplay setBackgroundColor:hex(rgb, 1.0)];
    }];
}

- (IBAction)updateHeightVal:(id)sender {
    [_heightValue setText:[NSString stringWithFormat:@"%.01f", _heightSlider.value]];
}

- (IBAction)cancel:(id)sender {
    if(!darkModeIsEnabled()){[[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault animated:YES];}
    [self dismissViewControllerAnimated:YES completion:nil];
}

UIImage *line;
int lc(const char *colour, BOOL transparent) {
    float sv = sliderVal_;
         UIGraphicsBeginImageContextWithOptions(CGRectMake(0, 0, 10000, sv).size, NO, 0.0);
         CGContextRef context = UIGraphicsGetCurrentContext();
         CGContextSetFillColorWithColor(context, [[UIColor blackColor] CGColor]);
         CGRect size;
         if (transparent == FALSE) {
             size =  CGRectMake(0, 0, 10000, sv);
         } else {
             size = CGRectMake(0, 0, 0, 0);
         }
         CGContextFillRect(context, size);
         line = UIGraphicsGetImageFromCurrentImageContext();
         UIGraphicsEndImageContext();
         UIGraphicsBeginImageContextWithOptions(CGSizeMake(10000, sv), NO, 0.0);
         CGRect bounds=(CGRect){CGPointZero, CGSizeMake(10000, sv)};
         [line drawInRect:bounds];
         line = UIGraphicsGetImageFromCurrentImageContext();
         UIGraphicsEndImageContext();
    unsint rgb = 0;
    [[NSScanner scannerWithString:[[[NSString stringWithFormat:@"%s", colour] lowercaseString] stringByTrimmingCharactersInSet:[[NSCharacterSet characterSetWithCharactersInString:@"abcdef0123456789"] invertedSet]]] scanHexInt:&rgb];
    CGRect rect = CGRectMake(0, 0, line.size.width, line.size.height);
    UIGraphicsBeginImageContextWithOptions(rect.size, NO, 0.0);
    CGContextRef context_ = UIGraphicsGetCurrentContext();
    CGContextClipToMask(context_, rect, line.CGImage);
    CGContextSetFillColorWithColor(context_, [hex(rgb, 1.0) CGColor]);
    CGContextFillRect(context_, rect);
    line = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    [line writeToCPBitmapFile:@"/private/var/mobile/DockLine_Torngat.cpbitmap" flags:1];
    unlink("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/highlight-0.05a-0.5h.cpbitmap");
    int read_fd = open("/private/var/mobile/DockLine_Torngat.cpbitmap", O_RDONLY, 0);
    int write_fd = open("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/highlight-0.05a-0.5h.cpbitmap", O_RDWR | O_CREAT | O_APPEND, 0777);
    if(fdopen(read_fd, "r") == NULL) {
        return -1;
    }
    if(fdopen(write_fd, "wb") == NULL) {
        return -1;
    }
    FILE *read_f = fdopen(read_fd, "r");
    FILE *write_f = fdopen(write_fd, "wb");
    size_t write_size;
    size_t read_size;
    while(feof(read_f) == 0) {
        char buff[100];
        if((read_size = fread(buff, 1, 100, read_f)) != 100) {
            if(ferror(read_f) != 0) {
                return -1;
            }
        }
        if((write_size = fwrite(buff, 1, read_size, write_f)) != read_size) {
            return -1;
        }
    }
    fclose(read_f);
    fclose(write_f);
    close(read_fd);
    close(write_fd);
    if (unlink("/private/var/mobile/DockLine_Torngat.cpbitmap") != 0) {
        return -1;
    }
    chown("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/highlight-0.05a-0.5h.cpbitmap", 501, 501);
    chmod("/private/var/mobile/Library/Caches/MappedImageCache/Persistent/highlight-0.05a-0.5h.cpbitmap", 0666);
    return 1;
}

- (IBAction)transparent:(id)sender {
    if (lc("000000", TRUE)) {
        if (dontRespring == FALSE){[_respringBtn setHidden:NO];}
        [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
    } else {
        [self calert:@"Failed" alertMessage:@"An error has occurred." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
    }
}

- (IBAction)change:(id)sender {
    NSString *hexv = [_hexf.text stringByReplacingOccurrencesOfString:@"#" withString:@""];
    if (![hexv isEqual: @""]) {
        if ([hexv length] == 6) {
            sliderVal_ = [[NSString stringWithFormat:@"%.01f", _heightSlider.value] floatValue];
            int ret = lc([hexv UTF8String], FALSE);
            if (ret == 1) {
                if (dontRespring == FALSE){[_respringBtn setHidden:NO];}
                [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
            } else if (ret == -2) {
                [self calert:@"Failed" alertMessage:@"Torngat could not detect the correct line size." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
            } else {
                [self calert:@"Failed" alertMessage:@"An error has occurred." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
            }
        } else {
            [self calert:@"Failed" alertMessage:@"Invalid hex code." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
        }
    } else {
        [self calert:@"Failed" alertMessage:@"No hex code was supplied." dismissButton:nil buttonVis:0 dismissBtnAction:nil];
    }
}

- (IBAction)keybtn:(id)sender {
    [self.view endEditing:YES];
}

@end

@interface layout ()
@property (strong, nonatomic) IBOutlet UIView *alert;
@property (strong, nonatomic) IBOutlet UILabel *alertTitle;
@property (strong, nonatomic) IBOutlet UITextView *alertText;
@property (strong, nonatomic) IBOutlet UIButton *dismissAlertBtn;
@property (strong, nonatomic) IBOutlet UITableView *table;
@property (strong,nonatomic) NSArray *content;

@end

@implementation layout

- (void)calert:(NSString*)alertTitle alertMessage:(NSString*)alertMessage dismissButton:(NSString*)dismissButton buttonVis:(int)buttonVis dismissBtnAction:(SEL)dismissBtnAction {
    [_dismissAlertBtn setExclusiveTouch:YES];
    [_cancel setEnabled:NO];
    [_alert setAlpha:0.0]; [_X setAlpha:0.0];
    [_alertTitle setText:alertTitle];
    [_alertText setText:alertMessage];
    if (buttonVis == 0) {
        [_dismissAlertBtn setHidden:YES];
    } else if (buttonVis == 1) {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:@selector(calertd) forControlEvents:UIControlEventTouchUpInside];
    } else {
        [_dismissAlertBtn setHidden:NO];
        [_dismissAlertBtn setTitle:dismissButton forState:UIControlStateNormal];
        [_dismissAlertBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [_dismissAlertBtn addTarget:self action:dismissBtnAction forControlEvents:UIControlEventTouchUpInside];
    }
    [_alert setHidden:NO]; [_X setHidden:NO];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:1.0f]; [_X setAlpha:1.0f];
    }];
}

- (void)calertd {
    [_alert setAlpha:1.0f];
    [_X setAlpha:1.0f];
    [UIView animateWithDuration:0.5f animations:^{
        [_alert setAlpha:0.0f];
        [_X setAlpha:0.0f];
    } completion:^(BOOL finished) {
        [_respringBtn setHidden:YES];
    }];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{[NSThread sleepForTimeInterval:0.5f];dispatch_async(dispatch_get_main_queue(),^{[_alert setHidden:YES];[_X setHidden:YES];});});
    [_cancel setEnabled:YES];
}

- (IBAction)xBtnPressed:(id)sender {
    [self calertd];
}

- (void)applyBtn:(UIButton*)btnId {
    btnId.layer.shadowColor = [[UIColor colorWithRed:0 green:0 blue:0 alpha:0.25f] CGColor];
    btnId.layer.shadowOffset = CGSizeMake(0, 0);
    btnId.layer.shadowOpacity = 1.0f;
    btnId.layer.shadowRadius = 5;
    btnId.layer.masksToBounds = NO;
    btnId.layer.cornerRadius = 10.0f;
    btnId.exclusiveTouch = YES;
}

- (void)viewWillAppear:(BOOL)animated {
    [_respringBtn setHidden:YES];
    [self applyBtn:_change];
    [self applyBtn:_cancel];
    getDocumentsDirectory();
    BOOL isDir;
    BOOL ret = [[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithFormat:@"%@/layouts/", documentsDirectory] isDirectory:&isDir];
    NSLog(@"%i", ret); NSLog(@"%i", isDir);
    if (!isDir) {
        removeLocalFile(@"layouts");
        createLocalDirectory(@"layouts");
        chmod(stringWithPathOfLocalFile(@"layout").UTF8String, 0666);
        chown(stringWithPathOfLocalFile(@"layout").UTF8String, 501, 501);
    }
    chmod(stringWithPathOfLocalFile(@"layout").UTF8String, 0666);
    chown(stringWithPathOfLocalFile(@"layout").UTF8String, 501, 501);
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent animated:YES];
    [self configureTableview];
    self.content = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[NSString stringWithFormat:@"%@/layouts/", documentsDirectory] error:nil];
}

- (IBAction)cancel:(id)sender {
    if(!darkModeIsEnabled()){[[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleDefault animated:YES];}
    [self dismissViewControllerAnimated:YES completion:nil];
}

-(void)configureTableview {
    self.table.delegate = self;
    self.table.dataSource = self;
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return _content.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cellIdentifier = @"cellIdentifier";
    UITableViewCell *cell = [self.table dequeueReusableCellWithIdentifier:cellIdentifier];
    if(cell == nil) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:cellIdentifier];
    }
    cell.textLabel.text =  [_content objectAtIndex:indexPath.row];
    cell.backgroundColor = hex(0x000000, 0.0);
    cell.textLabel.textColor = hex(0xFFFFFF, 1.0);
    //cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

NSString *b;

- (void)yesido {
    [self calertd];
    unlink("/var/mobile/Library/SpringBoard/IconState.plist");
    [[NSMutableDictionary dictionaryWithContentsOfFile:stringWithPathOfLocalFile([NSString stringWithFormat:@"layouts/%@", b])] writeToFile:@"/var/mobile/Library/SpringBoard/IconState.plist" atomically:YES];
    chown("/var/mobile/Library/SpringBoard/IconState.plist", 501, 501);
    chmod("/var/mobile/Library/SpringBoard/IconState.plist", 0666); dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{ [NSThread sleepForTimeInterval:0.51f];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (dontRespring == FALSE){[_respringBtn setHidden:NO];}
            [self calert:@"Success" alertMessage:@"Please respring your device." dismissButton:@"Dismiss" buttonVis:2 dismissBtnAction:@selector(cancel:)];
        });});
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath; {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    b = [NSString stringWithFormat:@"%@", [_content objectAtIndex:indexPath.row]];
    [_respringBtn setHidden:YES];
    [self calert:@"Confirmation" alertMessage:[NSString stringWithFormat:@"Do you really want to set your home screen layout to the one saved on %@?", [_content objectAtIndex:indexPath.row]] dismissButton:@"Continue" buttonVis:2 dismissBtnAction:@selector(yesido)];
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    return YES;
}

- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle == UITableViewCellEditingStyleDelete) {
        removeLocalFile([NSString stringWithFormat:@"layouts/%@", [_content objectAtIndex:indexPath.row]]);
        self.content = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[NSString stringWithFormat:@"%@/layouts/", documentsDirectory] error:nil];
        [self.table reloadData];
    }
}

- (IBAction)respringDevice:(id)sender {
    respringDevice();
}

- (IBAction)change:(id)sender {
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd_hh:mm:ss"];
    NSString *d = [NSString stringWithFormat:@"%@", [dateFormatter stringFromDate:[NSDate date]]];
    printf("name: %s\n", d.UTF8String);
#ifndef guionly
    [[NSMutableDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/SpringBoard/IconState.plist"] writeToFile:stringWithPathOfLocalFile([NSString stringWithFormat:@"layouts/%@", d]) atomically:YES];
    chown(stringWithPathOfLocalFile([NSString stringWithFormat:@"layouts/%@", d]).UTF8String, 501, 501);
    chmod(stringWithPathOfLocalFile([NSString stringWithFormat:@"layouts/%@", d]).UTF8String, 0666);
#else
    NSLog(@"write test");
    NSError *e;
    [@"test" writeToFile:stringWithPathOfLocalFile([NSString stringWithFormat:@"layouts/%@", d]) atomically:YES encoding:NSUTF8StringEncoding error:&e];
    NSLog(@"%@", e);
    NSLog(@"%@", stringWithContentsOfLocalFile([NSString stringWithFormat:@"layouts/%@", d]));
    chown(stringWithPathOfLocalFile([NSString stringWithFormat:@"layouts/%@", d]).UTF8String, 501, 501);
    chmod(stringWithPathOfLocalFile([NSString stringWithFormat:@"layouts/%@", d]).UTF8String, 0666);
#endif
    NSLog(@"%@", [NSMutableDictionary dictionaryWithContentsOfFile:stringWithPathOfLocalFile([NSString stringWithFormat:@"layouts/%@", d])]);
    self.content = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:stringWithPathOfLocalFile(@"layouts") error:nil];
    NSLog(@"%@", _content);
    [self.table reloadData];
}

- (IBAction)keybtn:(id)sender {
    [self.view endEditing:YES];
}

@end
