#import "AppDelegate.h"
#include "ViewController.h"

@interface AppDelegate ()

@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    return YES;
}

- (void)applicationWillTerminate:(UIApplication *)application {
    setuid(501);
}

- (BOOL)application:(UIApplication *)application handleOpenURL:(NSURL *)url {
    if (exploitationComplete) {
        NSString *URL = [NSString stringWithFormat:@"%@", url];
        ___URL = URL;
    }
    return YES;
}

@end
