#import <UIKit/UIKit.h>

extern NSString *___URL;
extern BOOL exploitationComplete;

@interface ViewController : UIViewController
@property (strong, nonatomic) IBOutlet UIView *X;

@end

@interface Done : UIViewController
@property (strong, nonatomic) IBOutlet UIView *X;
- (void)_urlScheme:(NSString *)url;
@end

@interface tweaksView : UIViewController

@end

@interface resizeViewController : UIViewController

@end

@interface blockRevokes : UIViewController
@property (strong, nonatomic) IBOutlet UIButton *block;
@property (strong, nonatomic) IBOutlet UIButton *cancel;
@property (strong, nonatomic) IBOutlet UIView *X;

@end

@interface blockUpdates : UIViewController
@property (strong, nonatomic) IBOutlet UIButton *block;
@property (strong, nonatomic) IBOutlet UIButton *cancel;
@property (strong, nonatomic) IBOutlet UIView *X;

@end

@interface res : UIViewController
@property (strong, nonatomic) IBOutlet UISegmentedControl *o;
@property (strong, nonatomic) IBOutlet UIButton *change;
@property (strong, nonatomic) IBOutlet UIButton *cancel;
@property (strong, nonatomic) IBOutlet UIView *X;

@end

@interface cc : UIViewController

@end

@interface Masks : UIViewController
@property (strong, nonatomic) IBOutlet UIButton *change;
@property (strong, nonatomic) IBOutlet UIButton *cancel;
@property (strong, nonatomic) IBOutlet UIButton *custom;
@property (strong, nonatomic) IBOutlet UISegmentedControl *o;
@property (strong, nonatomic) IBOutlet UIView *X;

@end

@interface bootlogo : UIViewController
@property (strong, nonatomic) IBOutlet UIButton *change;
@property (strong, nonatomic) IBOutlet UIButton *cancel;
@property (strong, nonatomic) IBOutlet UIButton *revert;
@property (strong, nonatomic) IBOutlet UIView *url;
@property (strong, nonatomic) IBOutlet UITextField *urlf;
@property (strong, nonatomic) IBOutlet UIView *X;

@end

@interface layout : UIViewController
@property (strong, nonatomic) IBOutlet UIButton *change;
@property (strong, nonatomic) IBOutlet UIButton *cancel;
@property (strong, nonatomic) IBOutlet UIView *X;
@property (strong, nonatomic) IBOutlet UIButton *respringBtn;

@end

@interface respringv : UIViewController

@end

@interface credits : UIViewController
@property (strong, nonatomic) IBOutlet UIView *one;
@property (strong, nonatomic) IBOutlet UIView *two;
@property (strong, nonatomic) IBOutlet UIView *three;
@property (strong, nonatomic) IBOutlet UIView *four;
@property (strong, nonatomic) IBOutlet UIView *five;
@property (strong, nonatomic) IBOutlet UIView *six;
@property (strong, nonatomic) IBOutlet UIScrollView *scroll;
@property (strong, nonatomic) IBOutlet UIImageView *icons8;

@end

@interface fonts : UIViewController
@property (strong, nonatomic) IBOutlet UIView *X;

@end

@interface bigFullscreenBoi : UIViewController
@property (strong, nonatomic) IBOutlet UIView *alert;
@property (strong, nonatomic) IBOutlet UIView *X;
@property (strong, nonatomic) IBOutlet UILabel *titleT;
@property (strong, nonatomic) IBOutlet UITextView *text;

@end

@interface badges : UIViewController
@property (strong, nonatomic) IBOutlet UIButton *cancel;
@property (strong, nonatomic) IBOutlet UIButton *change;
@property (strong, nonatomic) IBOutlet UITextField *hexf;
@property (strong, nonatomic) IBOutlet UIView *X;

@end

@interface aboutVC : UIViewController
@property (strong, nonatomic) IBOutlet UIWebView *contentDisplay;

@end

@interface settings : UITableViewController
- (void)enableDarkMode;
- (void)disableDarkMode;
- (void)viewWillAppear:(BOOL)animated;
@property (strong, nonatomic) IBOutlet UISwitch *darkModeSwitch;
@property (strong, nonatomic) IBOutlet UISwitch *loaderSwitch;
@property (strong, nonatomic) IBOutlet UISwitch *autoExploitSwitch;
@property (strong, nonatomic) IBOutlet UISwitch *resizeBootlogosSwitch;
@end

@interface dockLine : UIViewController
@property (strong, nonatomic) IBOutlet UIButton *cancel;
@property (strong, nonatomic) IBOutlet UIButton *change;
@property (strong, nonatomic) IBOutlet UITextField *hexf;
@property (strong, nonatomic) IBOutlet UIView *X;

@end
