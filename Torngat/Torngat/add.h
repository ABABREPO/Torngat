#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <sys/cdefs.h>

@class LSApplicationProxy;

__BEGIN_DECLS

UIImage *_UIImageWithName(NSString *name);

__END_DECLS

@interface UIImage (Private)

+ (instancetype)kitImageNamed:(NSString *)name;
+ (instancetype)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle;

+ (instancetype)imageWithContentsOfCPBitmapFile:(NSString *)filename flags:(NSInteger)flags;

- (instancetype)_flatImageWithColor:(UIColor *)color;

- (BOOL)writeToCPBitmapFile:(NSString *)filename flags:(NSInteger)flags;

@property CGFloat scale;

@end

@interface NSArray(removeFromArray)
- (NSArray *)arrayByRemovingObject:(nonnull id)object;
- (NSArray *)arrayByRemovingObjectsFromArray:(NSArray *)array;
@end

@implementation NSArray(removeFromArray)
- (NSArray *)arrayByRemovingObject:(nonnull id)object {
    if (self.count == 0) {
        return @[];
    }
    NSArray *arr = @[];
    for (unsigned long i = 0; i < self.count; ++i) {
        if (![object isEqual:[self objectAtIndex:i]]) {
            arr = [arr arrayByAddingObject:[self objectAtIndex:i]];
        }
    }
    return arr;
}
- (NSArray *)arrayByRemovingObjectsFromArray:(NSArray *)array {
    if (self.count == 0) {
        return @[];
    }
    NSArray *arr = @[];
    for (unsigned long i = 0; i < self.count; ++i) {
        if (![array containsObject:[self objectAtIndex:i]]) {
            arr = [arr arrayByAddingObject:[self objectAtIndex:i]];
        }
    }
    return arr;
}
@end

@interface UIImage(ext)
+ (UIImage *)imageWithImage:(UIImage *)image scaledToSize:(CGSize)newSize;

@end

@implementation UIImage(ext)
+ (UIImage *)imageWithImage:(UIImage *)image scaledToSize:(CGSize)newSize {
    UIGraphicsBeginImageContextWithOptions(newSize, NO, 0.0);
    [image drawInRect:CGRectMake(0, 0, newSize.width, newSize.height)];
    UIImage *newImage = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return newImage;
}

@end
