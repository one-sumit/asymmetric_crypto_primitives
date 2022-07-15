#import "AsymmetricCryptoPrimitivesPlugin.h"
#if __has_include(<asymmetric_crypto_primitives/asymmetric_crypto_primitives-Swift.h>)
#import <asymmetric_crypto_primitives/asymmetric_crypto_primitives-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "asymmetric_crypto_primitives-Swift.h"
#endif

@implementation AsymmetricCryptoPrimitivesPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftAsymmetricCryptoPrimitivesPlugin registerWithRegistrar:registrar];
}
@end
