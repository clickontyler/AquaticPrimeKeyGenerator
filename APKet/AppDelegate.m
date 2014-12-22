//
//  AppDelegate.m
//  APKet
//
//  Created by Tyler Hall on 12/22/14.
//  Copyright (c) 2014 Click On Tyler. All rights reserved.
//

#import "AppDelegate.h"

@interface AppDelegate () {
    RSA *rsaKey;
    IBOutlet NSTextView *rsaKeyView;
    IBOutlet NSTextView *publicKeyView;
    IBOutlet NSTextView *privateKeyView;
}

@property (weak) IBOutlet NSWindow *window;

@end

@implementation AppDelegate

#define WINDOW_THRESH 30

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    rsaKey = RSA_generate_key(1024, 3, NULL, NULL);
    
    // The public key
    NSString *pubKey = [NSString stringWithFormat:@"0x%s", BN_bn2hex(rsaKey->n)];
    // How many characters we have left
    int lengthLeft = [pubKey length];
    // Where we are now
    int curPos = 0;
    
    NSMutableString *pubConstruct = [NSMutableString stringWithString:@"\n\t// This string is specially constructed to prevent key replacement \
                                     // *** Begin Public Key ***\n\tCFMutableStringRef key = CFStringCreateMutable(NULL, 0);\n"];
    
    while ((lengthLeft - WINDOW_THRESH) > 0) {
        // Logic to check for repeats
        int repeated = 0;
        char charBuf = 0;
        int i;
        for (i = curPos; i < WINDOW_THRESH + curPos; i++) {
            // We have a repeat!
            if (charBuf == [pubKey characterAtIndex:i]) {
                // Print up to repeat
                [pubConstruct appendString:[NSString stringWithFormat:@"\tCFStringAppend(key, CFSTR(\"%@\"));\n", [pubKey substringWithRange:NSMakeRange(curPos, (i-1) - curPos)]]];
                //Do the repeat
                [pubConstruct appendString:[NSString stringWithFormat:@"\tCFStringAppend(key, CFSTR(\"%@\"));\n", [pubKey substringWithRange:NSMakeRange(i-1, 1)]]];
                [pubConstruct appendString:[NSString stringWithFormat:@"\tCFStringAppend(key, CFSTR(\"%@\"));\n", [pubKey substringWithRange:NSMakeRange(i, 1)]]];
                // Finish the line
                [pubConstruct appendString:[NSString stringWithFormat:@"\tCFStringAppend(key, CFSTR(\"%@\"));\n", [pubKey substringWithRange:NSMakeRange(i+1, (WINDOW_THRESH + curPos) - (i+1))]]];
                repeated = 1;
                break;
            }
            charBuf = [pubKey characterAtIndex:i];
        }
        // No repeats
        if (!repeated)
            [pubConstruct appendString:[NSString stringWithFormat:@"\tCFStringAppend(key, CFSTR(\"%@\"));\n", [pubKey substringWithRange:NSMakeRange(curPos, WINDOW_THRESH)]]];
        
        lengthLeft -= WINDOW_THRESH;
        curPos += WINDOW_THRESH;
    }
    [pubConstruct appendString:[NSString stringWithFormat:@"\tCFStringAppend(key, CFSTR(\"%@\"));\n\t// *** End Public Key *** \n", [pubKey substringWithRange:NSMakeRange(curPos, lengthLeft)]]];
    
    // Populate key view
    [rsaKeyView setString:pubConstruct];
    [publicKeyView setString:[self publicKey]];
    [privateKeyView setString:[self privateKey]];
}

- (NSString *)publicKey
{
    NSString *nString;
    char *cString;
    
    if (!rsaKey->n)
        return nil;
    
    cString = BN_bn2hex(rsaKey->n);

    nString = [NSString stringWithFormat:@"0x%s", cString];
    OPENSSL_free(cString);
    
    return nString;
}

- (NSString *)privateKey
{
    NSString *nString;
    char *cString;
    
    if (!rsaKey->d)
        return nil;
    
    cString = BN_bn2hex(rsaKey->d);
    
    nString = [NSString stringWithFormat:@"0x%s", cString];
    OPENSSL_free(cString);
    
    return nString;
}

@end
