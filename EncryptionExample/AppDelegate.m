//
//  AppDelegate.m
//  EncryptionExample
//
//  Created by Collin B. Stuart on 2014-04-29.
//  Copyright (c) 2014 CollinBStuart. All rights reserved.
//

#import "AppDelegate.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>

const CFStringRef kEncryptedData = CFSTR("EncryptedData");
const CFStringRef kEncryptionKey = CFSTR("EncryptedKey");
const CFStringRef kEncryptedInitializationVector = CFSTR("EncryptedIV");

@implementation AppDelegate

CFDictionaryRef EncryptAES128FromData(CFDataRef plainTextData)
{
    //password
    uint8_t password[kCCKeySizeAES128];
    OSStatus result = SecRandomCopyBytes(kSecRandomDefault, kCCKeySizeAES128, password); //  /dev/random is used
    if (result != errSecSuccess)
    {
        CFShow(CFSTR("\nCould not create password"));
    }
    
    //salt
    uint8_t salt[8];
    result = SecRandomCopyBytes(kSecRandomDefault, 8, salt);
    if (result != errSecSuccess)
    {
        CFShow(CFSTR("\nCould not create salt"));
    }
    
    //key
    uint8_t derivedKey;
    CCCryptorStatus cryptResult = CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)password, sizeof(password), salt, sizeof(salt), kCCPRFHmacAlgSHA1, 10000, &derivedKey, kCCKeySizeAES128);
    if (cryptResult != kCCSuccess)
    {
        CFShow(CFSTR("\nCould not create key"));
    }
    CFDataRef keyData = CFDataCreate(kCFAllocatorDefault, &derivedKey, kCCKeySizeAES128);
    
    //generate an initialization vector
    uint8_t ivBytesChar[kCCBlockSizeAES128];
    result = SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, ivBytesChar);
    if (result != errSecSuccess)
    {
        CFShow(CFSTR("\nCould not create IV"));
    }
    CFDataRef ivData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)ivBytesChar, kCCBlockSizeAES128);
    
    //encrypt
    size_t outLength;
    CFIndex encryptedLength = CFDataGetLength(plainTextData) + kCCBlockSizeAES128;
    CFMutableDataRef encryptedData = CFDataCreateMutable(kCFAllocatorDefault, encryptedLength);
    cryptResult = CCCrypt(kCCEncrypt,
                          kCCAlgorithmAES128,
                          kCCOptionPKCS7Padding,
                          CFDataGetBytePtr(keyData),
                          CFDataGetLength(keyData),
                          CFDataGetBytePtr(ivData),
                          CFDataGetBytePtr(plainTextData),
                          CFDataGetLength(plainTextData),
                          CFDataGetMutableBytePtr(encryptedData),
                          encryptedLength,
                          &outLength);
    if (cryptResult == kCCSuccess)
    {
        CFDataSetLength(encryptedData, outLength);
    }
    else
    {
        CFShow(CFSTR("\nEncryption error"));
    }
    

    CFMutableDictionaryRef encryptionDictionary = CFDictionaryCreateMutable(kCFAllocatorDefault, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(encryptionDictionary, kEncryptedData, encryptedData);
    CFDictionarySetValue(encryptionDictionary, kEncryptionKey, keyData);
    CFDictionarySetValue(encryptionDictionary, kEncryptedInitializationVector, ivData);
    CFRelease(encryptedData);
    CFRelease(keyData);
    CFRelease(ivData);
    return CFAutorelease(encryptionDictionary);
}

CFDataRef DecryptAES128File(CFDictionaryRef cipherText)
{
    //get encrypted data as data object
    CFDataRef encryptedData = CFDictionaryGetValue(cipherText, kEncryptedData);
    
    //get the key
    CFDataRef key = CFDictionaryGetValue(cipherText, kEncryptionKey);
    
    //get the initialization vector
    CFDataRef iv = CFDictionaryGetValue(cipherText, kEncryptedInitializationVector);
    
    size_t outLength = 0;
    size_t decryptedLength = CFDataGetLength(encryptedData) + kCCBlockSizeAES128;
    CFMutableDataRef decryptedData = CFDataCreateMutable(kCFAllocatorDefault, decryptedLength);
    CCCryptorStatus cryptResult = CCCrypt(kCCDecrypt,
                          kCCAlgorithmAES128,
                          kCCOptionPKCS7Padding,
                          CFDataGetBytePtr(key),
                          CFDataGetLength(key),
                          CFDataGetBytePtr(iv),
                          CFDataGetBytePtr(encryptedData),
                          CFDataGetLength(encryptedData),
                          CFDataGetMutableBytePtr(decryptedData),
                          decryptedLength,
                          &outLength);
    if (cryptResult == kCCSuccess)
    {
        CFDataSetLength(decryptedData, outLength);
    }
    else
    {
        CFShow(CFSTR("\nDecryption error"));
    }

    return CFAutorelease(decryptedData);
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    NSDictionary *encryptedDictionary = (__bridge NSDictionary *)EncryptAES128FromData((__bridge CFDataRef)[@"test string to encrypt" dataUsingEncoding:NSUTF8StringEncoding]);
    
    NSData *data = (__bridge NSData *)DecryptAES128File((__bridge CFDictionaryRef)encryptedDictionary);
    
    NSString *decodedString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    NSLog(@"Decrypted string is: %@", decodedString);
    
    return YES;
}
							
- (void)applicationWillResignActive:(UIApplication *)application
{
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
}

- (void)applicationDidEnterBackground:(UIApplication *)application
{
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later. 
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}

- (void)applicationWillEnterForeground:(UIApplication *)application
{
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
}

- (void)applicationDidBecomeActive:(UIApplication *)application
{
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}

- (void)applicationWillTerminate:(UIApplication *)application
{
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}

@end
