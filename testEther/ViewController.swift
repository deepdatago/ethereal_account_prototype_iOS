//
//  ViewController.swift
//  testEther
//
//  Created by tnnd on 5/28/18.
//  Copyright © 2018 Mingjun. All rights reserved.
//

import UIKit
import Geth
import Security
import RNCryptor

class ViewController: UIViewController {
    // properties

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        let labelHeight = 1000
        let label = UILabel(frame: CGRect(x: 0, y: 0, width: 400, height: labelHeight))
        label.center = CGPoint(x: 205, y: labelHeight/2)
        label.layer.borderColor = UIColor.green.cgColor
        label.layer.borderWidth = 0.5
        label.textAlignment = .left
        let datadir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)[0]
        let ks = GethNewKeyStore(datadir + "/keystore", GethLightScryptN, GethLightScryptP);
        // label.text = "datadir: " + datadir
        let password = "password"
        let accounts = (ks?.getAccounts())!
        var newAccount: GethAccount
        if (accounts.size() <= 0) {
            newAccount = createUser(ks:ks!, password:password)
        }
        else {
            newAccount = try! accounts.get(0)
        }
        
        // let newAccount = try! ks?.newAccount(password)
        
        // Export the newly created account with a different passphrase. The returned
        // data from this method invocation is a JSON encoded, encrypted key-file.
        // let jsonKey = try! ks?.exportKey(newAcc!, passphrase: password, newPassphrase: "Export password")
        
        // Update the passphrase on the account created above inside the local keystore.
        // try! ks?.update(newAcc, passphrase: "Creation password", newPassphrase: "Update password")
        
        // Delete the account updated above from the local keystore.
        // try! ks?.delete(newAcc, passphrase: "Update password")
        
        // Import back the account we've exported (and then deleted) above with yet
        // again a fresh passphrase.
        // let impAcc  = try! ks?.importKey(jsonKey, passphrase: "Export password", newPassphrase: "Import password")
        // label.text = "account: "
        let acctHex = newAccount.getAddress().getHex()
        let content = "account: " + acctHex!
        label.text = content
        label.lineBreakMode = .byWordWrapping
        label.numberOfLines = 45
        label.font = label.font.withSize(20)

        // create transaction
        // let myString = "abc" as NSString
        // let myNSData = myString.data(using: String.Encoding.utf8.rawValue)! as NSData
        // let signedTrans = signTransaction(ks:ks!, account:newAccount, password:password, data:myNSData)
        let myString = "abc"
        let myNSData = myString.data(using: .utf8)!
        let signedTrans = signTransaction(ks:ks!, account:newAccount, password:password, data:myNSData)
        label.text = label.text! + "\n\nsigned transaction: " + signedTrans
        
        var publicKeyPEM: String!
        var privateKeyPEM: String!
        
        (publicKeyPEM, privateKeyPEM) = generateKeyPairPEM()
        

        // load public/private key from string
        // var publicKeyFromStr: SecKey?
        // var privateKeyFromStr: SecKey?

        // addRSAPublicKey(_ pubkeyBase64: String, tagName: String)
        var publicKeyTagName: String! // concatenate with hash of key
        var privateKeyTagName: String! // concatenate with hash of key
        (publicKeyTagName, privateKeyTagName) = generateKeyTagsFromKeyPEM(publicKeyPEM: publicKeyPEM, privateKeyPEM: privateKeyPEM)
        // publicKeyFromStr = try! RSAUtils.addRSAPublicKey(publicKeyPEM, tagName: publicKeyTagName)
        // privateKeyFromStr = try! RSAUtils.addRSAPrivateKey(privateKeyPEM, tagName: privateKeyTagName)
        
        let input = "Hello World"
        
        // let encodedData = RSAUtils.encryptWithRSAKey(data, rsaKeyRef:publicKey!, padding: SecPadding.PKCS1)
        let encryptedData = RSAUtils.encryptWithRSAKey(str: input, tagName: publicKeyTagName)
        let encryptedStr = encryptedData?.base64EncodedString()
        // let encodedStr = String(data: encodedData!, encoding: String.Encoding.utf8) as String!
        print ("encoded str: \((encryptedStr!))")

        let decodedData = Data(base64Encoded: encryptedStr!)
        let decryptedData = RSAUtils.decryptWithRSAKey(encryptedData: decodedData!, tagName: privateKeyTagName)
        var backToString2 = String(data: decryptedData!, encoding: String.Encoding.utf8) as String!
        NSLog("decrypted string: \((backToString2!))")

        /*
        var error: Unmanaged<CFError>?
        let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA512
        guard let cipherText = SecKeyCreateEncryptedData(publicKeyFromStr,
                                                         algorithm,
                                                         plainText as CFData,
                                                         &error) as Data? else {
                                                            throw error!.takeRetainedValue() as Error
        }
        */
        
        // AES encryption
            // AES encryption
        let aesInput = "Hello"
        let aesData = aesInput.data(using: .utf8)
        let guidStr = UUID().uuidString
        // let aesKey = guidStr.replacingOccurrences(of: "-", with: "")
        let aesKey = "5978A3C7E8BC4F8CB2D6080C18A5F689"
        print("aesKey: \(aesKey)")

        let cipherStr = aesEncryptToBase64String(key:aesKey, input:aesInput)!
        print ("cipher text: \((cipherStr))")

        let originalStr = aesDecryptFromBase64String(base64Input:cipherStr, key:aesKey)
        print ("decrypted text: \((originalStr!))")

        let registerRequestStr = getRegisterRequest(ks:ks!, account:newAccount, password:password, publicKeyPEM:publicKeyPEM)!
        print("register request: \((registerRequestStr))")
        
        // create friend request:
        let friendAccountAddress = "0xf021a64E5227A786AC2ed1A605Dcd3dD5B63A29b"
        let friendPublicKeyPEM = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1pwLugBWGMqU6xJCs6p40VT5MrsWcOPXEcd/sRQpPcQ/reg1aWdNlQoN7I8VHpDsmnTvOQCbe0rowHEXVaJ0tRi8x7bjL6dBXVg+58oTLKG6vbyxTQNfPd7LWW6CBgR5G2FfNWs1LRgRIOLLPff5bcHHo/fp5lZMZIKlCwKIsyzfa5r4PiEJALKV5chse+LWXGeP11LM4ROUk5fvBDijdqI2B+btO1rqNOmU6QdO5eAxU3Cq2by+4Qms6v/DEQrPuIJMSHTxU4Q9cda1qq9yhhoaaG7ZSRQQajYr3aupsXlF6EPViWL2Smc9nyXcqalKsZ0jzivvcsCKYgFvAsFS3wIDAQAB\n-----END RSA PUBLIC KEY----- "
        
        let friendRequestStr = getFriendRequest(ks: ks!, fromAccount: newAccount, toAccountAddress: friendAccountAddress, toAccountPublicKeyPEM: friendPublicKeyPEM, password: password, friendKey: aesKey, allFriendsKey: aesKey)!
        print("friend request: \((friendRequestStr))")

        // approve friend request:
        // approveFriendRequest
        // let friendAccountAddress = "0xf021a64E5227A786AC2ed1A605Dcd3dD5B63A29b"
        
        let approveRequestStr = approveFriendRequest(ks: ks!, fromAccount: newAccount, requestAddress: friendAccountAddress, password: password, mutualKey: aesKey, allFriendsKey: aesKey)!
        print("approve request: \((approveRequestStr))")
        self.view.addSubview(label)
    }
    
    func getRegisterRequest(ks: GethKeyStore, account: GethAccount, password: String, publicKeyPEM: String!) -> String! {
        // let myString = publicKeyPEM as NSString
        // let myNSData = myString.data(using: String.Encoding.utf8.rawValue)! as NSData
       
        let data = publicKeyPEM.data(using: .utf8)!
        let transactionStr = signTransaction(ks: ks, account: account, password: password, data: data)
        var request: NSMutableDictionary = NSMutableDictionary()
        request.setValue(transactionStr, forKey:"transaction")
        request.setValue(account.getAddress().getHex(), forKey:"sender_address")
        
        let aesKey = "5978A3C7E8BC4F8CB2D6080C18A5F689"
        let senderName = "Name"
        request.setValue(aesEncryptToBase64String(key:aesKey, input:senderName), forKey:"name")


        let jsonData = try! JSONSerialization.data(withJSONObject: request, options: JSONSerialization.WritingOptions()) as NSData
        let jsonString = NSString(data: jsonData as Data, encoding: String.Encoding.utf8.rawValue) as! String
        return jsonString
    }
    
    func publicKeyEncryptToBase64(publicKeyPEM:String!, input:String) -> String! {
        let publicKeyTag = "publicKey_" + MD5HashToBase64(string:publicKeyPEM)
        try! RSAUtils.addRSAPublicKey(publicKeyPEM, tagName: publicKeyTag)
        let publicKeyEncryptedData = RSAUtils.encryptWithRSAKey(str: input, tagName: publicKeyTag)
        return publicKeyEncryptedData?.base64EncodedString()


    }
    
    func getFriendRequest(ks: GethKeyStore, fromAccount: GethAccount, toAccountAddress:String!, toAccountPublicKeyPEM:String!, password: String, friendKey:String!, allFriendsKey:String!) -> String! {
        
        var keysRequest: NSMutableDictionary = NSMutableDictionary()
        keysRequest.setValue(friendKey, forKey:"friend_request_symmetric_key")
        keysRequest.setValue(allFriendsKey, forKey:"all_friends_symmetric_key")
        let keysRequestData = try! JSONSerialization.data(withJSONObject: keysRequest, options: JSONSerialization.WritingOptions()) as NSData
        let keysRequestString = NSString(data: keysRequestData as Data, encoding: String.Encoding.utf8.rawValue) as! String
        let encryptedKeysStr = publicKeyEncryptToBase64(publicKeyPEM: toAccountPublicKeyPEM!, input: keysRequestString)!
        let encrpytedKeyStrData = encryptedKeysStr.data(using: .utf8)!
        let transactionStr = signTransaction(ks: ks, account: fromAccount, password: password, data: encrpytedKeyStrData)

        var friendRequest: NSMutableDictionary = NSMutableDictionary()
        friendRequest.setValue(0, forKey:"action_type")
        friendRequest.setValue(toAccountAddress, forKey:"to_address")
        friendRequest.setValue(fromAccount.getAddress().getHex(), forKey:"from_address")
        friendRequest.setValue(transactionStr, forKey:"request")
        let friendRequestData = try! JSONSerialization.data(withJSONObject: friendRequest, options: JSONSerialization.WritingOptions()) as NSData
        let friendRequestDataString = NSString(data: friendRequestData as Data, encoding: String.Encoding.utf8.rawValue) as! String
        return friendRequestDataString

    }
    
    func approveFriendRequest(ks: GethKeyStore, fromAccount: GethAccount, requestAddress:String!, password: String, mutualKey:String!, allFriendsKey:String!) -> String! {
        
        var keysRequest: NSMutableDictionary = NSMutableDictionary()
        keysRequest.setValue(allFriendsKey, forKey:"all_friends_symmetric_key")
        let keysRequestData = try! JSONSerialization.data(withJSONObject: keysRequest, options: JSONSerialization.WritingOptions()) as NSData
        let keysRequestString = NSString(data: keysRequestData as Data, encoding: String.Encoding.utf8.rawValue) as! String
        let encryptedKeysStr = aesEncryptToBase64String(key: mutualKey, input: keysRequestString)!
        let encrpytedKeyStrData = encryptedKeysStr.data(using: .utf8)!
        let transactionStr = signTransaction(ks: ks, account: fromAccount, password: password, data: encrpytedKeyStrData)
        
        var friendRequest: NSMutableDictionary = NSMutableDictionary()
        friendRequest.setValue(1, forKey:"action_type")
        friendRequest.setValue(fromAccount.getAddress().getHex(), forKey:"to_address")
        friendRequest.setValue(requestAddress, forKey:"from_address")
        friendRequest.setValue(transactionStr, forKey:"request")
        let approveRequestData = try! JSONSerialization.data(withJSONObject: friendRequest, options: JSONSerialization.WritingOptions()) as NSData
        let approveRequestDataString = NSString(data: approveRequestData as Data, encoding: String.Encoding.utf8.rawValue) as! String
        return approveRequestDataString
        
    }


    func MD5HashToBase64(string: String) -> String! {
        let messageData = string.data(using:.utf8)!
        var digestData = Data(count: Int(CC_MD5_DIGEST_LENGTH))
        
        _ = digestData.withUnsafeMutableBytes {digestBytes in
            messageData.withUnsafeBytes {messageBytes in
                CC_MD5(messageBytes, CC_LONG(messageData.count), digestBytes)
            }
        }
        return digestData.base64EncodedString()
    }
    
    func generateKeyTagsFromKeyPEM(publicKeyPEM: String, privateKeyPEM:String) -> (String!, String!) {
        let publicKeyTagName = "publicKeyTag_" + MD5HashToBase64(string: publicKeyPEM) // concatenate with hash of key
        let privateKeyTagName = "privateKeyTag_" + MD5HashToBase64(string: privateKeyPEM)// concatenate with hash of key
        try! RSAUtils.addRSAPublicKey(publicKeyPEM, tagName: publicKeyTagName)
        try! RSAUtils.addRSAPrivateKey(privateKeyPEM, tagName: privateKeyTagName)
        return (publicKeyTagName, privateKeyTagName)

    }
    func generateKeyPairPEM() -> (String!, String!) {
        var statusCode: OSStatus?
        var publicKey: SecKey?
        var privateKey: SecKey?
        let publicKeyAttr: [NSObject: NSObject] = [
            kSecAttrIsPermanent:true as NSObject,
            kSecAttrApplicationTag:"com.xeoscript.app.RsaFromScrach.public".data(using: String.Encoding.utf8)! as NSObject,
            kSecClass: kSecClassKey, // added this value
            kSecReturnData: kCFBooleanTrue] // added this value
        let privateKeyAttr: [NSObject: NSObject] = [
            kSecAttrIsPermanent:true as NSObject,
            kSecAttrApplicationTag:"com.xeoscript.app.RsaFromScrach.private".data(using: String.Encoding.utf8)! as NSObject,
            kSecClass: kSecClassKey, // added this value
            kSecReturnData: kCFBooleanTrue] // added this value
        
        var keyPairAttr = [NSObject: NSObject]()
        keyPairAttr[kSecAttrKeyType] = kSecAttrKeyTypeRSA
        keyPairAttr[kSecAttrKeySizeInBits] = 4096 as NSObject
        keyPairAttr[kSecPublicKeyAttrs] = publicKeyAttr as NSObject
        keyPairAttr[kSecPrivateKeyAttrs] = privateKeyAttr as NSObject
        
        statusCode = SecKeyGeneratePair(keyPairAttr as CFDictionary, &publicKey, &privateKey)
        var finalPubKeyStr: String!
        var finalPrivateKeyStr: String!
        
        if statusCode == noErr && publicKey != nil && privateKey != nil {
            print("Key pair generated OK")
            var resultPublicKey: AnyObject?
            var resultPrivateKey: AnyObject?
            let statusPublicKey = SecItemCopyMatching(publicKeyAttr as CFDictionary, &resultPublicKey)
            let statusPrivateKey = SecItemCopyMatching(privateKeyAttr as CFDictionary, &resultPrivateKey)
            
            if statusPublicKey == noErr {
                if let publicKey = resultPublicKey as? Data {
                    finalPubKeyStr = "-----BEGIN RSA PUBLIC KEY-----\n"
                    finalPubKeyStr = finalPubKeyStr + publicKey.base64EncodedString()
                    
                    // print("Public Key: \((publicKey.base64EncodedString()))")
                    // let publicKeyStr = publicKey.base64EncodedString()
                    finalPubKeyStr = finalPubKeyStr + "\n-----END RSA PUBLIC KEY-----"
                    print("Public Key: \((finalPubKeyStr))")
                    let cryptoImportExportManager = CryptoExportImportManager()
                    finalPubKeyStr = cryptoImportExportManager.exportRSAPublicKeyToPEM(publicKey, keyType: kSecAttrKeyTypeRSA as String, keySize: 4096)
                    print(finalPubKeyStr)
                }
            }
            
            if statusPrivateKey == noErr {
                if let privateKey = resultPrivateKey as? Data {
                    // print("Private Key: \((privateKey.base64EncodedString()))")
                    finalPrivateKeyStr = "-----BEGIN RSA PRIVATE KEY-----\n"
                    finalPrivateKeyStr = finalPrivateKeyStr + privateKey.base64EncodedString()
                    finalPrivateKeyStr = finalPrivateKeyStr + "\n-----END RSA PRIVATE KEY-----"
                    print("Private Key: \((finalPrivateKeyStr))")
                }
            }
        } else {
            print("Error generating key pair: \(String(describing: statusCode))")
        }
        return (finalPubKeyStr, finalPrivateKeyStr)
    }
    
    func createUser(ks: GethKeyStore, password: String) -> GethAccount {
        let newAccount = try! ks.newAccount(password)
        return newAccount
    }
    
    // function generateKeyPair()
    func signTransaction(ks: GethKeyStore, account:GethAccount, password: String, data: Data) -> String {
        var error: NSError?
        let to    = GethNewAddressFromHex("0x0000000000000000000000000000000000000000", &error)
        // GethTransaction* GethNewTransaction(int64_t nonce, GethAddress* to, GethBigInt* amount, int64_t gasLimit, GethBigInt* gasPrice, NSData* data);
        var gasLimit: Int64
        gasLimit = 0
        // let data = "abc".data(using: .utf8)
        let tx    = GethNewTransaction(1, to, GethNewBigInt(0), gasLimit, GethNewBigInt(0), data) // Random empty transaction
        let chain = GethNewBigInt(1) // Chain identifier of the main net
        
        // Sign a transaction with multiple manually cancelled authorizations
        try! ks.unlock(account, passphrase: password)
        let signed = try! ks.signTx(account, tx: tx, chainID: chain)
        let signedTrans = try! signed.encodeJSON()
        return signedTrans
    }

    func aesEncryptToBase64String(key:String, input:String) -> String? {
        let inputData = input.data(using: .utf8)!
        let keyData = key.data(using: .utf8)!
        return aesCBCEncrypt(data:inputData, keyData:keyData)!.base64EncodedString()
    }
    
    func aesDecryptFromBase64String(base64Input:String, key:String) -> String? {
        let inputData = Data(base64Encoded: base64Input)!
        let keyData = key.data(using: .utf8)!

        let decryptedData = aesCBCDecrypt(data:inputData, keyData:keyData)!
        return String(data: decryptedData, encoding: String.Encoding.utf8) as String!
    }

    func aesCBCEncrypt(data:Data, keyData:Data) -> Data? {
        let keyLength = keyData.count
        let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256]
        if (validKeyLengths.contains(keyLength) == false) {
            return nil
        }
        
        // changed according to http://www.riptutorial.com/swift/example/27054/aes-encryption-in-ecb-mode-with-pkcs7-padding
        // let ivSize = kCCBlockSizeAES128;
        let cryptLength = size_t(data.count + kCCBlockSizeAES128)
        var cryptData = Data(count:cryptLength)
        
        let status = cryptData.withUnsafeMutableBytes {ivBytes in
            SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, ivBytes)
        }
        if (status != 0) {
            return nil
        }
        
        var numBytesEncrypted :size_t = 0
        let options   = CCOptions(kCCOptionPKCS7Padding + kCCOptionECBMode)
        
        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            data.withUnsafeBytes {dataBytes in
                keyData.withUnsafeBytes {keyBytes in
                    CCCrypt(CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            options,
                            keyBytes, keyLength,
                            cryptBytes,
                            dataBytes, data.count,
                            cryptBytes, cryptLength,
                            &numBytesEncrypted)
                }
            }
        }
        
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.count = numBytesEncrypted
        }
        else {
            return nil
        }
        
        return cryptData;
    }
    
    // The iv is prefixed to the encrypted data
    func aesCBCDecrypt(data:Data, keyData:Data) -> Data? {
        let keyLength = keyData.count
        let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256]
        if (validKeyLengths.contains(keyLength) == false) {
            return nil
        }
        
        // let ivSize = kCCBlockSizeAES128;
        let clearLength = size_t(data.count)
        var clearData = Data(count:clearLength)
        
        var numBytesDecrypted :size_t = 0
        let options   = CCOptions(kCCOptionPKCS7Padding + kCCOptionECBMode)
        
        let cryptStatus = clearData.withUnsafeMutableBytes {cryptBytes in
            data.withUnsafeBytes {dataBytes in
                keyData.withUnsafeBytes {keyBytes in
                    CCCrypt(CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            options,
                            keyBytes, keyLength,
                            dataBytes,
                            dataBytes, clearLength,
                            cryptBytes, clearLength,
                            &numBytesDecrypted)
                }
            }
        }
        
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            clearData.count = numBytesDecrypted
        }
        else {
            return nil
        }
        
        return clearData;
    }
}

