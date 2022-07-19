import Flutter
import UIKit
import LocalAuthentication
import CryptoKit
import Sodium
import Foundation


@available(iOS 12.0, *)
public class SwiftAsymmetricCryptoPrimitivesPlugin: NSObject, FlutterPlugin {
  var IOS_AES_ALIAS = "9aac15df-4b0f-4f9d-a6b7-210aae2a1179"
  let sodium = Sodium()
    var context = LAContext()
    
    static public func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "asymmetric_crypto_primitives", binaryMessenger: registrar.messenger())
    let instance = SwiftAsymmetricCryptoPrimitivesPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
        if !instance.checkAESKeyExists(){
        makeAndStoreAESKey(name: instance.IOS_AES_ALIAS)
    }
  }

    @available(iOS 12.0.0, *)
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult){
      switch call.method {
      case "checkIfDeviceSecure":
          result(LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil))
          break
      case "readData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          var data =  UserDefaults.standard.string(forKey: key)
          print(data)
          if data == nil{
              result(false)
          }else{
              let tempdata = decryptData(dataToDecrypt: data!)
              data = tempdata
          }
          result(data)
          break
      case "writeData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          let data =  (args!["data"] as? String)!
          let encryptedData = encryptData(dataToEncrypt: data)
          UserDefaults.standard.set(encryptedData, forKey: key)
          result(true)
          break
      case "deleteData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          UserDefaults.standard.removeObject(forKey: key)
          result(true)
          break
      case "editData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          let data =  (args!["data"] as? String)!
          UserDefaults.standard.set(data, forKey: key)
          result(true)
          break
      case "establishForRSA":
          let args = call.arguments as? Dictionary<String, Any>
          let uuid = (args!["uuid"] as? String)!
          print(uuid)
          createRSAKey(name: "\(uuid)_0_rsa")
          createRSAKey(name: "\(uuid)_1_rsa")
          result(true)
          break
      case "signRSA":
          let args = call.arguments as? Dictionary<String, Any>
          let uuid = (args!["uuid"] as? String)!
          let dataToSign = (args!["message"] as? String)!
          let signature = signRSA(data: dataToSign, uuid: uuid)
          print("The signature is \(signature)")
          result(signature)
      case "checkUuid":
          let args = call.arguments as? Dictionary<String, Any>
          let uuid = (args!["uuid"] as? String)!
          result(checkUuid(uuid:uuid))
      case "establishForEd25519":
          let args = call.arguments as? Dictionary<String, Any>
          let uuid = (args!["uuid"] as? String)!
          createEd25519Key(uuid: uuid)
          createNextEd25519Key(uuid: uuid)
          result(true)
      case "signEd25519":
          let args = call.arguments as? Dictionary<String, Any>
          let uuid = (args!["uuid"] as? String)!
          let dataToSign = (args!["message"] as? String)!
          if #available(iOS 13.0.0, *) {
              signEd25519(data: dataToSign, uuid: uuid, result: result)
          } else {
              result(false)
          }
      case "rotateForEd25519":
          let args = call.arguments as? Dictionary<String, Any>
          let uuid = (args!["uuid"] as? String)!
          let pubKey = readData(key: "\(uuid)_1_pub")
          let privKey = readData(key: "\(uuid)_1_priv")
          writeData(data: pubKey as! String, key: "\(uuid)_0_pub")
          writeData(data: privKey as! String, key: "\(uuid)_0_priv")
          createNextEd25519Key(uuid: uuid)
          result(true)
      case "cleanUp":
          let args = call.arguments as? Dictionary<String, Any>
          let uuid = (args!["uuid"] as? String)!
          cleanUp(uuid: uuid)
          result(true)
      default:
          result("Not implemented!")
          break
      }
  }
    
    
    ///EC KEYS
    public static func makeAndStoreAESKey(name: String, requiresBiometry: Bool = false) -> SecKey {
        let flags: SecAccessControlCreateFlags
        if #available(iOS 11.3, *) {
            flags = requiresBiometry ?
                [.privateKeyUsage, .biometryCurrentSet] : .privateKeyUsage
        } else {
            flags = requiresBiometry ?
                [.privateKeyUsage, .touchIDCurrentSet] : .privateKeyUsage
        }
        let access =
            SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                            flags,
                                            nil)!
        let tag = name.data(using: .utf8)!
        let attributes: [String: Any] = [
            kSecAttrKeyType as String           : kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String     : 256,
            kSecAttrTokenID as String           : kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String : [
                kSecAttrIsPermanent as String       : true,
                kSecAttrApplicationTag as String    : tag,
                kSecAttrAccessControl as String     : access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)! //else {
            //throw error!.takeRetainedValue() as Error
        //}
        
        return privateKey
    }
    
    public func loadAESKey(name: String) -> SecKey? {
        let tag = name.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag,
            kSecAttrKeyType as String           : kSecAttrKeyTypeEC,
            kSecReturnRef as String             : true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }
        return (item as! SecKey)
    }
    
    public func encryptData(dataToEncrypt: String) -> String{
        let key = loadAESKey(name: IOS_AES_ALIAS)
        let publicKey = SecKeyCopyPublicKey(key!)
        print(publicKey)
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(publicKey!, .encrypt, algorithm) else {
            print("The guard clause got here")
            return ""
        }
        var error: Unmanaged<CFError>?
        let clearTextData = dataToEncrypt.data(using: .utf8)!
        let cipherTextData = SecKeyCreateEncryptedData(publicKey!, algorithm,
                                                   clearTextData as CFData,
                                                   &error) as Data?
        guard cipherTextData != nil else {
            print("cipherTextData is nil")
            //showSimpleAlert()
            return ""
        }
        return cipherTextData!.base64EncodedString()
    }
    
    public func decryptData(dataToDecrypt: String) -> String{
        let privateKey = loadAESKey(name: IOS_AES_ALIAS)
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(privateKey!, .decrypt, algorithm) else {
            print("Algorithm not supported")
            return ""
        }

        var error: Unmanaged<CFError>?
        let clearTextData = SecKeyCreateDecryptedData(privateKey!,
                                                      algorithm,
                                                      Data.init(base64Encoded: dataToDecrypt)! as CFData,
                                                      &error) as Data?
        print(clearTextData!)
        //DispatchQueue.main.async {
        guard clearTextData != nil else {
            print("clearTextData is nil")
            return ""
        }
        let clearText = String(decoding: clearTextData!, as: UTF8.self)
            // clearText is our decrypted string
        //}
        
        return String(decoding: clearTextData!, as: UTF8.self)
    }
    
    public func checkAESKeyExists() -> Bool{
        if(loadAESKey(name: IOS_AES_ALIAS) == nil){
            return false;
        }else{
            return true;
        }
    }
    
    ///ED25519 KEYS
    public func createEd25519Key(uuid: String){
        let keyPair = sodium.sign.keyPair()
        let pub = (keyPair?.publicKey)!
        let priv = (keyPair?.secretKey)!
        print("pub: \(sodium.utils.bin2base64(pub))")
        print("priv: \(sodium.utils.bin2base64(priv))")
        let encryptedPub = encryptData(dataToEncrypt: sodium.utils.bin2base64(pub)!)
        let encryptedPriv = encryptData(dataToEncrypt: sodium.utils.bin2base64(priv)!)
        UserDefaults.standard.set(encryptedPub, forKey: "\(uuid)_0_pub")
        UserDefaults.standard.set(encryptedPriv, forKey: "\(uuid)_0_priv")
    }
    
    public func createNextEd25519Key(uuid: String){
        let keyPair = sodium.sign.keyPair()
        let pub = (keyPair?.publicKey)!
        let priv = (keyPair?.secretKey)!
        print("pub: \(sodium.utils.bin2base64(pub))")
        print("priv: \(sodium.utils.bin2base64(priv))")
        let encryptedPub = encryptData(dataToEncrypt: sodium.utils.bin2base64(pub)!)
        let encryptedPriv = encryptData(dataToEncrypt: sodium.utils.bin2base64(priv)!)
        UserDefaults.standard.set(encryptedPub, forKey: "\(uuid)_1_pub")
        UserDefaults.standard.set(encryptedPriv, forKey: "\(uuid)_1_priv")
    }
    
    @available(iOS 13.0.0, *)
    public func signEd25519(data: String, uuid: String, result: @escaping FlutterResult) -> Void{
        let secretKey = readData(key: "\(uuid)_0_priv")
        //var signature = "".bytes
        var error: NSError?
        DispatchQueue.main.async { [self] in
            if self.context.canEvaluatePolicy(LAPolicy.deviceOwnerAuthentication, error: &error) {
                context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Log in to your account") { [weak self] (success, error) in
                    if success {
                        let signature = sodium.sign.signature(message: data.bytes, secretKey: sodium.utils.base642bin(secretKey as! String)!)!
                        result(sodium.utils.bin2hex(signature)!)
                    } else {
                        result(false)
                    }
                }
              } else {
                  result(false)
              }
        }
        //var error: NSError?
//        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
//            print(error?.localizedDescription ?? "Can't evaluate policy")
//            result(sodium.utils.bin2base64(signature)!)
//            return
//        }
//        do {
//            try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Log in to your account")
//            signature = sodium.sign.signature(message: data.bytes, secretKey: sodium.utils.base642bin(secretKey as! String)!)!
//        } catch let error {
//            print(error.localizedDescription)
//
//            // Fall back to a asking for username and password.
//            // ...
//        }
        //result(sodium.utils.bin2base64(signature)!)
    }
    
    
    
    ///RSA KEYS
    public func createRSAKey(name: String, requiresBiometry: Bool = true){
        let flags: SecAccessControlCreateFlags
        flags = requiresBiometry ?
            [.privateKeyUsage, .biometryCurrentSet] : .privateKeyUsage
    
        let access = SecAccessControlCreateWithFlags(nil, // Use the default allocator.
                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     .userPresence,
                                                     nil) // Igno
        let tag = name.data(using: .utf8)!
        let attributes: [String: Any] = [
            kSecAttrKeyType as String           : kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String     : 2048,
            kSecAttrAccessControl as String: access as Any,
            kSecPrivateKeyAttrs as String : [
                kSecAttrIsPermanent as String       : true,
                kSecAttrApplicationTag as String    : tag,
            ]
        ]
        
        var error: Unmanaged<CFError>?
        let statuscode = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        //print(SecKeyCopyExternalRepresentation(statuscode!, &error))
        //else {
            //throw error!.takeRetainedValue() as Error
        //}
    
    }
    
    public func loadRSAKey(name: String) -> SecKey? {
        let tag = name.data(using: .utf8)!
        //print(tag.base64EncodedString())
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag,
            kSecAttrKeyType as String           : kSecAttrKeyTypeRSA,
            kSecReturnRef as String             : true
        ]
        
        var item: CFTypeRef?
        //print("The item is \(item)")
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        //print("the status is \(status)")
        guard status == errSecSuccess else {
            return nil
        }
        return (item as! SecKey)
    }
    
    public func signRSA(data: String, uuid: String) -> String {
        let privateKey = loadRSAKey(name: "\(uuid)_0_rsa")
        print(privateKey)
        let algorithm: SecKeyAlgorithm = .rsaSignatureRaw
        guard SecKeyIsAlgorithmSupported(privateKey!, .sign, algorithm) else {
            print("Algorithm not supported")
            return ""
        }
        var signature = Data.init()
        // SecKeyCreateSignature call is blocking when the used key
        // is protected by biometry authentication. If that's not the case,
        // dispatching to a background thread isn't necessary.
        let dataToSign = data.data(using: .utf8)!
        DispatchQueue.global().async {
            var error: Unmanaged<CFError>?
            signature = (SecKeyCreateSignature(privateKey!,                                                  algorithm,
                                               dataToSign as CFData,
                                               &error) as Data?)!
            print(signature)
//            DispatchQueue.main.async {
//                self.signature = signature
//                guard signature != nil else {
//                    UIAlertController.showSimple(title: "Can't sign",
//                                                 text: (error!.takeRetainedValue() as Error).localizedDescription,
//                                                 from: self)
//                    return
//                }
//                // signature is a Data instance containing the digital signature value
//                // ...
//            }
        }
        return signature.base64EncodedString()
    }
    
    public func checkUuid(uuid: String) -> Bool{
        //print(loadRSAKey(name: "\(uuid)_0_rsa"))
        if (loadRSAKey(name: "\(uuid)_0_rsa") != nil) || (checkDataExists(key: "\(uuid)_0_pub") != false){
            return true
        }else{
            return false
        }
    }
    
    public func checkDataExists(key: String) -> Bool{
        let data =  UserDefaults.standard.string(forKey: key)
        if data == nil{
            return false
        }else{
            return true
        }
    }
    
    public func cleanUp(uuid: String){
        for (key, _) in UserDefaults.standard.dictionaryRepresentation() {
            if key.contains(uuid){
                UserDefaults.standard.removeObject(forKey: key)
            }
        }
    }
    
    public func readData(key: String) -> Any{
        let data =  UserDefaults.standard.string(forKey: key)
        if data == nil{
            return false
        }else{
            let tempdata = decryptData(dataToDecrypt: data!)
            return tempdata
        }
    }
    
    public func writeData(data: String, key: String){
        let encryptedData = encryptData(dataToEncrypt: data)
        UserDefaults.standard.set(encryptedData, forKey: key)
    }
}

extension String {

    func fromBase64() -> String? {
        guard let data = Data(base64Encoded: self) else {
            return nil
        }

        return String(data: data, encoding: .utf8)
    }

    func toBase64() -> String {
        return Data(self.utf8).base64EncodedString()
    }

}
