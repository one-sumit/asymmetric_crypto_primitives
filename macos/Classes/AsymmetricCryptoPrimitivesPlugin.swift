import Cocoa
import FlutterMacOS
import CryptoKit
import Sodium
import LocalAuthentication
import Foundation


@available(macOS 10.15, *)
public class AsymmetricCryptoPrimitivesPlugin: NSObject, FlutterPlugin {
    let sodium = Sodium()
    var EC_ALIAS = "9aac15df-4b0f-4f9d-a6b7-210aae2a1177"
    var context = LAContext()
    var keychain = GenericPasswordStore()


  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "asymmetric_crypto_primitives", binaryMessenger: registrar.messenger)
    let instance = AsymmetricCryptoPrimitivesPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "getPlatformVersion":
      result("macOS " + ProcessInfo.processInfo.operatingSystemVersionString)
    case "checkIfDeviceSecure":
        result(true)
        break
    case "checkUuid":
          let args = call.arguments as? Dictionary<String, Any>
          let uuid = (args!["uuid"] as? String)!
          result(checkUuid(uuid:uuid))
        break
      case "establishForEd25519":
          let args = call.arguments as? Dictionary<String, Any>
          let uuid = (args!["uuid"] as? String)!
          createEd25519Key(uuid: uuid)
          createNextEd25519Key(uuid: uuid)
          result(true)
        break
      case "signEd25519":
          let args = call.arguments as? Dictionary<String, Any>
          let uuid = (args!["uuid"] as? String)!
          let dataToSign = (args!["message"] as? String)!
          if #available(iOS 13.0.0, *) {
              signEd25519(data: dataToSign, uuid: uuid, result: result)
          } else {
              result(false)
          }
        break
      case "rotateForEd25519":
          let args = call.arguments as? Dictionary<String, Any>
          let uuid = (args!["uuid"] as? String)!
          let pubKey = readData(key: "\(uuid)_1_pub")
          let privKey = readData(key: "\(uuid)_1_priv")
          writeData(data: pubKey as! String, key: "\(uuid)_0_pub")
          writeData(data: privKey as! String, key: "\(uuid)_0_priv")
          createNextEd25519Key(uuid: uuid)
          result(true)
        break
      case "cleanUp":
          let args = call.arguments as? Dictionary<String, Any>
          let uuid = (args!["uuid"] as? String)!
          cleanUp(uuid: uuid)
          result(true)
        break
    case "readData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
            var data : Any? = nil
            if key.contains("0_pub") || key.contains("1_pub"){
                data = try? retrieveKeychain(username: key)
                //print("Data is \(String(decoding:data, as: UTF8.self))")
                print("Data datatype is \(type(of:data))")
            }
          //var data =  UserDefaults.standard.string(forKey: key)
          if data == nil{
              result(false)
          }else{
              result(data as? String)
              //let tempdata = decryptData(dataToDecrypt: data!)
              //if tempdata.isEmpty{
              //    result(false)
              //}else{
              //    data = tempdata
              //}
          }
          result(data)
          break
      case "writeData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          let data =  (args!["data"] as? String)!
          //let encryptedData = encryptData(dataToEncrypt: data)
          if data.isEmpty{
              result(false)
          }else{
              UserDefaults.standard.set(data, forKey: key)
              result(true)
          }
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
          ///let encryptedData = encryptData(dataToEncrypt: data)
          //if encryptedData.isEmpty{
          //    result(false)
          //}else{
          //    UserDefaults.standard.set(encryptedData, forKey: key)
          //    result(true)
          //}
          UserDefaults.standard.set(data, forKey: key)
          result(true)
          break
    default:
      result("Not Implemented")
    }
  }
    
    
    ///EC KEYS
    public static func makeAndStoreECKey(name: String, requiresBiometry: Bool = false) -> SecKey {
        let tag = name.data(using: .utf8)!
        let attributes: [String: Any] = [
            kSecAttrKeyType as String           : kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String     : 256,
            kSecPrivateKeyAttrs as String : [
                kSecAttrIsPermanent as String       : true,
                kSecAttrApplicationTag as String    : tag,
            ]
        ]
        
        var error: Unmanaged<CFError>?
        let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)! //else {
            //throw error!.takeRetainedValue() as Error
        //}
        //SecKey publicKey = SecKeyCopyPublicKey(privateKey);
        print("Private key is: \(privateKey)")
        return privateKey
    }
    
    public func loadECKey(name: String) -> SecKey? {
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
            print("error")
            return nil
        }
        print("Key after loading: \(SecKeyCopyPublicKey(item as! SecKey))")
        return (item as! SecKey)
    }
    
    public func encryptData(dataToEncrypt: String) -> String{
        let key = try! retrieveSymmetricKey(withKeychainTag: EC_ALIAS)
        print("The key is: \(key)")
        let publicKey = SecKeyCopyPublicKey(key! as! SecKey)
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(publicKey!, .encrypt, algorithm) else {
            return ""
        }
        var error: Unmanaged<CFError>?
        let clearTextData = dataToEncrypt.data(using: .utf8)!
        let cipherTextData = SecKeyCreateEncryptedData(publicKey!, algorithm,
                                                   clearTextData as CFData,
                                                   &error) as Data?
        guard cipherTextData != nil else {
            return ""
        }
        return cipherTextData!.base64EncodedString()
    }
    
    public func decryptData(dataToDecrypt: String) -> String{
        let privateKey = loadECKey(name: EC_ALIAS)
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(privateKey!, .decrypt, algorithm) else {
            return ""
        }

        var error: Unmanaged<CFError>?
        let clearTextData = SecKeyCreateDecryptedData(privateKey!,
                                                      algorithm,
                                                      Data.init(base64Encoded: dataToDecrypt)! as CFData,
                                                      &error) as Data?
        guard clearTextData != nil else {
            return ""
        }
        let clearText = String(decoding: clearTextData!, as: UTF8.self)
            // clearText is our decrypted string
        return String(decoding: clearTextData!, as: UTF8.self)
    }
    
    public func checkECKeyExists() -> Bool{
        if(loadECKey(name: EC_ALIAS) == nil){
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
        //let encryptedPub = encryptData(dataToEncrypt: sodium.utils.bin2base64(pub)!)
        //let encryptedPriv = encryptData(dataToEncrypt: sodium.utils.bin2base64(priv)!)
        let encryptedPub = sodium.utils.bin2base64(pub)!
        let encryptedPriv = sodium.utils.bin2base64(priv)!
        UserDefaults.standard.set(encryptedPub, forKey: "\(uuid)_0_pub")
        UserDefaults.standard.set(encryptedPriv, forKey: "\(uuid)_0_priv")
        try! storeKeychain(username: "\(uuid)_0_pub", password: encryptedPub)
        try! storeKeychain(username: "\(uuid)_0_priv", password: encryptedPriv)
        //keychain.storeKey(encryptedPub.data(using: .utf8)!, account: "\(uuid)_0_pub")
        //storeKey(encryptedPub as! GenericPasswordConvertible, account: "\(uuid)_0_pub")
    }
    
    public func createNextEd25519Key(uuid: String){
        let keyPair = sodium.sign.keyPair()
        let pub = (keyPair?.publicKey)!
        let priv = (keyPair?.secretKey)!
        //let encryptedPub = encryptData(dataToEncrypt: sodium.utils.bin2base64(pub)!)
        //let encryptedPriv = encryptData(dataToEncrypt: sodium.utils.bin2base64(priv)!)
        let encryptedPub = sodium.utils.bin2base64(pub)!
        let encryptedPriv = sodium.utils.bin2base64(priv)!
        UserDefaults.standard.set(encryptedPub, forKey: "\(uuid)_1_pub")
        UserDefaults.standard.set(encryptedPriv, forKey: "\(uuid)_1_priv")
        try! storeKeychain(username: "\(uuid)_1_pub", password: encryptedPub)
        try! storeKeychain(username: "\(uuid)_1_priv", password: encryptedPriv)
    }
    
    @available(iOS 13.0.0, *)
    public func signEd25519(data: String, uuid: String, result: @escaping FlutterResult) -> Void{
        let secretKey = readData(key: "\(uuid)_0_priv")
        var error: NSError?
        DispatchQueue.main.async { [self] in
            if self.context.canEvaluatePolicy(LAPolicy.deviceOwnerAuthentication, error: &error) {
                context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Please authenticate to prove your identity") { [weak self] (success, error) in
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
    }
    
    public func readData(key: String) -> Any{
        let data =  UserDefaults.standard.string(forKey: key)
        if data == nil{
            return false
        }else{
            //let tempdata = decryptData(dataToDecrypt: data!)
            return data
        }
    }
    
    public func writeData(data: String, key: String){
        //let encryptedData = encryptData(dataToEncrypt: data)
        UserDefaults.standard.set(data, forKey: key)
    }
    
    public func cleanUp(uuid: String){
        for (key, _) in UserDefaults.standard.dictionaryRepresentation() {
            if key.contains(uuid){
                UserDefaults.standard.removeObject(forKey: key)
            }
        }
    }
    
    public func checkUuid(uuid: String) -> Bool{
       if (checkDataExists(key: "\(uuid)_0_pub") != false){
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
    
    public func storeKeychain(username: String, password: String) throws -> Any? {
        let data = password.data(using: .utf8)!

    // store password as data and if you want to store username
        let query: [String: Any] = [kSecClass as String:  kSecClassGenericPassword,
                                    kSecAttrAccount as String: username,
                                    kSecValueData as String: data]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            print("Not working again")
            return ""
        }
        return status
    }
    
    public func retrieveKeychain(username: String) throws -> Any? {
        let query: [String : Any] = [kSecClass as String: kSecClassGenericPassword,
                                     kSecAttrAccount as String: username,
                                     kSecReturnData as String: true]
        var item: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            guard let data = item as? Data else {
                print("Fail to convert the key reference to Data."); return nil}
            let keyToReturn = String(decoding:data, as:UTF8.self)
            return try! keyToReturn
        case errSecItemNotFound: return nil
        default: print("Error in reading the key")
        }
        return nil
    }

}
