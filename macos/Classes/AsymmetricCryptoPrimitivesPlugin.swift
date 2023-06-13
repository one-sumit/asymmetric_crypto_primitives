import Cocoa
import FlutterMacOS
import CryptoKit
import Sodium
import LocalAuthentication
import Foundation

public class AsymmetricCryptoPrimitivesPlugin: NSObject, FlutterPlugin {
    let sodium = Sodium()
    var EC_ALIAS = "9aac15df-4b0f-4f9d-a6b7-210aae2a1177"
    var context = LAContext()


  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "asymmetric_crypto_primitives", binaryMessenger: registrar.messenger)
    let instance = AsymmetricCryptoPrimitivesPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "checkIfDeviceSecure":
        result(LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil))
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
        let prompt = (args!["prompt"] as? String)!
        let subPrompt = (args!["subPrompt"] as? String)!
        let dataToSign = (args!["message"] as? String)!
        signEd25519(data: dataToSign, uuid: uuid, prompt: prompt, subPrompt: subPrompt, result: result)
        break
    case "signEd25519NoAuth":
        let args = call.arguments as? Dictionary<String, Any>
        let uuid = (args!["uuid"] as? String)!
        let dataToSign = (args!["message"] as? String)!
        signEd25519NoAuth(data: dataToSign, uuid: uuid, result: result)
        break
    case "rotateForEd25519":
        let args = call.arguments as? Dictionary<String, Any>
        let uuid = (args!["uuid"] as? String)!
        let pubKey = try? retrieveKeychain(username: "\(uuid)_1_pub")
        let privKey = try? retrieveKeychain(username: "\(uuid)_1_priv")
        try? updateKeychain(username: "\(uuid)_0_pub", password: pubKey as! String)
        try? updateKeychain(username: "\(uuid)_0_priv", password: privKey as! String)
        try? deleteKeychain(username: "\(uuid)_1_pub")
        try? deleteKeychain(username: "\(uuid)_1_priv")
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
        if key.contains("0_pub") || key.contains("1_pub") || key.contains("0_priv") || key.contains("1_priv"){
            data = try? retrieveKeychain(username: key)
        }else{
            data =  UserDefaults.standard.string(forKey: key)
        }
        if data == nil{
            result(false)
        }else{
            result(data as? String)
        }
          result(data)
          break
    case "writeData":
        let args = call.arguments as? Dictionary<String, Any>
        let key = (args!["key"] as? String)!
        let data =  (args!["data"] as? String)!
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
        UserDefaults.standard.set(data, forKey: key)
        result(true)
        break
    default:
      result("Not Implemented")
    }
  }
    
    
    ///-------------------------------------------------------ED25519 KEYS------------------------------------------------------------------
    public func createEd25519Key(uuid: String){
        let keyPair = sodium.sign.keyPair()
        let pub = (keyPair?.publicKey)!
        let priv = (keyPair?.secretKey)!
        let encryptedPub = sodium.utils.bin2base64(pub)!
        let encryptedPriv = sodium.utils.bin2base64(priv)!
        try! storeKeychain(username: "\(uuid)_0_pub", password: encryptedPub)
        try! storeKeychain(username: "\(uuid)_0_priv", password: encryptedPriv)
    }
    
    public func createNextEd25519Key(uuid: String){
        let keyPair = sodium.sign.keyPair()
        let pub = (keyPair?.publicKey)!
        let priv = (keyPair?.secretKey)!
        let encryptedPub = sodium.utils.bin2base64(pub)!
        let encryptedPriv = sodium.utils.bin2base64(priv)!
        try! storeKeychain(username: "\(uuid)_1_pub", password: encryptedPub)
        try! storeKeychain(username: "\(uuid)_1_priv", password: encryptedPriv)
    }
    
    public func signEd25519(data: String, uuid: String, prompt: String, subPrompt: String, result: @escaping FlutterResult) -> Void{
        let secretKey = try? retrieveKeychain(username: "\(uuid)_0_priv")
        if(secretKey == nil){
            result(false)
        }
        let localAuthContext = LAContext()
        var error: NSError?
        DispatchQueue.main.async { [self] in
            if localAuthContext.canEvaluatePolicy(LAPolicy.deviceOwnerAuthentication, error: &error) {
                localAuthContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: prompt) { [weak self] (success, error) in
                    if success {
                        let signature = self!.sodium.sign.signature(message: data.bytes, secretKey: self!.sodium.utils.base642bin(secretKey as! String)!)
                        if(signature != nil){
                            result(self!.sodium.utils.bin2hex(signature!)!)
                        }else{
                            result(false)
                        }
                    } else {
                        result(false)
                    }
                }
            } else {
                result(false)
            }
        }
    }

    public func signEd25519NoAuth(data: String, uuid: String, result: @escaping FlutterResult) -> Void{
        let secretKey = try? retrieveKeychain(username: "\(uuid)_0_priv")
        if(secretKey == nil){
            result(false)
        }
        let signature = self!.sodium.sign.signature(message: data.bytes, secretKey: self!.sodium.utils.base642bin(secretKey as! String)!)
        if(signature != nil){
            result(self!.sodium.utils.bin2hex(signature!)!)
        }else{
            result(false)
        }
                
    }
    
    
    ///------------------------------------------------------------Side functions------------------------------------------------------------
    public func readData(key: String) -> Any{
        let data =  UserDefaults.standard.string(forKey: key)
        if data == nil{
            return false
        }else{
            return data
        }
    }
    
    public func writeData(data: String, key: String){
        UserDefaults.standard.set(data, forKey: key)
    }
    
    public func cleanUp(uuid: String){
        if(checkDataExists(key: "\(uuid)_0_pub") != false){
            try? deleteKeychain(username: "\(uuid)_0_pub")
            try? deleteKeychain(username: "\(uuid)_0_priv")
            try? deleteKeychain(username: "\(uuid)_1_pub")
            try? deleteKeychain(username: "\(uuid)_1_priv")
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
       let data = try? retrieveKeychain(username: key)
       if data == nil{
           return false
       }else{
           return true
       }
   }
    
    ///----------------------------------------Storing items in keychain and retrieving them--------------------------------------------
    public func storeKeychain(username: String, password: String) throws -> Any? {
        let data = password.data(using: .utf8)!

    // store password as data and if you want to store username
        let query: [String: Any] = [kSecClass as String:  kSecClassGenericPassword,
                                    kSecAttrAccount as String: username,
                                    kSecValueData as String: data]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
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
            guard let data = item as? Data else { return nil}
            let keyToReturn = String(decoding:data, as:UTF8.self)
            return try! keyToReturn
        case errSecItemNotFound: return nil
        default: print("Error in reading the key")
        }
        return nil
    }
    
    public func updateKeychain(username: String, password: String) throws -> Any?{
        let data = password.data(using: .utf8)!

        let query: [String: Any] = [kSecClass as String:  kSecClassGenericPassword,
                                    kSecAttrAccount as String: username]
        let attributes: [String: Any] = [kSecClass as String:  kSecClassGenericPassword,
                                         kSecAttrAccount as String: username,
                                         kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        guard status != errSecItemNotFound else { return nil}
        guard status == errSecSuccess else { return nil }
        return status
    }
    
    public func deleteKeychain(username: String) throws -> Any?{
        let query: [String: Any] = [kSecClass as String:  kSecClassGenericPassword,
                                    kSecAttrAccount as String: username]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { return nil }
        return status
    }

}
