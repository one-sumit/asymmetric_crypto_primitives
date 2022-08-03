#ifndef FLUTTER_PLUGIN_ASYMMETRIC_CRYPTO_PRIMITIVES_PLUGIN_H_
#define FLUTTER_PLUGIN_ASYMMETRIC_CRYPTO_PRIMITIVES_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace asymmetric_crypto_primitives {

class AsymmetricCryptoPrimitivesPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  AsymmetricCryptoPrimitivesPlugin();

  virtual ~AsymmetricCryptoPrimitivesPlugin();

  // Disallow copy and assign.
  AsymmetricCryptoPrimitivesPlugin(const AsymmetricCryptoPrimitivesPlugin&) = delete;
  AsymmetricCryptoPrimitivesPlugin& operator=(const AsymmetricCryptoPrimitivesPlugin&) = delete;

 private:
  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace asymmetric_crypto_primitives

#endif  // FLUTTER_PLUGIN_ASYMMETRIC_CRYPTO_PRIMITIVES_PLUGIN_H_
