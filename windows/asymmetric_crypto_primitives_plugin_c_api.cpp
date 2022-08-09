#include "include/asymmetric_crypto_primitives/asymmetric_crypto_primitives_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "asymmetric_crypto_primitives_plugin.h"


#include "sodium/crypto_sign.h"
#include "sodium.h"

void AsymmetricCryptoPrimitivesPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  asymmetric_crypto_primitives::AsymmetricCryptoPrimitivesPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
