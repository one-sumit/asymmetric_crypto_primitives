//
//  Generated file. Do not edit.
//

// clang-format off

#include "generated_plugin_registrant.h"

#include <asymmetric_crypto_primitives/asymmetric_crypto_primitives_plugin_c_api.h>
#include <local_auth_windows/local_auth_plugin.h>

void RegisterPlugins(flutter::PluginRegistry* registry) {
  AsymmetricCryptoPrimitivesPluginCApiRegisterWithRegistrar(
      registry->GetRegistrarForPlugin("AsymmetricCryptoPrimitivesPluginCApi"));
  LocalAuthPluginRegisterWithRegistrar(
      registry->GetRegistrarForPlugin("LocalAuthPlugin"));
}
