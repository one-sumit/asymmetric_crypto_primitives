#include "include/sodium_key_generator_plugin/sodium_key_generator_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "sodium_key_generator_plugin.h"

void SodiumKeyGeneratorPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  sodium_key_generator_plugin::SodiumKeyGeneratorPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
