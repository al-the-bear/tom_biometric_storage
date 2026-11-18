#include "include/tom_biometric_storage/biometric_storage_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "windows_hello.h"

void BiometricStoragePluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  biometric_storage::WindowsHelloPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
