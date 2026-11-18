#ifndef FLUTTER_PLUGIN_BIOMETRIC_STORAGE_WINDOWS_HELLO_H_
#define FLUTTER_PLUGIN_BIOMETRIC_STORAGE_WINDOWS_HELLO_H_

// This must be included before many other Windows headers.
#include <windows.h>

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>
#include <optional>

namespace biometric_storage {

// The channel `biometric_storage/windows_hello`: data sealed under a key that
// exists only after Windows Hello has signed (see windows_hello.cpp).
class WindowsHelloPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  explicit WindowsHelloPlugin(flutter::PluginRegistrarWindows *registrar);

  virtual ~WindowsHelloPlugin();

  WindowsHelloPlugin(const WindowsHelloPlugin &) = delete;
  WindowsHelloPlugin &operator=(const WindowsHelloPlugin &) = delete;

 private:
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

  // Delivers a worker's answer on the platform thread (the message a worker
  // posts to the app's top-level window).
  std::optional<LRESULT> HandleWindowProc(HWND hwnd, UINT message,
                                          WPARAM wparam, LPARAM lparam);

  HWND TopLevelWindow() const;

  flutter::PluginRegistrarWindows *registrar_;
  int window_proc_id_ = -1;
};

}  // namespace biometric_storage

#endif  // FLUTTER_PLUGIN_BIOMETRIC_STORAGE_WINDOWS_HELLO_H_
