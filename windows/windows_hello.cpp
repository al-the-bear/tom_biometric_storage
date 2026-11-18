// Windows Hello for biometric_storage: data sealed under a key that exists
// only after Windows Hello has signed.
//
// The scheme is KeePassWinHello's. Each store name gets a Hello key credential
// of its own (`KeyCredentialManager`, an RSA key in the TPM or the software
// key storage provider, usable only after the user passes Hello). Signing a
// fixed challenge with it gives the same signature every time (PKCS#1 v1.5),
// and the SHA-256 of that signature is the AES-256-GCM key the data is sealed
// with. Without Hello there is no signature and so no key: the binding is
// cryptographic, unlike `UserConsentVerifier`, which only answers yes or no.
//
// Sealed form: a version byte (1), the 12-byte nonce, the ciphertext, the
// 16-byte tag. The Dart side keeps it in the Credential Manager.
//
// Every WinRT call is waited on a worker thread (blocking on the platform
// thread, an STA, is not allowed), and the answer is posted back to the app's
// top-level window, whose window procedure delivers it on the platform thread.

#include "windows_hello.h"

#include <bcrypt.h>
#include <flutter/standard_method_codec.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Security.Cryptography.h>
#include <winrt/Windows.Storage.Streams.h>

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif

namespace biometric_storage {

namespace {

using winrt::Windows::Security::Credentials::KeyCredential;
using winrt::Windows::Security::Credentials::KeyCredentialCreationOption;
using winrt::Windows::Security::Credentials::KeyCredentialManager;
using winrt::Windows::Security::Credentials::KeyCredentialStatus;
using winrt::Windows::Security::Cryptography::CryptographicBuffer;

using Bytes = std::vector<uint8_t>;
using Result = flutter::MethodResult<flutter::EncodableValue>;

// The message a worker posts with its answer (a heap std::function in lParam).
constexpr UINT kAnswerMessage = WM_APP + 0x0B5;

constexpr uint8_t kVersion = 1;
constexpr size_t kNonceBytes = 12;
constexpr size_t kTagBytes = 16;

// The challenge every key signs; its signature is the sealing key's input.
constexpr char kChallenge[] = "biometric_storage windows hello key v1";

// A failure reported to Dart: a code its mapping knows ("AuthError:...") or
// "SecurityError".
struct Failure {
  std::string code;
  std::string message;
};

std::string Narrow(const std::wstring &text) {
  if (text.empty()) return std::string();
  const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                       static_cast<int>(text.size()), nullptr,
                                       0, nullptr, nullptr);
  std::string out(size, '\0');
  WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                      out.data(), size, nullptr, nullptr);
  return out;
}

std::wstring Widen(const std::string &text) {
  if (text.empty()) return std::wstring();
  const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                                       static_cast<int>(text.size()), nullptr,
                                       0);
  std::wstring out(size, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                      out.data(), size);
  return out;
}

Failure StatusFailure(KeyCredentialStatus status, const char *step) {
  switch (status) {
    case KeyCredentialStatus::UserCanceled:
    case KeyCredentialStatus::UserPrefersPassword:
      return {"AuthError:UserCanceled", std::string(step) + ": cancelled"};
    case KeyCredentialStatus::NotFound:
      return {"AuthError:KeyInvalidated",
              std::string(step) + ": the Windows Hello key is gone"};
    case KeyCredentialStatus::SecurityDeviceLocked:
      return {"AuthError:LockoutPermanent",
              std::string(step) + ": the security device is locked"};
    default:
      return {"AuthError:AuthFailed", std::string(step) + ": failed"};
  }
}

void Wipe(Bytes &bytes) {
  SecureZeroMemory(bytes.data(), bytes.size());
  bytes.clear();
}

// Brings the Windows Hello dialog to the front while [done] is false: a
// desktop app's Hello prompt otherwise often opens behind its window.
void RaiseHelloDialog(std::atomic<bool> *done) {
  for (int i = 0; i < 100 && !done->load(); i++) {
    HWND dialog = FindWindowW(L"Credential Dialog Xaml Host", nullptr);
    if (dialog != nullptr) {
      SetForegroundWindow(dialog);
      return;
    }
    Sleep(100);
  }
}

// The sealing key of [name]: SHA-256 of the Hello key's signature of the
// challenge. With [create], a missing key credential is created (a Hello
// prompt); without, a missing one is KeyInvalidated.
bool DeriveKey(const std::wstring &name, bool create, Bytes *key,
               Failure *failure) {
  std::atomic<bool> done{false};
  std::thread raise(RaiseHelloDialog, &done);
  struct Join {
    std::atomic<bool> *done;
    std::thread *thread;
    ~Join() {
      done->store(true);
      thread->join();
    }
  } join{&done, &raise};

  auto opened = KeyCredentialManager::OpenAsync(name).get();
  KeyCredential credential{nullptr};
  if (opened.Status() == KeyCredentialStatus::Success) {
    credential = opened.Credential();
  } else if (opened.Status() == KeyCredentialStatus::NotFound && create) {
    auto created = KeyCredentialManager::RequestCreateAsync(
                       name, KeyCredentialCreationOption::ReplaceExisting)
                       .get();
    if (created.Status() != KeyCredentialStatus::Success) {
      *failure = StatusFailure(created.Status(), "creating the key");
      return false;
    }
    credential = created.Credential();
  } else {
    *failure = StatusFailure(opened.Status(), "opening the key");
    return false;
  }

  auto challenge = CryptographicBuffer::ConvertStringToBinary(
      Widen(kChallenge),
      winrt::Windows::Security::Cryptography::BinaryStringEncoding::Utf8);
  auto signed_ = credential.RequestSignAsync(challenge).get();
  if (signed_.Status() != KeyCredentialStatus::Success) {
    *failure = StatusFailure(signed_.Status(), "signing");
    return false;
  }
  winrt::com_array<uint8_t> signature;
  CryptographicBuffer::CopyToByteArray(signed_.Result(), signature);

  key->assign(32, 0);
  BCRYPT_ALG_HANDLE sha = nullptr;
  NTSTATUS status =
      BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (BCRYPT_SUCCESS(status)) {
    status = BCryptHash(sha, nullptr, 0, signature.data(),
                        static_cast<ULONG>(signature.size()), key->data(),
                        static_cast<ULONG>(key->size()));
    BCryptCloseAlgorithmProvider(sha, 0);
  }
  SecureZeroMemory(signature.data(), signature.size());
  if (!BCRYPT_SUCCESS(status)) {
    Wipe(*key);
    *failure = {"SecurityError", "hashing the signature failed"};
    return false;
  }
  return true;
}

// AES-256-GCM over [input] under [key]; [encrypt] or decrypt. For decrypt
// [nonce] and [tag] are read, for encrypt [tag] is written.
bool AesGcm(const Bytes &key, bool encrypt, const uint8_t *nonce,
            const uint8_t *input, size_t length, uint8_t *output,
            uint8_t *tag, Failure *failure) {
  BCRYPT_ALG_HANDLE aes = nullptr;
  BCRYPT_KEY_HANDLE handle = nullptr;
  NTSTATUS status =
      BCryptOpenAlgorithmProvider(&aes, BCRYPT_AES_ALGORITHM, nullptr, 0);
  if (BCRYPT_SUCCESS(status)) {
    status = BCryptSetProperty(
        aes, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
  }
  if (BCRYPT_SUCCESS(status)) {
    status = BCryptGenerateSymmetricKey(
        aes, &handle, nullptr, 0, const_cast<uint8_t *>(key.data()),
        static_cast<ULONG>(key.size()), 0);
  }
  if (BCRYPT_SUCCESS(status)) {
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<uint8_t *>(nonce);
    info.cbNonce = static_cast<ULONG>(kNonceBytes);
    info.pbTag = tag;
    info.cbTag = static_cast<ULONG>(kTagBytes);
    ULONG written = 0;
    status = encrypt
                 ? BCryptEncrypt(handle, const_cast<uint8_t *>(input),
                                 static_cast<ULONG>(length), &info, nullptr, 0,
                                 output, static_cast<ULONG>(length), &written,
                                 0)
                 : BCryptDecrypt(handle, const_cast<uint8_t *>(input),
                                 static_cast<ULONG>(length), &info, nullptr, 0,
                                 output, static_cast<ULONG>(length), &written,
                                 0);
  }
  if (handle != nullptr) BCryptDestroyKey(handle);
  if (aes != nullptr) BCryptCloseAlgorithmProvider(aes, 0);
  if (status == STATUS_AUTH_TAG_MISMATCH) {
    // The key exists but is not the one the data was sealed with: a key
    // credential replaced since (Hello reset, then re-created).
    *failure = {"AuthError:KeyInvalidated",
                "the data does not open with this Windows Hello key"};
    return false;
  }
  if (!BCRYPT_SUCCESS(status)) {
    *failure = {"SecurityError", "AES-GCM failed"};
    return false;
  }
  return true;
}

bool Protect(const std::wstring &name, const Bytes &plain, Bytes *sealed,
             Failure *failure) {
  Bytes key;
  if (!DeriveKey(name, true, &key, failure)) return false;
  sealed->assign(1 + kNonceBytes + plain.size() + kTagBytes, 0);
  (*sealed)[0] = kVersion;
  uint8_t *nonce = sealed->data() + 1;
  const bool ok =
      BCRYPT_SUCCESS(BCryptGenRandom(nullptr, nonce,
                                     static_cast<ULONG>(kNonceBytes),
                                     BCRYPT_USE_SYSTEM_PREFERRED_RNG)) &&
      AesGcm(key, true, nonce, plain.data(), plain.size(),
             nonce + kNonceBytes, nonce + kNonceBytes + plain.size(),
             failure);
  Wipe(key);
  if (!ok && failure->code.empty()) {
    *failure = {"SecurityError", "no random nonce"};
  }
  return ok;
}

bool Unprotect(const std::wstring &name, const Bytes &sealed, Bytes *plain,
               Failure *failure) {
  if (sealed.size() < 1 + kNonceBytes + kTagBytes || sealed[0] != kVersion) {
    *failure = {"SecurityError", "not data sealed by Windows Hello"};
    return false;
  }
  Bytes key;
  if (!DeriveKey(name, false, &key, failure)) return false;
  const size_t length = sealed.size() - 1 - kNonceBytes - kTagBytes;
  plain->assign(length, 0);
  Bytes tag(sealed.end() - kTagBytes, sealed.end());
  const bool ok = AesGcm(key, false, sealed.data() + 1,
                         sealed.data() + 1 + kNonceBytes, length,
                         plain->data(), tag.data(), failure);
  Wipe(key);
  if (!ok) Wipe(*plain);
  return ok;
}

const flutter::EncodableValue *Argument(
    const flutter::MethodCall<flutter::EncodableValue> &call,
    const char *name) {
  const auto *args = std::get_if<flutter::EncodableMap>(call.arguments());
  if (args == nullptr) return nullptr;
  auto it = args->find(flutter::EncodableValue(name));
  return it == args->end() ? nullptr : &it->second;
}

}  // namespace

// static
void WindowsHelloPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {
  auto channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), "biometric_storage/windows_hello",
          &flutter::StandardMethodCodec::GetInstance());
  auto plugin = std::make_unique<WindowsHelloPlugin>(registrar);
  channel->SetMethodCallHandler(
      [plugin_pointer = plugin.get()](const auto &call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });
  registrar->AddPlugin(std::move(plugin));
}

WindowsHelloPlugin::WindowsHelloPlugin(
    flutter::PluginRegistrarWindows *registrar)
    : registrar_(registrar) {
  window_proc_id_ = registrar_->RegisterTopLevelWindowProcDelegate(
      [this](HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
        return HandleWindowProc(hwnd, message, wparam, lparam);
      });
}

WindowsHelloPlugin::~WindowsHelloPlugin() {
  registrar_->UnregisterTopLevelWindowProcDelegate(window_proc_id_);
}

HWND WindowsHelloPlugin::TopLevelWindow() const {
  HWND view = registrar_->GetView() == nullptr
                  ? nullptr
                  : registrar_->GetView()->GetNativeWindow();
  return view == nullptr ? nullptr : GetAncestor(view, GA_ROOT);
}

std::optional<LRESULT> WindowsHelloPlugin::HandleWindowProc(HWND hwnd,
                                                            UINT message,
                                                            WPARAM wparam,
                                                            LPARAM lparam) {
  if (message != kAnswerMessage) return std::nullopt;
  auto *deliver = reinterpret_cast<std::function<void()> *>(lparam);
  (*deliver)();
  delete deliver;
  return 0;
}

void WindowsHelloPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue> &method_call,
    std::unique_ptr<Result> result) {
  const std::string &method = method_call.method_name();
  if (method != "isSupported" && method != "protect" &&
      method != "unprotect" && method != "deleteKey") {
    result->NotImplemented();
    return;
  }
  std::wstring name;
  Bytes data;
  if (method != "isSupported") {
    const auto *name_arg = Argument(method_call, "name");
    const auto *name_text =
        name_arg == nullptr ? nullptr : std::get_if<std::string>(name_arg);
    if (name_text == nullptr || name_text->empty()) {
      result->Error("InvalidArguments", "name");
      return;
    }
    name = Widen(*name_text);
  }
  if (method == "protect" || method == "unprotect") {
    const auto *data_arg = Argument(method_call, "data");
    const auto *bytes =
        data_arg == nullptr ? nullptr : std::get_if<Bytes>(data_arg);
    if (bytes == nullptr) {
      result->Error("InvalidArguments", "data");
      return;
    }
    data = *bytes;
  }
  HWND window = TopLevelWindow();
  if (window == nullptr) {
    result->Error("SecurityError", "no window to answer on");
    return;
  }
  std::shared_ptr<Result> shared(result.release());
  std::thread([window, method, name, data = std::move(data), shared]() mutable {
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    flutter::EncodableValue value;
    Failure failure;
    bool ok = true;
    try {
      if (method == "isSupported") {
        value = flutter::EncodableValue(
            KeyCredentialManager::IsSupportedAsync().get());
      } else if (method == "deleteKey") {
        try {
          KeyCredentialManager::DeleteAsync(name).get();
          value = flutter::EncodableValue(true);
        } catch (const winrt::hresult_error &) {
          // Nothing to delete.
          value = flutter::EncodableValue(false);
        }
      } else {
        Bytes out;
        ok = method == "protect" ? Protect(name, data, &out, &failure)
                                 : Unprotect(name, data, &out, &failure);
        if (ok) value = flutter::EncodableValue(out);
        Wipe(out);
      }
    } catch (const winrt::hresult_error &e) {
      ok = false;
      failure = {"SecurityError", Narrow(std::wstring(e.message()))};
    }
    Wipe(data);
    winrt::uninit_apartment();
    auto *deliver = new std::function<void()>(
        [shared, ok, value = std::move(value), failure]() {
          if (ok) {
            shared->Success(value);
          } else {
            shared->Error(failure.code, failure.message);
          }
        });
    if (!PostMessage(window, kAnswerMessage, 0,
                     reinterpret_cast<LPARAM>(deliver))) {
      delete deliver;
    }
  }).detach();
}

}  // namespace biometric_storage
