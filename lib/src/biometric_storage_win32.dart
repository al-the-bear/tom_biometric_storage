import 'dart:convert';
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:flutter/services.dart';
import 'package:logging/logging.dart';
import 'package:win32/win32.dart';

import './biometric_storage.dart';

final _logger = Logger('biometric_storage_win32');

/// Windows: values kept in the Credential Manager (wincred). A store with
/// [StorageFileInitOptions.windowsHello] (and `authenticationRequired`) keeps
/// them sealed under a
/// key bound to Windows Hello: each store has a Hello key credential of its
/// own (`KeyCredentialManager`), the SHA-256 of its signature of a fixed
/// challenge is the AES-256-GCM key, so the value cannot be opened without
/// passing Hello (the native half, `windows/windows_hello.cpp`). A write
/// creates the key credential when there is none, which shows the Hello
/// prompt; so does every read. Without Hello set up, [canAuthenticate]
/// answers [CanAuthenticateResponse.errorHwUnavailable] and such a store
/// refuses to write. The prompt's text is Windows' own.
class Win32BiometricStoragePlugin extends BiometricStorage {
  Win32BiometricStoragePlugin() : super.create();

  static const namePrefix = 'design.codeux.authpass.';

  static const _userName = 'flutter.biometric_storage';

  /// The native half's channel.
  static const MethodChannel _hello = MethodChannel(
    'biometric_storage/windows_hello',
  );

  /// What a sealed value starts with in the credential blob (the rest is
  /// base64 of the sealed bytes).
  static const _sealedPrefix = 'hello:v1:';

  /// Names handed out by [getStorage] in this runtime, so that [forceInit] can
  /// mean what the API documents. Windows has no per-store native handle to
  /// hang this off, unlike the method-channel platforms.
  final _initialized = <String>{};

  /// The stores opened with `authenticationRequired` (by prefixed name).
  final _helloStores = <String>{};

  /// Registers this class as the default instance of [BiometricStorage].
  static void registerWith() {
    BiometricStorage.instance = Win32BiometricStoragePlugin();
  }

  @override
  Future<CanAuthenticateResponse> canAuthenticate({
    StorageFileInitOptions? options,
  }) async {
    try {
      final supported = await _hello.invokeMethod<bool>('isSupported');
      return supported == true
          ? CanAuthenticateResponse.success
          : CanAuthenticateResponse.errorHwUnavailable;
    } on MissingPluginException {
      return CanAuthenticateResponse.errorHwUnavailable;
    } on PlatformException catch (e) {
      _logger.warning('Windows Hello: ${e.code}');
      return CanAuthenticateResponse.errorHwUnavailable;
    }
  }

  /// Runs a native Hello call, its errors turned into the plugin's.
  Future<T?> _helloCall<T>(String method, Map<String, Object?> args) async {
    try {
      return await _hello.invokeMethod<T>(method, args);
    } on PlatformException catch (e) {
      final code = _windowsAuthCodes[e.code];
      if (code != null) throw AuthException(code, e.message ?? e.code);
      throw BiometricStorageException(
        'Windows Hello: ${e.message ?? e.code}',
        code: BiometricStorageExceptionCode.storageFailure,
      );
    }
  }

  static const _windowsAuthCodes = {
    'AuthError:UserCanceled': AuthExceptionCode.userCanceled,
    'AuthError:KeyInvalidated': AuthExceptionCode.keyInvalidated,
    'AuthError:LockoutPermanent': AuthExceptionCode.lockoutPermanent,
    'AuthError:AuthFailed': AuthExceptionCode.authFailed,
  };

  @override
  Future<BiometricStorageFile> getStorage(
    String name, {
    StorageFileInitOptions? options,
    bool forceInit = false,
    PromptInfo promptInfo = PromptInfo.defaultValues,
  }) async {
    // Keyed by the prefixed name, which is what every other method on this
    // class is handed — BiometricStorageFile carries the prefixed form, so
    // tracking the bare one here would leave dispose() unable to find it.
    final prefixedName = namePrefix + name;
    // forceInit was accepted and dropped here, so the documented "will throw if
    // the store was already created in this runtime" held on Android alone.
    if (!_initialized.add(prefixedName) && forceInit) {
      throw BiometricStorageException(
        "A storage file with the name '$name' was already initialized.",
        code: BiometricStorageExceptionCode.alreadyInitialized,
      );
    }
    if ((options?.authenticationRequired ?? true) &&
        (options?.windowsHello ?? false)) {
      _helloStores.add(prefixedName);
    } else {
      _helloStores.remove(prefixedName);
    }
    return BiometricStorageFile(this, prefixedName, promptInfo);
  }

  @override
  Future<bool> linuxCheckAppArmorError() async => false;

  @override
  Future<bool> delete(String name, PromptInfo promptInfo) async {
    final deleted = _deleteBlob(name);
    if (_helloStores.contains(name)) {
      await _helloCall<bool>('deleteKey', {'name': name});
    }
    return deleted;
  }

  @override
  Future<String?> read(String name, PromptInfo promptInfo) async {
    final blob = _readBlob(name);
    if (blob == null || !_helloStores.contains(name)) return blob;
    if (!blob.startsWith(_sealedPrefix)) {
      // Written before the store asked for Windows Hello: not released
      // without it.
      throw AuthException(
        AuthExceptionCode.keyInvalidated,
        'the value of $name is not sealed by Windows Hello',
      );
    }
    final plain = await _helloCall<Uint8List>('unprotect', {
      'name': name,
      'data': base64.decode(blob.substring(_sealedPrefix.length)),
    });
    if (plain == null) return null;
    try {
      return utf8.decode(plain);
    } finally {
      plain.fillRange(0, plain.length, 0);
    }
  }

  @override
  Future<void> write(String name, String content, PromptInfo promptInfo) async {
    if (!_helloStores.contains(name)) return _writeBlob(name, content);
    final plain = Uint8List.fromList(utf8.encode(content));
    try {
      final sealed = await _helloCall<Uint8List>('protect', {
        'name': name,
        'data': plain,
      });
      if (sealed == null) {
        throw BiometricStorageException(
          'Windows Hello sealed nothing',
          code: BiometricStorageExceptionCode.storageFailure,
        );
      }
      _writeBlob(name, '$_sealedPrefix${base64.encode(sealed)}');
    } finally {
      plain.fillRange(0, plain.length, 0);
    }
  }

  bool _deleteBlob(String name) {
    return using((arena) {
      final result = CredDelete(
        name.toPcwstr(allocator: arena),
        CRED_TYPE_GENERIC,
      );
      if (!result.value) {
        _logFailure('deleting', name, result.error);
        // Same distinction read() makes: `false` means there was nothing to
        // delete, so a store that is failing must not borrow that answer.
        if (result.error != ERROR_NOT_FOUND) {
          throw BiometricStorageException(
            'Error deleting credential $name: ${result.error}',
            code: BiometricStorageExceptionCode.storageFailure,
          );
        }
        return false;
      }
      return true;
    });
  }

  String? _readBlob(String name) {
    _logger.finer('read($name)');
    return using((arena) {
      final credentialPointer = arena<Pointer<CREDENTIAL>>();
      final result = CredRead(
        name.toPcwstr(allocator: arena),
        CRED_TYPE_GENERIC,
        credentialPointer,
      );
      if (!result.value) {
        _logFailure('reading', name, result.error);
        // `null` is the documented answer to "no value stored". Reporting a
        // credential-store failure the same way left a caller unable to tell
        // an empty store from a broken one, so it read as data loss.
        if (result.error != ERROR_NOT_FOUND) {
          throw BiometricStorageException(
            'Error reading credential $name: ${result.error}',
            code: BiometricStorageExceptionCode.storageFailure,
          );
        }
        return null;
      }
      final credential = credentialPointer.value;
      try {
        // asTypedList is a view onto memory owned by the credential, so the
        // bytes have to be copied out before CredFree invalidates them.
        final blob = Uint8List.fromList(
          credential.ref.CredentialBlob.asTypedList(
            credential.ref.CredentialBlobSize,
          ),
        );
        return utf8.decode(blob);
      } finally {
        CredFree(credential);
      }
    });
  }

  void _writeBlob(String name, String content) {
    _logger.finer('write($name)');
    using((arena) {
      final blob = utf8.encode(content);
      // toNative rejects an empty list, but an empty value is a legitimate
      // thing to store: a zero-length blob needs a valid pointer all the same.
      final blobPointer = blob.isEmpty
          ? arena<Uint8>()
          : blob.toNative(allocator: arena);
      final credential = arena<CREDENTIAL>()
        ..ref.Type = CRED_TYPE_GENERIC
        ..ref.TargetName = name.toPwstr(allocator: arena)
        ..ref.Persist = CRED_PERSIST_LOCAL_MACHINE
        ..ref.UserName = _userName.toPwstr(allocator: arena)
        ..ref.CredentialBlob = blobPointer
        ..ref.CredentialBlobSize = blob.length;

      final result = CredWrite(credential, 0);
      if (!result.value) {
        throw BiometricStorageException(
          'Error writing credential $name: ${result.error} '
          '(${WindowsException(HRESULT_FROM_WIN32(result.error))})',
          code: BiometricStorageExceptionCode.storageFailure,
        );
      }
    });
  }

  @override
  Future<bool> dispose(String name, PromptInfo promptInfo) async =>
      // [name] arrives prefixed, matching what getStorage recorded. There is
      // no native handle to release — the stored credential is deliberately
      // left alone — so forgetting the name is the whole of it.
      _initialized.remove(name);

  void _logFailure(String action, String name, WIN32_ERROR error) {
    if (error == ERROR_NOT_FOUND) {
      _logger.fine('Unable to find credential of name $name');
    } else {
      _logger.warning(
        'Error $action credential $name: $error',
        WindowsException(HRESULT_FROM_WIN32(error)),
      );
    }
  }
}
