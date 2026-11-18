/// `tom_core_storage`'s [TomGatedSecretStore] over this plugin: the store the
/// Tom apps' OS unlock keeps its bundles in (part-os-unlock of the Tom
/// Secrets Manager).
///
/// | Platform | Gate | [TomGatedAvailability] |
/// | --- | --- | --- |
/// | macOS, an app with the `keychain-access-groups` entitlement | the data-protection keychain, `.biometryCurrentSet` | `biometric` |
/// | macOS, an ad-hoc signed app | Touch ID before the read, the item in the login keychain (`darwinGateOnly`) | `gateOnly`, the weaker form |
/// | Windows | Windows Hello signs, its signature is the AES key (`windowsHello`) | `biometric` |
/// | iOS, Android | the keychain or the Keystore key, bound to the biometrics | `biometric` |
/// | Linux and the web | none: no mechanism binds an item to a check | `none` |
library;

import 'dart:io' show Platform;

import 'package:flutter/services.dart' show PlatformException;
import 'package:tom_core_storage/settings.dart';

import 'biometric_storage.dart';

/// A [TomGatedSecretStore] over [BiometricStorage].
///
/// One plugin store per handle. On macOS a key-bound item and a gate-only one
/// are different items, so a write in the key-bound form removes the handle's
/// gate-only twin (an app that was ad-hoc signed and is now team-signed moves
/// each item over at its next write).
final class TomBiometricGatedSecretStore implements TomGatedSecretStore {
  /// The store over [storage] (default the plugin's instance) on
  /// [operatingSystem] (default this one).
  TomBiometricGatedSecretStore({
    BiometricStorage? storage,
    String? operatingSystem,
  }) : _storage = storage ?? BiometricStorage(),
       _os = operatingSystem ?? Platform.operatingSystem;

  final BiometricStorage _storage;
  final String _os;
  bool? _keyBound;

  /// The suffix of a handle's gate-only item on macOS.
  static const String gateOnlySuffix = '.gate';

  bool get _supported =>
      const {'macos', 'windows', 'ios', 'android'}.contains(_os);

  Future<bool> _darwinKeyBound() async =>
      _keyBound ??= _os == 'ios' || await _storage.darwinKeyBoundAvailable();

  Future<StorageFileInitOptions> _options({bool? gateOnly}) async =>
      StorageFileInitOptions(
        authenticationRequired: true,
        darwinBiometricOnly: true,
        darwinGateOnly:
            gateOnly ?? (_os == 'macos' && !await _darwinKeyBound()),
        windowsHello: _os == 'windows',
      );

  Future<BiometricStorageFile> _file(
    String handle, {
    String? reason,
    bool? gateOnly,
  }) async {
    final text = reason ?? '';
    final ios = IosPromptInfo(saveTitle: text, accessTitle: text);
    final gate = gateOnly ?? (_os == 'macos' && !await _darwinKeyBound());
    return _storage.getStorage(
      gate && _os == 'macos' ? '$handle$gateOnlySuffix' : handle,
      options: await _options(gateOnly: gate),
      promptInfo: PromptInfo(
        androidPromptInfo: AndroidPromptInfo(
          title: text.isEmpty ? 'Unlock' : text,
        ),
        iosPromptInfo: ios,
        macOsPromptInfo: ios,
      ),
    );
  }

  @override
  Future<TomGatedAvailability> availability() async {
    if (!_supported) return TomGatedAvailability.none;
    final CanAuthenticateResponse answer;
    try {
      answer = await _storage.canAuthenticate(options: await _options());
    } on Object {
      return TomGatedAvailability.none;
    }
    if (answer != CanAuthenticateResponse.success) {
      return TomGatedAvailability.none;
    }
    if (_os == 'macos' && !await _darwinKeyBound()) {
      return TomGatedAvailability.gateOnly;
    }
    return TomGatedAvailability.biometric;
  }

  @override
  Future<void> write(
    String handle,
    String secret, {
    TomGatedLifetime lifetime = TomGatedLifetime.saved,
    String? reason,
  }) async {
    if (!_supported) {
      throw const TomGatedSecretStoreException(
        TomGatedSecretErrorKind.unavailable,
      );
    }
    await _guard(() async {
      final file = await _file(handle, reason: reason);
      await file.write(secret);
      if (_os == 'macos' && await _darwinKeyBound()) {
        await (await _file(handle, gateOnly: true)).delete();
      }
    });
  }

  @override
  Future<String?> read(String handle, {required String reason}) async {
    if (!_supported) return null;
    return _guard(() async => (await _file(handle, reason: reason)).read());
  }

  @override
  Future<void> delete(String handle) async {
    if (!_supported) return;
    await _guard(() async {
      await (await _file(handle)).delete();
      if (_os == 'macos' && await _darwinKeyBound()) {
        await (await _file(handle, gateOnly: true)).delete();
      }
    });
  }

  /// [call], its failures as [TomGatedSecretStoreException] of their kind.
  Future<T> _guard<T>(Future<T> Function() call) async {
    try {
      return await call();
    } on AuthException catch (e) {
      throw TomGatedSecretStoreException(
        tomGatedErrorKindOf(e.code),
        code: e.code.name,
      );
    } on BiometricStorageException catch (e) {
      throw TomGatedSecretStoreException(
        TomGatedSecretErrorKind.failed,
        code: e.code.name,
      );
    } on PlatformException catch (e) {
      throw TomGatedSecretStoreException(
        TomGatedSecretErrorKind.failed,
        code: e.code,
      );
    }
  }
}

/// The port's error kind of the plugin's [code].
TomGatedSecretErrorKind tomGatedErrorKindOf(AuthExceptionCode code) =>
    switch (code) {
      AuthExceptionCode.userCanceled ||
      AuthExceptionCode.canceled ||
      AuthExceptionCode.timeout => TomGatedSecretErrorKind.cancelled,
      AuthExceptionCode.lockout ||
      AuthExceptionCode.lockoutPermanent => TomGatedSecretErrorKind.lockedOut,
      AuthExceptionCode.keyInvalidated => TomGatedSecretErrorKind.invalidated,
      AuthExceptionCode.unavailable => TomGatedSecretErrorKind.unavailable,
      _ => TomGatedSecretErrorKind.failed,
    };
