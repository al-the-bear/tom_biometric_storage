// The Tom adapter (lib/tom_gated_secret_store.dart) over a fake platform:
// the availability per OS and form, the options each store is opened with
// (Windows Hello, the macOS gate-only form), the macOS move from the
// gate-only item to the key-bound one, and every error kind.
import 'package:flutter_test/flutter_test.dart';
import 'package:tom_biometric_storage/src/biometric_storage.dart';
import 'package:tom_biometric_storage/tom_gated_secret_store.dart';
import 'package:tom_core_storage/settings.dart';

final class _FakePlatform extends BiometricStorage {
  _FakePlatform({this.keyBound = true}) : super.create();

  bool keyBound;
  CanAuthenticateResponse answer = CanAuthenticateResponse.success;
  final Map<String, String> items = {};
  final Map<String, StorageFileInitOptions> opened = {};
  final List<String> prompts = [];
  Object? failRead;

  @override
  Future<bool> darwinKeyBoundAvailable() async => keyBound;

  @override
  Future<CanAuthenticateResponse> canAuthenticate({
    StorageFileInitOptions? options,
  }) async => answer;

  @override
  Future<BiometricStorageFile> getStorage(
    String name, {
    StorageFileInitOptions? options,
    bool forceInit = false,
    PromptInfo promptInfo = PromptInfo.defaultValues,
  }) async {
    opened[name] = options!;
    return BiometricStorageFile(this, name, promptInfo);
  }

  @override
  Future<bool> linuxCheckAppArmorError() async => false;

  @override
  Future<String?> read(String name, PromptInfo promptInfo) async {
    final item = items[name];
    if (item == null) return null;
    prompts.add(promptInfo.macOsPromptInfo.accessTitle);
    final failure = failRead;
    if (failure != null) {
      failRead = null;
      throw failure;
    }
    return item;
  }

  @override
  Future<void> write(
    String name,
    String content,
    PromptInfo promptInfo,
  ) async => items[name] = content;

  @override
  Future<bool?> delete(String name, PromptInfo promptInfo) async =>
      items.remove(name) != null;

  @override
  Future<bool> dispose(String name, PromptInfo promptInfo) async => true;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('availability: biometric where the check binds the item, gateOnly on '
      'an ad-hoc signed Mac, none on Linux or without enrolment', () async {
    final platform = _FakePlatform();
    Future<TomGatedAvailability> on(String os) => TomBiometricGatedSecretStore(
      storage: platform,
      operatingSystem: os,
    ).availability();
    expect(await on('windows'), TomGatedAvailability.biometric);
    expect(await on('macos'), TomGatedAvailability.biometric);
    platform.keyBound = false;
    expect(await on('macos'), TomGatedAvailability.gateOnly);
    expect(await on('linux'), TomGatedAvailability.none);
    platform.answer = CanAuthenticateResponse.errorNoBiometricEnrolled;
    expect(await on('windows'), TomGatedAvailability.none);
  });

  test('Windows opens its stores with Windows Hello; a read prompts with the '
      'reason; delete forgets', () async {
    final platform = _FakePlatform();
    final store = TomBiometricGatedSecretStore(
      storage: platform,
      operatingSystem: 'windows',
    );
    await store.write('tsm.os-unlock.demo', 'demo-bundle');
    expect(platform.opened['tsm.os-unlock.demo']!.windowsHello, isTrue);
    expect(
      platform.opened['tsm.os-unlock.demo']!.authenticationRequired,
      isTrue,
    );
    expect(
      await store.read('tsm.os-unlock.demo', reason: 'Unlock the vaults'),
      'demo-bundle',
    );
    expect(platform.prompts, ['Unlock the vaults']);
    await store.delete('tsm.os-unlock.demo');
    expect(await store.read('tsm.os-unlock.demo', reason: 'x'), isNull);
  });

  test('macOS: ad-hoc signed, the item is gate-only under its own name; '
      'team-signed, a write moves it to the key-bound form', () async {
    final platform = _FakePlatform(keyBound: false);
    await TomBiometricGatedSecretStore(
      storage: platform,
      operatingSystem: 'macos',
    ).write('h', 'demo-bundle');
    expect(platform.items.keys, ['h.gate']);
    expect(platform.opened['h.gate']!.darwinGateOnly, isTrue);

    platform.keyBound = true;
    final signed = TomBiometricGatedSecretStore(
      storage: platform,
      operatingSystem: 'macos',
    );
    expect(await signed.read('h', reason: 'x'), isNull);
    await signed.write('h', 'demo-bundle');
    expect(platform.items.keys, ['h']);
    expect(platform.opened['h']!.darwinGateOnly, isFalse);
  });

  test('every failure becomes its kind, never a miss', () async {
    final platform = _FakePlatform();
    final store = TomBiometricGatedSecretStore(
      storage: platform,
      operatingSystem: 'windows',
    );
    await store.write('h', 'demo-bundle');
    final cases = {
      AuthExceptionCode.userCanceled: TomGatedSecretErrorKind.cancelled,
      AuthExceptionCode.lockoutPermanent: TomGatedSecretErrorKind.lockedOut,
      AuthExceptionCode.keyInvalidated: TomGatedSecretErrorKind.invalidated,
      AuthExceptionCode.unavailable: TomGatedSecretErrorKind.unavailable,
      AuthExceptionCode.authFailed: TomGatedSecretErrorKind.failed,
    };
    for (final MapEntry(key: code, value: kind) in cases.entries) {
      platform.failRead = AuthException(code, 'demo');
      await expectLater(
        store.read('h', reason: 'x'),
        throwsA(
          isA<TomGatedSecretStoreException>().having(
            (e) => e.kind,
            'kind',
            kind,
          ),
        ),
      );
    }
    platform.failRead = BiometricStorageException('demo');
    await expectLater(
      store.read('h', reason: 'x'),
      throwsA(
        isA<TomGatedSecretStoreException>().having(
          (e) => e.kind,
          'kind',
          TomGatedSecretErrorKind.failed,
        ),
      ),
    );
  });

  test('Linux writes nothing and reads nothing', () async {
    final store = TomBiometricGatedSecretStore(
      storage: _FakePlatform(),
      operatingSystem: 'linux',
    );
    await expectLater(
      store.write('h', 'demo-bundle'),
      throwsA(isA<TomGatedSecretStoreException>()),
    );
    expect(await store.read('h', reason: 'x'), isNull);
  });
}
