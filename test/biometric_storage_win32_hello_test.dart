// `src/` rather than the barrel, as in biometric_storage_win32_test.dart: the
// analyzer resolves the barrel's conditional export to its stub. This file
// runs on every host: it drives only the Windows Hello channel, never the
// credential store.
import 'package:biometric_storage/src/biometric_storage.dart';
import 'package:biometric_storage/src/biometric_storage_win32.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const hello = MethodChannel('biometric_storage/windows_hello');

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(hello, null);
  });

  test('canAuthenticate is success where Windows Hello is set up, else '
      'errorHwUnavailable, also without the native half', () async {
    final plugin = Win32BiometricStoragePlugin();
    expect(
      await plugin.canAuthenticate(),
      CanAuthenticateResponse.errorHwUnavailable,
    );
    var supported = true;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(hello, (methodCall) async {
          if (methodCall.method == 'isSupported') return supported;
          throw PlatformException(code: 'NotImplemented');
        });
    expect(await plugin.canAuthenticate(), CanAuthenticateResponse.success);
    supported = false;
    expect(
      await plugin.canAuthenticate(),
      CanAuthenticateResponse.errorHwUnavailable,
    );
  });
}
