/// The Tom Framework's fork of `biometric_storage`: the same library under
/// the package's own name (Flutter's plugin registrant imports this barrel,
/// which carries the Windows class on every `dart.library.io` platform), and
/// `tom_gated_secret_store.dart` beside it.
library;

export 'src/biometric_storage.dart';
export 'src/biometric_storage_win32_fake.dart'
    if (dart.library.io) 'src/biometric_storage_win32.dart';
