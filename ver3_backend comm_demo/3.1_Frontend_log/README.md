# Virtual HSM C++/QML Example

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Notes
- This is a minimal C++ + QML scaffold.
- `AuthService` and `CryptoService` currently use mock logic.
- Replace those services with real RSA, file I/O, and key-management logic later.
