# BMC Crypto Library

Thư viện crypto với các module AES, Curve25519/Ed25519, SHA256/SHA512, HMAC, HKDF.

## Cấu trúc dự án

```
bmc_crypt_lib/
├── src/
│   ├── aes/                    # Module AES
│   ├── curve_25519/            # Module Curve25519/Ed25519
│   ├── hash/                   # SHA256/SHA512
│   ├── hmac/                   # HMAC-SHA256/HMAC-SHA512
│   ├── hkdf/                   # HKDF-SHA256
│   └── ...
├── include/                    # Header files
│   └── bmc_crypt/
│       ├── crypto_hash_sha256.h
│       ├── crypto_hash_sha512.h
│       ├── crypto_hmacsha256.h
│       ├── crypto_hmacsha512.h
│       ├── crypto_hkdf_256.h
│       └── ...
├── test/                       # Unit tests
│   ├── test_hash.c             # Test SHA256/SHA512, HMAC
│   ├── test_hkdf.c             # Test HKDF (RFC 5869)
│   └── ...
├── CMakeLists.txt              # File build chính
├── cmake/                      # CMake config files
└── README.md                   # File này
```

## Build với CMake

### Yêu cầu
- CMake 3.10 trở lên
- C compiler (GCC, Clang, hoặc MSVC)

### Cách build với vs2022

1. **Tạo thư mục build:**
```bash
mkdir build
cd build
```

2. **Configure project:**
```bash
cmake .. -G "Visual Studio 17 2022" -DCMAKE_BUILD_TYPE=Release
```

3. **Build project:**
```bash
cmake --build . --config Release
```

### Cách build với Ninja cho android

1. **Tạo thư mục build:**
```bash
mkdir build_android
cd build_android
```

2. **Configure project:**
```bash
cmake .. -DCMAKE_TOOLCHAIN_FILE="C:/Users/PAM/AppData/Local/Android/Sdk/ndk/29.0.13599879/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-24 \
    -DCMAKE_BUILD_TYPE=Release \
    -G "Ninja"
```

3. **Build project:**
```bash
cmake --build . --config Release
```

### Các tùy chọn build

- **Build shared library:**
```bash
cmake -DBUILD_SHARED_LIBS=ON ..
```

- **Build với debug:**
```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

- **Build tests:**
```bash
cmake -DBUILD_TESTS=ON ..
```

### Cài đặt

```bash
cmake --build . --target install
```

## Chạy test

Sau khi build với `-DBUILD_TESTS=ON`, các test sẽ được build trong thư mục `test/`.

Ví dụ chạy test HKDF:
```bash
./test/test_hkdf
```

- Test sử dụng test vector chuẩn từ RFC 5869 để kiểm tra tính đúng đắn của HKDF-SHA256.
- Các test kiểm tra: extract, expand, derive_secrets, compare context, edge cases (input rỗng, output lớn, ...).
- Nếu tất cả test pass sẽ in ra: `All HKDF tests passed!`

Tương tự, có thể chạy các test khác như:
```bash
./test/test_hash      # Test SHA256, SHA512, HMAC
./test/test_gcm       # Test AES-GCM
./test/test_ctr       # Test AES-CTR
...
```

## Sử dụng trong project khác

### Với CMake

```cmake
find_package(bmc_crypt REQUIRED)
target_link_libraries(your_target bmc_crypt::bmc_crypt)
```

### Với pkg-config

Thư viện sẽ được cài đặt với pkg-config support.

## API

### AES Module
- `crypto_core_aes.h` - API cho AES (ECB, CBC, CTR, GCM)

### Curve25519/Ed25519 Module
- `crypto_scalarmult_curve25519.h` - API cho scalar multiplication trên Curve25519
- `crypto_scalarmult_ed25519.h` - API cho scalar multiplication trên Ed25519

### Hash/HMAC/HKDF
- `crypto_hash_sha256.h`, `crypto_hash_sha512.h` - SHA256/SHA512
- `crypto_hmacsha256.h`, `crypto_hmacsha512.h` - HMAC-SHA256/SHA512
- `crypto_hkdf_256.h` - HKDF-SHA256 (chuẩn RFC 5869)

## License

[Thêm thông tin license ở đây] 