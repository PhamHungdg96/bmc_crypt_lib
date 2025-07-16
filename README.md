# BMC Crypto Library

Thư viện crypto với các module AES và Curve25519/Ed25519.

## Cấu trúc dự án

```
bmc_crypt_lib/
├── src/
│   ├── AES/                    # Module AES
│   │   ├── aes_internal.c
│   │   └── aes_internal.h
│   ├── curve_25519/            # Module Curve25519/Ed25519
│   │   ├── curve25519/
│   │   │   ├── scalarmult_curve25519.c
│   │   │   ├── scalarmult_curve25519.h
│   │   │   └── ref10/
│   │   │       ├── x25519_ref10.c
│   │   │       └── x25519_ref10.h
│   │   └── ed25519/
│   │       └── ref10/
│   │           └── scalarmult_ed25519_ref10.c
│   └── include/                # Header files
│       └── bmc_crypt/
│           ├── crypto_scalarmult_curve25519.h
│           ├── crypto_scalarmult_ed25519.h
│           ├── export.h
│           ├── utils.h
│           └── private/
├── CMakeLists.txt              # File build chính
├── cmake/                      # CMake config files
│   └── bmc_cryptConfig.cmake.in
└── README.md                   # File này
```

## Build với CMake

### Yêu cầu
- CMake 3.10 trở lên
- C compiler (GCC, Clang, hoặc MSVC)

### Cách build

1. **Tạo thư mục build:**
```bash
mkdir build
cd build
```

2. **Configure project:**
```bash
cmake ..
```

3. **Build project:**
```bash
cmake --build .
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

- **Build tests (nếu có):**
```bash
cmake -DBUILD_TESTS=ON ..
```

### Cài đặt

```bash
cmake --build . --target install
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
- `aes_internal.h` - Header cho các hàm AES internal

### Curve25519 Module
- `crypto_scalarmult_curve25519.h` - API cho scalar multiplication trên Curve25519
- `x25519_ref10.h` - Implementation reference cho X25519

### Ed25519 Module
- `crypto_scalarmult_ed25519.h` - API cho scalar multiplication trên Ed25519

## License

[Thêm thông tin license ở đây] 