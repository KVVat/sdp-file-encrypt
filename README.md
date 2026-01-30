# SDP File Encryption Demo

## 1. Project Overview

This is an Android application designed to demonstrate and compare different file encryption strategies, particularly focusing on the correct and incorrect ways to use the `AndroidKeyStore` system.

The primary goal is to compare three distinct `EncryptionProvider` implementations:
- `HybridKeyProvider`: The most secure and recommended approach, demonstrating a two-tier envelope encryption.
- `SecureKeyProvider`: A standard, best-practice implementation of envelope encryption using symmetric keys.
- `RawEncryptionProvider`: An intentionally insecure implementation for educational purposes, highlighting the pitfalls of misusing the Keystore.

## 2. Key Components

### `EncryptionProvider` Implementations

#### `HybridKeyProvider`
- **Strategy**: A robust two-tier envelope encryption.
- **KEK (Key-Encrypting Key)**: An `AES-256-GCM` key stored securely in the `AndroidKeyStore` with the `unlockedDeviceRequired` flag.
- **DEK (Data-Encapsulating Key)**: A Tink-managed ECIES keyset using a `P-521` key pair. This entire keyset is encrypted by the KEK.
- **Lock-State Behavior**:
    - **Encryption**: It safely supports encryption while the device is locked. This is achieved by persisting the ECIES public key in a separate, cleartext `SharedPreferences` file.
    - **Decryption**: It correctly fails when the device is locked. This is enforced by re-instantiating the `AndroidKeysetManager` on every `decrypt` call, which forces a check against the hardware-protected KEK.

#### `SecureKeyProvider`
- **Strategy**: Standard envelope encryption.
- **KEK**: An `AES-256-GCM` key stored in the `AndroidKeyStore`.
- **DEK**: A Tink-managed `AES256_GCM` keyset, encrypted by the KEK.
- **Note**: This is a solid, best-practice implementation for use cases that do not require lock-state encryption. It does not support encryption while the device is locked.

#### `RawEncryptionProvider`
- **Strategy**: An "anti-pattern" demonstrating "key-per-file" by importing software-generated keys into the Keystore.
- **Behavior**: For each file, it generates a new software AES key, imports it into the `AndroidKeyStore` with the `unlockedDeviceRequired` flag, and embeds the key's unique alias in the file header.
- **Purpose**: This provider serves as an educational example of an inefficient and difficult-to-manage approach that pollutes the Keystore. The necessity of a complex `destroy()` method that iterates through all keys with a specific prefix highlights these management challenges.

### `EncryptionManager` & `MainActivity`
- The `EncryptionManager` acts as a facade, providing a simple API for the `MainActivity` to interact with the different `EncryptionProvider`s.
- The `MainActivity` provides a UI to run encryption/decryption tests for each provider, both in unlocked and locked states, and to display the results.

### `DeviceAdminReceiver`
- This component is required to programmatically lock the screen for the "Lock & Test" feature. The user must grant Device Administrator permissions to the app for this functionality to work.

## 3. How to Build and Run

1. Clone the repository.
2. Open the project in a recent version of Android Studio.
3. Build and run the app on an emulator or a physical device.
4. Use the buttons on the screen to test each encryption provider.
5. To use the "Lock & Test" feature, you may need to grant Device Administrator permissions to the app via the device's settings.

## 4. License

Copyright 2026 The Android Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUTHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
