# SDP File Encryption Demo

## 1. Project Overview

This is an Android application designed to demonstrate and compare different file encryption strategies, focusing on compliance with the **NIAP Mobile Device Fundamentals Protection Profile (MDF PP) Version 3.3**.

The primary goal is to compare distinct `EncryptionProvider` implementations:
- **`RawHybridKeyProvider`**: The **NIAP-compliant** reference implementation. It uses raw JCA primitives to strictly control key memory lifecycles (zeroization) and supports secure lock-state operations.
- **`HybridKeyProvider`**: A standard implementation using **Google Tink's Hybrid Encryption** (ECIES).
- **`SecureKeyProvider`**: A standard implementation using **Google Tink's Envelope Encryption** (AES-GCM).
- **`RawKeyProvider`**: A manual implementation using raw Android JCA APIs (`Cipher`, `KeyStore`) wrapped in the Tink `Aead` interface.

## 2. Security Architecture & Compliance

This library is designed to meet the strict security requirements of the **NIAP Mobile Device Fundamentals Protection Profile (MDF PP) Version 3.3**.

### Key Implementation: `RawHybridKeyProvider`
Unlike standard high-level wrappers, our `RawHybridKeyProvider` uses raw JCA primitives to ensure full control over the key lifecycle, specifically addressing memory zeroization requirements.

* **Algorithm**: Hybrid Encryption Scheme (EC-DH + HKDF + AES-GCM).
* **Compliance Features**:
    * **FCS_CKM_EXT.4 (Key Destruction)**: Explicitly zeroes out (overwrites) plain-text DEKs and shared secrets in volatile memory immediately after use via `finally` blocks. Standard high-level libraries often rely on Garbage Collection, which is insufficient for PP compliance.
    * **FDP_DAR_EXT.2 (Locked State Operation)**: Supports encryption even when the device is locked (AFU/BFU) by leveraging a cached public key configuration, while keeping the private key securely hardware-backed in the TEE.
    * **FCS_CKM_EXT.2 (Key Generation)**: Uses `SecureRandom` for generating ephemeral Data Encryption Keys (DEKs).
    * **FCS_STG_EXT.2 (Key Storage)**: Implements Envelope Encryption where DEKs are wrapped by a TEE-backed Key Encryption Key (KEK).

## 3. Key Components

### `EncryptionProvider` Implementations

#### `RawHybridKeyProvider` (Compliant)
- **Strategy**: A robust two-tier envelope encryption designed for Common Criteria evaluation.
- **KEK (Key-Encrypting Key)**: An `EC` (Elliptic Curve) key pair stored securely in the `AndroidKeyStore` with `unlockedDeviceRequired`.
- **DEK (Data-Encapsulating Key)**: An ephemeral `AES-256-GCM` key generated via `SecureRandom` for each file.
- **Lock-State Behavior**:
    - **Encryption**: Supported in locked state. Uses a pre-shared/cached Public Key to wrap the ephemeral DEK without accessing the Keystore.
    - **Decryption**: Fails securely when locked. Requires user authentication to access the Private Key in the TEE for unwrapping.
- **Memory Safety**: Implements explicit zeroization of sensitive byte arrays immediately after use.

#### `HybridKeyProvider` (Tink Standard)
- **Strategy**: Two-tier envelope encryption using the **Google Tink** library.
- **KEK**: An `AES` key stored in the `AndroidKeyStore`.
- **DEK**: A Tink-managed ECIES keyset.
- **Note**: This implementation demonstrates the standard usage of Tink's Hybrid primitives. While secure for general use, it abstracts memory management, making it difficult to prove strict compliance with NIAP's volatile memory zeroization requirements (`FCS_CKM_EXT.4`).

#### `SecureKeyProvider` (Tink Envelope)
- **Strategy**: Standard envelope encryption using **Google Tink**.
- **KEK**: An `AES-256-GCM` key stored in the `AndroidKeyStore`.
- **DEK**: A Tink-managed `AES256_GCM` keyset, encrypted by the KEK.
- **Note**: A solid, best-practice implementation for general use cases using symmetric keys.

#### `RawKeyProvider` (JCA Adapter)
- **Strategy**: A manual implementation wrapping standard Android JCA APIs (`Cipher`, `AndroidKeyStore`) into the Tink `Aead` interface.
- **Algorithm**: `AES/CBC/PKCS7Padding`.
- **Behavior**: Generates software-backed keys and imports them into the Keystore.
- **Purpose**: Demonstrates how to adapt raw platform APIs to a common interface without using the full Tink library features.

### `EncryptionManager` & `MainActivity`
- The `EncryptionManager` acts as a facade, providing a simple API for the `MainActivity` to interact with the different `EncryptionProvider`s.
- The `MainActivity` provides a UI to run encryption/decryption tests for each provider, both in unlocked and locked states, and to display the results.

### `DeviceAdminReceiver`
- This component is required to programmatically lock the screen for the "Lock & Test" feature. The user must grant Device Administrator permissions to the app for this functionality to work.

## 4. How to Build and Run

1. Clone the repository.
2. Open the project in a recent version of Android Studio.
3. Build and run the app on an emulator or a physical device.
4. Use the buttons on the screen to test each encryption provider.
5. To use the "Lock & Test" feature, you may need to grant Device Administrator permissions to the app via the device's settings.

## 5. License

Copyright 2026 The Android Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.