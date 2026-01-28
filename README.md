# SDP File Encryption Library for Android

This repository provides a robust and standardized library for securely encrypting and decrypting sensitive data (SDP: Sensitive Data Protection) on Android. It leverages hardware-backed security and modern cryptographic practices to protect data at rest.

## Features

- **Hardware-Backed Key Management**: Uses Android Keystore to store master keys (KEK), ensuring they never leave the secure hardware (TEE/SE).
- **Envelope Encryption**: Implementation of the "Digital Envelope" technique where data is encrypted with a Data Encryption Key (DEK), which is then encrypted by the master key and stored alongside the data.
- **Multiple Encryption Providers**:
    - **SECURE**: High-level implementation using Google's [Tink](https://github.com/google/tink) library with AES256-GCM.
    - **HYBRID**: Advanced hybrid encryption combining ECIES (P-521) for key wrapping and AES-GCM for data encryption.
    - **RAW**: Direct JCA (Java Cryptography Architecture) implementation for environments where external dependencies must be minimized.
    - **P521**: Asymmetric encryption support using the NIST P-521 elliptic curve.
- **Security Policies**: Support for `unlockedDeviceRequired` to prevent data decryption while the device is locked, meeting high security standards like NIAP.
- **Transparent SharedPreferences Encryption**: Includes a wrapper for `SharedPreferences` to seamlessly encrypt key-value pairs.

## Getting Started

### Prerequisites
- Android SDK Level 32 or higher (recommended)
- Kotlin 1.9+

### Integration

The core logic is managed by `EncryptionManager`. You can initialize a provider and start encrypting files or strings.

```kotlin
val manager = EncryptionManager(context)
val provider = manager.getProvider(KeyProviderType.SECURE)

// Encrypt a string
val encrypted = provider.encryptString("Sensitive Data", "alias")

// Decrypt a string
val decrypted = provider.decryptString(encrypted, "alias")
```

### Project Structure

app/src/main/java/.../encryption/api: Public interfaces and the EncryptionManager.

app/src/main/java/.../encryption/internal: Core cryptographic implementations and key providers.

app/src/main/java/.../demo: Demonstration of usage, including encrypted SharedPreferences and UI.

### Security Considerations
This library is designed to solve the complexity and fragmentation of custom cryptographic implementations on Android. By utilizing the Android Keystore and Tink, it provides a "secure by default" approach for enterprise-grade mobile applications.

### License
