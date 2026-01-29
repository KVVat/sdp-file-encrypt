md
# AI Agent Instructions for sdp-file-encrypt

This document provides project-level instructions for any AI agent assisting with the development of this Android application.

## 1. Core Project Goal (プロジェクトの核心的な目的)

The primary goal of this project is to demonstrate and compare different file encryption strategies on Android, focusing on the correct and incorrect ways to use the `AndroidKeyStore` system. The project must clearly distinguish between secure, best-practice implementations and intentionally insecure ones for educational purposes.

このプロジェクトの主な目的は、Android上での様々なファイル暗号化戦略を比較・実証することです。特に`AndroidKeyStore`システムの正しい使い方と間違った使い方に焦点を当てます。このプロジェクトは、セキュアなベストプラクティスに準拠した実装と、学習目的で意図的に安全でなくした実装とを明確に区別しなければなりません。

## 2. Key Component Roles (主要コンポーネントの役割)

When providing code suggestions or analysis, adhere to the specific role of each `EncryptionProvider`.

-   **`HybridKeyProvider`**: This is the **gold standard** and the most recommended approach.
    -   **Strategy**: Hybrid Encryption (ECIES with P-521 and AES-GCM).
    -   **KEK**: A P-521 key pair in `AndroidKeyStore`.
    -   **DEK**: An ephemeral AES-256 key.
    -   **Lock-State Encryption**: This is the *only* provider that correctly and safely supports encryption while the device is locked, by using the public key. Always prioritize this provider's architecture when discussing secure lock-state encryption.

-   **`SecureKeyProvider`**: A standard, secure implementation, but with limitations.
    -   **Strategy**: Envelope Encryption.
    -   **KEK**: An AES-256 key in `AndroidKeyStore`.
    -   **DEK**: A Tink `AES256_GCM` keyset.
    -   **Limitation**: It cannot safely perform encryption when the device is locked if `unlockedDeviceRequired=true`. Do not suggest caching the AEAD primitive as a solution, as this violates the Protection Profile (PP) requirement to clear keys from memory on lock.

-   **`RawEncryptionProvider`**: This is a deliberate **anti-pattern** and should always be treated as such.
    -   **Strategy**: "Key-per-file" using direct `AndroidKeyStore` entries.
    -   **Behavior**: It generates a new key in Keystore for every encryption operation and embeds the key alias in the file header.
    -   **Purpose**: Its purpose is to demonstrate an inefficient and hard-to-manage approach that pollutes the Keystore. When modifying this file, do not try to make it "more secure" in a way that changes its fundamental (and flawed) strategy. For example, do not suggest switching to a single master secret and HKDF, as that would defeat its educational purpose.

-   **`EncryptionManager`**: This is a client-facing facade. Its role is to simplify the API for the UI layer (`MainActivity`). Changes to the providers should ideally not require major changes to the `EncryptionManager` public API.

## 3. High-Level Instructions and Constraints (高レベルの指示と制約)

1.  **Prioritize Security Best Practices (for secure providers)**: For `HybridKeyProvider` and `SecureKeyProvider`, all suggestions must align with Android's official security guidelines and the principles of the Android Keystore system. Refer to the concepts in Protection Profiles (PP_MDF) where relevant.

2.  **Respect the Anti-Pattern (for `RawEncryptionProvider`)**: Do not "fix" the `RawEncryptionProvider`'s core design flaw. Suggestions should only be to make its flawed design *work* (e.g., correctly handling key aliases for multiple files), not to make it fundamentally secure. Always highlight *why* its approach is non-recommended compared to the other providers.

3.  **Distinguish Between Encryption and Decryption Constraints**: When discussing `unlockedDeviceRequired=true`, be precise.
    -   **Encryption**: Can be performed while locked *only* with the `HybridKeyProvider`'s public key.
    -   **Decryption**: *Always* requires the device to be unlocked to access the private/master key in Keystore.

4.  **No `AndroidOpenSSL` for Key Generation/Storage**: Do not suggest creating keys using `AndroidOpenSSL` and storing them in plain files. All persistent keys or key-encrypting keys must be managed by the `AndroidKeyStore` provider.
