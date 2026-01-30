md
# AI Agent Instructions for sdp-file-encrypt

This document provides project-level instructions and records the contributions of AI agents that have assisted with the development of this Android application.

## 1. Core Project Goal (プロジェクトの核心的な目的)

The primary goal of this project is to demonstrate and compare different file encryption strategies on Android, focusing on the correct and incorrect ways to use the `AndroidKeyStore` system. The project must clearly distinguish between secure, best-practice implementations and intentionally insecure ones for educational purposes.

このプロジェクトの主な目的は、Android上での様々なファイル暗号化戦略を比較・実証することです。特に`AndroidKeyStore`システムの正しい使い方と間違った使い方に焦点を当てます。このプロジェクトは、セキュアなベストプラクティスに準拠した実装と、学習目的で意図的に安全でなくした実装とを明確に区別しなければなりません。

## 2. Key Component Roles (主要コンポーネントの役割)

When providing code suggestions or analysis, adhere to the specific role of each `EncryptionProvider`.

-   **`HybridKeyProvider`**: This is the **gold standard** and the most recommended approach.
    -   **Strategy**: A two-tier envelope encryption. The DEK is a Tink-managed ECIES keyset (using P-521 and AES-GCM). This keyset is, in turn, protected by a KEK, which is an AES-256 GCM key stored in the `AndroidKeyStore`.
    -   **Lock-State Behavior**: It correctly supports safe encryption while the device is locked by using a separate, cleartext public keyset, which is persisted in a dedicated SharedPreferences file. Decryption correctly fails when the device is locked, as it enforces access to the hardware-protected KEK by re-instantiating the `AndroidKeysetManager` on every `decrypt` call.

-   **`RawEncryptionProvider`**: This is a deliberate **anti-pattern** and should always be treated as such.
    -   **Strategy**: "Key-per-file" by importing software-generated keys into `AndroidKeyStore`.
    -   **Behavior**: This provider was implemented through extensive debugging with an AI agent. For each file, it generates a software AES key, imports it into the Keystore with the `unlockedDeviceRequired` flag, and embeds the key's alias in the file header.
    -   **Purpose**: Its purpose is to demonstrate a non-standard, inefficient, and hard-to-manage approach that pollutes the Keystore. The complex `destroy()` method, which iterates through all keys with a specific prefix, highlights this management difficulty.

-   **`EncryptionManager`**: A client-facing facade. Its role is to simplify the API for the UI layer (`MainActivity`).

## 3. High-Level Instructions and Constraints (高レベルの指示と制約)

1.  **Respect the Anti-Pattern (for `RawEncryptionProvider`)**: Do not "fix" the `RawEncryptionProvider`'s core design flaw. Suggestions should only be to make its flawed design *work* (e.g., correctly handling key aliases for multiple files). The current implementation, which uses a file header for the key alias and imports software keys, is the intended final state for this provider.

2.  **Understand `HybridKeyProvider`'s Architecture**: This provider's implementation is the result of a deep and complex debugging process. **It intentionally uses a separate, cleartext keyset for the public key to ensure safe lock-state encryption.** The private keyset is protected by a separate `AndroidKeyStore` master key. Do not suggest simplifying this by using a single `AndroidKeysetManager` for both, as that was found to cause various exceptions (`InvalidKeyException`, `ClassCastException`) on locked devices.

3.  **Distinguish Between Encryption and Decryption Constraints**: When discussing `unlockedDeviceRequired=true`, be precise.
    -   **Encryption**: Can be performed while locked *only* with the `HybridKeyProvider`'s public key.
    -   **Decryption**: *Always* requires the device to be unlocked to access any key protected by `unlockedDeviceRequired`. **The fact that decryption fails on a locked device is the expected and correct behavior.**

4.  **No `AndroidOpenSSL` for Direct Key Generation**: Do not suggest creating keys using `AndroidOpenSSL` and storing them in plain files. All persistent keys or key-encrypting keys must be managed by the `AndroidKeyStore` provider, even for the "raw" provider.

