# AI Agent Instructions for sdp-file-encrypt

This document provides project-level instructions and records the architectural rules and contributions of AI agents that have assisted with the development of this Android application.

## 1. Core Project Goal

The primary goal of this project is to demonstrate and compare different file encryption strategies on Android, focusing on the correct and incorrect ways to use the `AndroidKeyStore` system. The project must clearly distinguish between secure, best-practice implementations compliant with Common Criteria / NIAP standards and intentionally insecure or sub-optimal ones for educational purposes.

## 2. Documentation and Language Policy

**All documentation (including Markdown files) and source code comments MUST be written in English.** This is a strict requirement for all future updates and contributions.

## 3. Key Component Roles

When providing code suggestions, debugging, or analyzing the codebase, strictly adhere to the specific role and architectural requirements of each component:

*   **`RawHybridKeyProvider` (The Compliant Reference)**:
    *   **Strategy**: This is the **gold standard** for strict security compliance (specifically targeting the **NIAP Mobile Device Fundamentals Protection Profile (MDF PP) Version 3.3**). It uses raw JCA primitives to achieve complete control over the key lifecycle and memory footprint.
    *   **Key Wrapping (Envelope Encryption)**: Ephemeral, per-file `AES-256-GCM` Data Encryption Keys (DEKs) are wrapped/unwrapped using asymmetric key agreement (ECDH with P-521). The KEK is a hardware-protected EC key pair generated directly within `AndroidKeyStore` with the `unlockedDeviceRequired` flag.
    *   **Lock-State Behavior (FDP_DAR_EXT.2)**: To allow safe background encryption while the device is locked (where hardware KeyStore keys are unavailable), the provider caches the public key in cleartext within SharedPreferences (using Device Protected (DE) storage context). Decryption correctly and securely fails when the device is locked, as the private key is hardware-locked in the TEE.
    *   **Sweep and Re-wrap (FDP_DAR_EXT.2.4)**: Once the device is unlocked (detected via `ACTION_USER_PRESENT`), a sweep mechanism runs to transition files from asymmetric lock-state protection back to an efficient symmetric KeyStore protection (using a dedicated symmetric Master Key or an ECDH symmetric scheme) to improve subsequent access times and minimize crypto overhead.
    *   **Key Destruction (FCS_CKM_EXT.4)**: Implements deterministic, explicit zeroization (overwriting key byte arrays with zero) in `finally` blocks immediately after usage. It also utilizes a specific Binder buffer poisoning/flushing method to clear residual key material from Keystore2/Binder IPC memory.

*   **`HybridKeyProvider` (Tink-based Standard)**:
    *   **Strategy**: A standard implementation leveraging the **Google Tink** library. It uses a two-tier envelope encryption: the DEK is an ECIES keyset (P-521 and AES-GCM) managed by Tink, which is in turn protected by a Master Key (KEK) stored in `AndroidKeyStore` with `unlockedDeviceRequired`.
    *   **Lock-State Behavior**: Similar to the raw hybrid implementation, it caches the public keyset in a separate SharedPreferences file to enable encryption in a locked state, while decryption fails when locked.
    *   **Note on Compliance**: While robust and suitable for most applications, it abstracts memory management. Since explicit zeroization of transient DEK byte arrays depends on standard JVM GC and Tink's internal behaviors (which do not guarantee instant destruction), it is documented as non-compliant with strict volatile memory zeroization requirements (`FCS_CKM_EXT.4`).

*   **`RawKeyProvider` (Intentionally Insecure Anti-Pattern)**:
    *   **Strategy**: A manual, raw JCA key provider that wraps standard APIs into the Tink `Aead` interface for comparative testing.
    *   **Anti-Pattern Behavior**: Implements a "Key-per-file" design. For each file, it generates a software AES key (using `AndroidOpenSSL`), imports it into the `AndroidKeyStore` with the `unlockedDeviceRequired` flag, and embeds the key's unique alias and initialization vector in the file's custom header.
    *   **Purpose**: Deliberately showcases a sub-optimal, high-overhead key management approach that pollutes the hardware Keystore. The complex `destroy()` method, which must search for and delete all keystore entries starting with a specific prefix, highlights this difficulty.

*   **`EncryptionManager`**: A client-facing facade that simplifies file and stream I/O operations for the UI layer (`MainActivity`) by abstracting the chosen `KeyProviderType`.

## 4. High-Level Instructions and Constraints

1.  **Respect the Anti-Pattern (for `RawKeyProvider`)**: Do not "fix" the `RawKeyProvider`'s core design flaw. Suggestions should only ensure its existing design works correctly (e.g., handling unique key aliases correctly across multiple files and robustly cleaning them up). The file-header based key-per-file alias import approach is the intended final state of this provider.

2.  **Maintain Key Separation in Lock-State**: Both `RawHybridKeyProvider` and `HybridKeyProvider` must separate the public key (cached in cleartext in SharedPreferences) from the private key (held securely inside the TEE/KeyStore). Do not attempt to simplify this architecture by calling standard Keystore methods for encryption during locked states, as this will trigger exceptions (e.g., `InvalidKeyException`, `ClassCastException`) and break lock-state ingestion support.

3.  **Distinguish Between Encryption and Decryption Constraints**: When configuring or explaining security policies (`unlockedDeviceRequired=true`):
    *   **Encryption**: Can be performed safely while the device is locked (using the cached public keys / public keysets).
    *   **Decryption**: *Always* requires the device to be unlocked to authenticate the user and authorize access to the hardware-backed private keys. **Failure to decrypt on a locked device is the expected, correct, and secure behavior.**

4.  **No Direct Plaintext Key Files Outside KeyStore**: Do not create or save raw persistent key material directly onto the filesystem. All persistent keys or key-encrypting keys must reside inside the `AndroidKeyStore` system, even for the software-backed keys imported by the `RawKeyProvider`.

5.  **Tool Usage & Stream Output**: When executing terminal commands or running scripts (such as ADB commands or local automation utilities), **never redirect standard output to external files** (e.g., `> /tmp/output.txt`) to process large JSON or UI dumps. AI agents must **always consume and process output directly from the standard stream** to prevent leaving unnecessary files on the host environment and avoid triggering file-system permission popups.
