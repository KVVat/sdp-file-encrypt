package com.android.niapsec.encryption.api

/**
 * Defines the available KeyProvider implementations that can be used by the EncryptionManager.
 */
enum class KeyProviderType {
    /**
     * Uses the MasterKeyProvider, which leverages the hardware-backed Android Keystore
     * for maximum security. This should be the default for production apps.
     */
    SECURE,

    /**
     * Uses the P521KeyProvider, which uses an Elliptic Curve key pair for
     * hybrid encryption.
     */
    P521,

    /**
     * Uses the HybridKeyProvider, which uses a P-521 elliptic curve key pair as the KEK
     * and AES256-GCM as the DEK for hybrid encryption.
     */
    HYBRID,

    /**
     * Uses the RawEncryptionProvider, which uses the standard Android Keystore and JCA
     * without the Tink library.
     */
    RAW
}
