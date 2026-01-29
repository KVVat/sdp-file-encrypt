/*
* Copyright (C) 2026 The Android Open Source Project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

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
