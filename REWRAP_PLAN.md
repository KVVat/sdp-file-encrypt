# Implementation Plan: FDP_DAR_EXT.2.4 Post-Unlock Key Rewrapping

This plan outlines the steps to implement the rewrapping of file keys from an asymmetric scheme to a symmetric scheme after the device is unlocked, as required by MDFPP 3.3 (FDP_DAR_EXT.2.4).

## Current Issue: UDR (Unlocked Device Required) Instability
Tests show that decryption sometimes succeeds when it should fail while the device is locked. 
**Likely cause:** Stale files from previous successful runs are not being deleted, leading to false "Success" results even if the current operation was blocked.

---

## Phase 1: UDR Reliability Fix (Priority)
**Goal:** Ensure "Lock & Test" results are consistent and accurate.

1.  **Strict File Cleanup in `EncryptionTestRunner.kt`**:
    *   Explicitly `delete()` the target test file at the very beginning of `runFullTest`.
    *   This ensures that the decryption phase cannot read old data if the encryption phase was blocked.
2.  **Explicit State Wait in `MainActivity.kt`**:
    *   Keep a controlled delay (e.g., 3-5 seconds) after calling `devicePolicyManager.lockNow()`.
    *   This allows the Android system and Keystore to propagate the "Locked" state.
3.  **Exception Logging**:
    *   Capture and log the exact Exception type (e.g., `UserNotAuthenticatedException`) in `TestResult.message`.

## Phase 2: Symmetric Master Key Management
**Goal:** Create a symmetric protection layer available only when unlocked.

1.  **Key Generation in `RawHybridKeyProvider.kt`**:
    *   Generate an AES-256 GCM key in Android Keystore.
    *   Alias: `${masterKeyAlias}_symmetric`.
    *   Policy: `setUnlockedDeviceRequired(true)`.
2.  **Initialization**: Ensure this key is generated alongside the EC key pair during provider startup.

## Phase 3: Storage Format Extension (Magic Bytes)
**Goal:** Allow the library to distinguish between asymmetric and symmetric wrappers.

1.  **Magic Bytes Definition**:
    *   `0x01`: Asymmetric/Hybrid mode (Wrapped by EC Public Key).
    *   `0x02`: Symmetric mode (Wrapped by AES Master Key).
2.  **Serialization Update**:
    *   Prepend the magic byte to the encPhasrypted package.
    *   Make the ephemeral public key optional (null for `0x02`).
3.  **Decryption Dispatch**:
    *   Update `Aead.decrypt` and `StreamingAead.newDecryptingStream` to branch based on the first byte.

## Phase 4: Rewrapping Logic
**Goal:** Transition data from asymmetric to symmetric protection.

1.  **Core Rewrap (`RawHybridKeyProvider`)**:
    *   Implement `rewrapKeyToSymmetricUdr`.
    *   Decrypt `0x01` package -> Extract DEK -> Re-encrypt DEK with Symmetric Master Key -> Return `0x02` package.
2.  **File Integration (`TinkEncryptionProvider`)**:
    *   Implement `rewrapFileKey(Uri)`.
    *   Read file -> Strip 0x00 flag -> Rewrap package -> Prepend 0x00 flag -> Overwrite file.
3.  **Batch Processing**: Implement `sweepAndRewrapPendingFiles()` to scan the app's files directory.

## Phase 5: Automated Triggers & UI
**Goal:** Ensure MDFPP compliance in the demo app.

1.  **Unlock Detection**:
    *   Implement `ACTION_USER_PRESENT` BroadcastReceiver in `MainActivity`.
    *   Trigger `sweepAndRewrapPendingFiles()` automatically on unlock.
2.  **UI Verification**:
    *   Add a "Check Status" button to list all `.enc` files and their magic byte.
    *   Add a "Manual Sweep" button for testing.
    *   Allow tapping a file to see its decrypted content in a Snackbar.

## Phase 6: Validation
1.  **Regression**: Run "Lock & Test" to confirm decryption fails while locked.
2.  **Rewrap Verification**: Confirm `0x01` file becomes `0x02` after unlock and remains decryptable.
