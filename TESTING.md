# Testing Guide

## Prerequisites

- Device with screen lock configured
- App installed with Device Admin permission granted

## Test Cases

### 1. Symmetric Encrypt → Symmetric Decrypt

Verifies normal encryption and decryption when the device is unlocked.

1. Tap **Test File**
2. Tap **Check Status** — file should show `Symmetric 0x02`
3. Tap the file entry to decrypt and verify the plaintext

### 2. Asymmetric Encrypt → Sweep → Symmetric Decrypt

Verifies that files encrypted while locked are re-wrapped to symmetric after unlock.

1. Tap **Lock & Test** (device will lock and encrypt with asymmetric key)
2. Unlock the device and return to the app
3. Tap **Check Status** — file should show `Symmetric 0x02` (sweep ran automatically on unlock)
4. Tap the file entry to decrypt and verify the plaintext

### 3. Asymmetric Encrypt → Asymmetric Decrypt (Sweep Disabled)

Verifies that asymmetric-encrypted files remain unchanged and can still be decrypted without sweep.

1. Open the 3-dot menu in the top bar
2. Uncheck **Enable DAR_EXT.2.4 sweep**
3. Tap **Lock & Test** (device will lock and encrypt with asymmetric key)
4. Unlock the device and return to the app
5. Tap **Check Status** — file should show `Asymmetric 0x01` (sweep is disabled)
6. Tap the file entry to decrypt and verify the plaintext
