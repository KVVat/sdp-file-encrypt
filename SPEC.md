# SDP File Write/Read Library Design Note

**Agent:** Kouki Watanabe

---

## 1. Introduction

### 1.1 Goal and Scope
The primary goal of this project is to simplify and modernize the handling of sensitive data protection (SDP) file I/O.

### 1.2 Audience
Internal and the collaborative vendors.

### 1.3 Definitions and Acronyms
- **SDP:** Sensitive Data Protection

---

## 2. Background and Motivation

### 2.1 Problem Statement
The existing solution for handling sensitive data protection files I/O is based on a raw level and legacy implementation. This architecture has resulted in:
- Code fragmentation and complexity
- Lack of Standardization
- Platform Integration issues.

### 2.2 Justification
- Provide a standardized way to read/write SDP files on the Android OS.
- It can support the NIAP standard in a high-level and secure manner.
- We will base on the Google Tink Library, and leverage the Android Keystore (Hardware Backed Keystore).
  - [Google Tink Library](https://github.com/tink-crypto/tink)
- It's not the fastest way but difficult to crack.
- Tink supports streaming files and use cases.

### 2.3 Requirements
- **OS:** Android OS SDK level 32
- Must handle files < 2GB
- Supports encryption on locked devices.

### 2.4 Schedule
- **Prototyping:** 2 weeks (+1 week).
- **Documentation:** 1 week.

---

## 3. High-Level Design and Architecture

### 3.1 System Context
The library can be included from Gradle settings and initially placed on GitHub packages.

### 3.2 Architectural Overview
- Provide a Custom `KeyManager` for Tink.
- Use `AES256_GCM` for Encryption and Decryption.
- The encryption file header style will follow [RFC 9580 (OpenPGP)](https://www.rfc-editor.org/rfc/rfc9580.html).
- Currently, the `NISAPSEC` library doesn’t follow any standard and it does not support file moves.
- Use the Envelope Encryption technique.
- We shouldn’t generate a key for each file, if we consider we should maintain thousands of the keys.
- To support file moves and name changes, the encrypted file should hold a UUID in the Notation Data section in the packet.

#### Packet Structure
```
[Signature Packet (Tag 2)]  <-- Contains Metadata of File
[Packet Header]
-> Version: 2
-> Symmetric-key Algorithm ID: (e.g., AES-256 is 9)
-> AEAD Algorithm ID: (e.g., GCM is 1)
-> Chunk Size: (Size parameter for incremental decryption)
[IV / Nonce]
-> (e.g., 12 bytes for AES-GCM)
[Encrypted Data]
-> (The ciphertext broken into chunks)
[Authentication Tag]
-> (The MAC tag to verify data integrity)
```

#### Envelope Encryption
**Encryption:**
1.  Generate a random DEK.
2.  Encrypt the file content using the DEK.
3.  Encrypt (wrap) the DEK itself using the Master Key from the KeyStore.

**Storage:**
- The Encrypted DEK (Wrapped DEK) is embedded directly into the file's metadata (e.g., in a PKESK/SKESK packet under RFC 9580).

**Decryption:**
1.  Extract the Wrapped DEK from the file.
2.  Use the Master Key in the KeyStore to decrypt the Wrapped DEK and retrieve the original DEK.
3.  Decrypt the file content using the DEK.

### 3.3 Key Design Decisions
- **Language:** Java, Android SDK
- **Encryption method:** `AES256_GCM` by default
- **Key Storage:** All keys are stored in AndroidKeyStore (Hardware Key Storage)


