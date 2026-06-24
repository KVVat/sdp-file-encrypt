import sys

def parse_protobuf_keyset(data):
    # Extremely simple, lightweight Protobuf parser for Tink keyset.
    # It scans for wire type 2 (length-delimited) with Tink type URLs.
    idx = 0
    while idx < len(data):
        # Look for the type URL string in the buffer
        tink_type = b"type.googleapis.com/"
        type_idx = data.find(tink_type, idx)
        if type_idx == -1:
            break
        
        # Determine length of the type URL string
        # Typically the byte before the string is the length (Tink type URLs are ~50-80 chars, fits in 1 byte)
        str_len = data[type_idx - 1]
        type_url = data[type_idx : type_idx + str_len].decode('utf-8', errors='ignore')
        
        print(f"    -> Found Tink Key Type URL: {type_url}")
        
        # Scan forward for GCM key or Elliptic Curve private bytes
        # Tink AesGcmKey has structure: version (uint32), value (bytes)
        # We can search for the raw 16-byte or 32-byte key material following it
        if "AesGcmKey" in type_url:
            # Look for 32-byte high-entropy blocks
            gcm_offset = type_idx + str_len
            # In Protobuf, the GCM key bytes are prepended by wire tag and length
            # Let's search for wire tag 0x12 (tag 2, length-delimited)
            val_tag_idx = data.find(b"\x12", gcm_offset, gcm_offset + 10)
            if val_tag_idx != -1:
                val_len = data[val_tag_idx + 1]
                if val_len in [16, 32]: # 128-bit or 256-bit key
                    key_bytes = data[val_tag_idx + 2 : val_tag_idx + 2 + val_len]
                    print(f"       [!] Leaked AES Key ({val_len*8} bits): {key_bytes.hex()}")
        
        elif "EciesAeadHkdfPrivateKey" in type_url:
            # ECIES Private Key contains EC private key bytes (D value)
            # Typically 32 bytes for NIST P-256 curve
            ec_offset = type_idx + str_len
            # Let's search for wire tag 0x1a or similar, or just dump the next 32-byte block
            # For P-256, D is 32 bytes.
            # Let's find the D value wire tag. In Tink ECIES Private Key, D is field 2 (wire tag 0x12) or similar.
            pass
            
        idx = type_idx + str_len

def main():
    dump_filename = "scratch/keymint_heap.dump"
    print(f"[*] Reading {dump_filename}...")
    with open(dump_filename, "rb") as f:
        data = f.read()

    # CBOR array pattern matching: [0, [[50, [serialized_tink_keyset]]]]
    # CBOR bytes: 
    # 82 (array, 2 elements)
    # 00 (unsigned int 0)
    # 81 (array, 1 element)
    # 82 (array, 2 elements)
    # 18 32 (unsigned int 50)
    # 81 (array, 1 element)
    # 59 (byte string, 2-byte length)
    target_cbor = bytes.fromhex("8200818218328159")

    print(f"[*] Scanning for Android Keystore CBOR KeyBlob headers in RAM...")
    
    offset = 0
    count = 0
    while True:
        offset = data.find(target_cbor, offset)
        if offset == -1:
            break
        
        count += 1
        print(f"\n[!!!] CBOR KEYBLOB CONTAINER DETECTED AT OFFSET: 0x{offset:x}")
        
        # Read the CBOR byte string length (next 2 bytes)
        len_bytes = data[offset + len(target_cbor) : offset + len(target_cbor) + 2]
        cbor_val_len = (len_bytes[0] << 8) | len_bytes[1]
        print(f"    - CBOR Payload Size: {cbor_val_len} bytes")
        
        # Extract the serialized Tink keyset payload
        payload_start = offset + len(target_cbor) + 2
        payload_bytes = data[payload_start : payload_start + cbor_val_len]
        
        # Print first 64 bytes of the payload in hex
        print(f"    - CBOR Payload Header (Hex): {payload_bytes[:32].hex()}...")
        
        # Parse the embedded protobuf keyset
        parse_protobuf_keyset(payload_bytes)
        
        offset += len(target_cbor)

    print(f"\n[*] Scan complete. Found {count} instances of CBOR KeyBlobs in heap.")

if __name__ == '__main__':
    main()
