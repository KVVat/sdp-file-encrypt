import sys

def main():
    dump_filename = "scratch/keymint_heap.dump"
    print(f"[*] Reading {dump_filename}...")
    with open(dump_filename, "rb") as f:
        data = f.read()

    targets = [
        b"type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
        b"type.googleapis.com/google.crypto.tink.AesGcmKey"
    ]

    for target in targets:
        print(f"\n[*] Searching for '{target.decode()}'...")
        offset = 0
        while True:
            offset = data.find(target, offset)
            if offset == -1:
                break
            
            print(f"\n[!!!] MATCH FOUND AT OFFSET: 0x{offset:x}")
            
            # Print hex dump of 256 bytes around the match
            start_dump = max(0, offset - 64)
            end_dump = min(len(data), offset + 192)
            chunk = data[start_dump:end_dump]
            
            print(f"--- Hex Dump around offset 0x{start_dump:x} ---")
            for i in range(0, len(chunk), 16):
                line_bytes = chunk[i:i+16]
                hex_str = " ".join(f"{b:02x}" for b in line_bytes)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in line_bytes)
                print(f"0x{start_dump + i:08x}: {hex_str:<48} |{ascii_str}|")
                
            offset += len(target)

if __name__ == '__main__':
    main()
