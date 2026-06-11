#!/usr/bin/env python3
import subprocess
import struct
import sys

# Patterns to search for
# Keystore2 CBOR wrapped pattern: 0x58 0x20 followed by (0x48 0x04) * 16
KEYSTORE2_PATTERN = bytes.fromhex("58204804480448044804480448044804480448044804480448044804480448044804")

# Raw key pattern: (0x48 0x04) * 16
RAW_KEY_PATTERN = bytes.fromhex("4804480448044804480448044804480448044804480448044804480448044804")

def find_patterns():
    print("[*] Reading /proc/kcore ELF header via adb...")
    cmd_header = ["adb", "exec-out", "dd if=/proc/kcore bs=4096 count=4 2>/dev/null"]
    try:
        header = subprocess.check_output(cmd_header)
    except Exception as e:
        print(f"[!] Failed to run adb: {e}")
        sys.exit(1)

    if header[:4] != b'\x7fELF':
        print("[!] Error: Not a valid ELF file. Make sure 'adb root' is run and kcore access is enabled.")
        sys.exit(1)

    e_phoff = struct.unpack_from("<Q", header, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", header, 0x36)[0]
    e_phnum = struct.unpack_from("<H", header, 0x38)[0]

    candidates = []
    for i in range(e_phnum):
        ph_start = e_phoff + (i * e_phentsize)
        p_type = struct.unpack_from("<I", header, ph_start)[0]
        if p_type == 1: # PT_LOAD
            p_offset = struct.unpack_from("<Q", header, ph_start + 0x08)[0]
            p_filesz = struct.unpack_from("<Q", header, ph_start + 0x20)[0]
            size_gb = p_filesz / (1024**3)
            # Find candidate physical memory segment
            if 1.0 < size_gb <= 16.0:
                candidates.append((i, p_offset, p_filesz, size_gb))

    if not candidates:
        print("[!] No physical memory segment found.")
        sys.exit(1)

    # Auto-select the target segment (largest segment)
    best_match = max(candidates, key=lambda x: x[2])
    target_index, target_offset, target_size, size_gb = best_match
    print(f"[*] Selected memory segment Index [{target_index}] with size {size_gb:.2f} GB (Offset: 0x{target_offset:x})")

    # We will use bs=1M. We calculate skip and count in MB.
    skip_mb = target_offset // (1024 * 1024)
    count_mb = target_size // (1024 * 1024)

    print(f"[*] Streaming {size_gb:.2f} GB of physical memory and scanning for patterns on-the-fly...")
    print(f"[*] Command: adb exec-out \"dd if=/proc/kcore bs=1M skip={skip_mb} count={count_mb} 2>/dev/null\"")

    stream_cmd = ["adb", "exec-out", f"dd if=/proc/kcore bs=1M skip={skip_mb} count={count_mb} 2>/dev/null"]
    
    proc = subprocess.Popen(stream_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    buffer = bytearray()
    chunk_size = 1024 * 1024 # 1MB chunks
    bytes_scanned = 0
    keystore2_count = 0
    raw_key_count = 0

    # To handle patterns crossing block boundaries, we keep a small overlap.
    overlap_size = 64

    try:
        while True:
            chunk = proc.stdout.read(chunk_size)
            if not chunk:
                break
            
            buffer.extend(chunk)
            
            # Scan in the buffer
            # Find Keystore2 pattern
            offset = 0
            while True:
                idx = buffer.find(KEYSTORE2_PATTERN, offset)
                if idx == -1 or idx >= len(buffer) - overlap_size:
                    break
                abs_offset = target_offset + bytes_scanned + idx
                print(f"[!] Found Keystore2 CBOR wrapped key at physical offset: 0x{abs_offset:x}")
                keystore2_count += 1
                offset = idx + len(KEYSTORE2_PATTERN)

            # Find Raw Key pattern (standalone)
            offset = 0
            while True:
                idx = buffer.find(RAW_KEY_PATTERN, offset)
                if idx == -1 or idx >= len(buffer) - overlap_size:
                    break
                # Check if it was already matched by the Keystore2 pattern (preceded by 5820)
                if idx >= 2 and buffer[idx-2:idx] == b'\x58\x20':
                    # Yes, this is part of the Keystore2 pattern, skip counting it separately
                    pass
                else:
                    abs_offset = target_offset + bytes_scanned + idx
                    print(f"[!] Found Raw Key pattern (standalone) at physical offset: 0x{abs_offset:x}")
                    raw_key_count += 1
                offset = idx + len(RAW_KEY_PATTERN)

            bytes_scanned += len(buffer) - overlap_size
            buffer = buffer[-(overlap_size):]

            # Print progress every 1GB
            if (bytes_scanned // (1024*1024*1024)) > ((bytes_scanned - len(chunk)) // (1024*1024*1024)):
                scanned_gb = bytes_scanned / (1024*1024*1024)
                print(f"Scanned {scanned_gb:.1f} GB...")

    except KeyboardInterrupt:
        print("[*] Scan interrupted by user.")
        proc.terminate()
        sys.exit(1)

    print("\n[*] Scan complete.")
    print(f"Total Keystore2 CBOR wrapped instances: {keystore2_count}")
    print(f"Total Raw Key (standalone) instances: {raw_key_count}")

if __name__ == '__main__':
    find_patterns()
