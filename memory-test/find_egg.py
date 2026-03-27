import mmap

# Pattern to search for: 32 bytes of 0x48 0x04 repeated 16 times
pattern = b'\x48\x04' * 16
filename = "main_ram_6gb.dump"

print(f"[*] Searching for the specific DEK pattern in {filename}...")

with open(filename, "rb") as f:
    # Memory-map the 6GB file (extremely fast and memory-efficient)
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    offset = 0
    count = 0
    while (offset := mm.find(pattern, offset)) != -1:
        count += 1
        print(f"[!] Found! Absolute offset: {offset} (Hex: 0x{offset:x})")
        offset += 1

print(f"[*] Search complete. Total {count} instances found.")