import subprocess
import re
import sys

def run_adb_cmd(cmd):
    # Runs adb shell command as root
    full_cmd = ["adb", "shell", f"su 0 {cmd}"]
    result = subprocess.run(full_cmd, capture_output=True)
    return result.stdout, result.stderr

def main():
    print("[*] Setting SELinux to Permissive...")
    run_adb_cmd("setenforce 0")

    print("[*] Finding PID of android.hardware.security.keymint-service.rust.trusty...")
    stdout, _ = run_adb_cmd("ps -A | grep keymint-service.rust.trusty")
    lines = stdout.decode('utf-8').strip().split('\n')
    if not lines or not lines[0]:
        print("[!] KeyMint Rust service not found!")
        sys.exit(1)
    
    parts = re.split(r'\s+', lines[0])
    pid = parts[1]
    print(f"[+] Found KeyMint Rust service PID: {pid}")

    print(f"[*] Reading /proc/{pid}/maps...")
    maps_out, _ = run_adb_cmd(f"cat /proc/{pid}/maps")
    maps_lines = maps_out.decode('utf-8').strip().split('\n')

    rw_segments = []
    for line in maps_lines:
        if not line:
            continue
        if "rw-p" in line:
            parts = re.split(r'\s+', line)
            addr_range = parts[0]
            start, end = addr_range.split('-')
            name = parts[-1] if len(parts) > 5 else "[anonymous]"
            rw_segments.append((start, end, name))

    print(f"[+] Found {len(rw_segments)} writable (rw-p) memory segments.")

    PAGE_SIZE = 4096
    combined_dump = bytearray()

    for start, end, name in rw_segments:
        start_dec = int(start, 16)
        end_dec = int(end, 16)
        
        start_aligned = (start_dec // PAGE_SIZE) * PAGE_SIZE
        end_aligned = ((end_dec + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE
        pages_count = (end_aligned - start_aligned) // PAGE_SIZE
        
        if pages_count * PAGE_SIZE > 20 * 1024 * 1024: 
            continue
            
        dump_cmd = f"dd if=/proc/{pid}/mem bs=4096 skip={start_aligned // PAGE_SIZE} count={pages_count} 2>/dev/null"
        segment_bytes, _ = run_adb_cmd(dump_cmd)
        
        if segment_bytes:
            combined_dump.extend(segment_bytes)

    dump_filename = "scratch/keymint_heap.dump"
    print(f"[*] Writing {len(combined_dump)} bytes of KeyMint RAM to {dump_filename}...")
    with open(dump_filename, "wb") as f:
        f.write(combined_dump)

    print("[+] Dump complete! Running string analysis on the dump...")
    
    # Simple ASCII string extractor (min 4 chars)
    ascii_strings = []
    current_str = []
    for b in combined_dump:
        if 32 <= b < 127:
            current_str.append(chr(b))
        else:
            if len(current_str) >= 4:
                ascii_strings.append("".join(current_str))
            current_str = []
            
    print(f"[+] Found {len(ascii_strings)} ASCII strings in KeyMint RAM.")
    print("--- Sample Strings (first 50) ---")
    for s in ascii_strings[:50]:
        print(f"  {s}")

    # Search for any string containing part of the package name
    interesting = [s for s in ascii_strings if "niap" in s.lower() or "sec" in s.lower() or "key" in s.lower()]
    if interesting:
        print("\n--- Interesting Strings Found ---")
        for s in interesting:
            print(f"  [!] {s}")

if __name__ == '__main__':
    main()
