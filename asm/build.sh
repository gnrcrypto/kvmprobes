#!/bin/bash

# KVM Prober - Simple Build Script
# Compiles C and ASM files in current directory

set -e

echo "[*] Building KVM Prober..."

# Compile C version
if [ -f "kvm_prober.c" ]; then
    echo "[*] Compiling kvm_prober.c..."
    gcc -O2 -Wall -Wextra -no-pie kvm_prober.c -o kvm_prober
    chmod +x kvm_prober
    echo "[✓] Built: kvm_prober"
else
    echo "[-] kvm_prober.c not found"
fi

# Compile ASM version
if [ -f "kvm_prober_asm.nasm" ]; then
    echo "[*] Assembling kvm_prober_asm.nasm..."
    nasm -f elf64 -o kvm_prober_asm.o kvm_prober_asm.nasm
    ld -o kvm_prober_asm kvm_prober_asm.o
    rm kvm_prober_asm.o
    chmod +x kvm_prober_asm
    echo "[✓] Built: kvm_prober_asm"
else
    echo "[-] kvm_prober_asm.nasm not found"
fi

echo "[✓] Build complete!"
ls -lh kvm_prober* 2>/dev/null || echo "[-] No binaries found"
