#ifndef SPIN_H
#define SPIN_H
#define DEVICE_NAME "spindrv"
#define CLASS_NAME "spin"

#ifdef __KERNEL__

#ifdef CONFIG_KUSP_SPIN_DSKI
#include <linux/kusp/dski.h>
#define SPIN_DEBUG(fmt, args...) DSTRM_DEBUG(SPIN, DEBUG, fmt, ## args)
#else
#define SPIN_DEBUG(fmt, args...) 
#endif /* CONFIG_KUSP_SPIN_DSKI */


#endif /* __KERNEL__*/

typedef unsigned long long u64;

typedef struct spindrv_ioctl_inc_s {
    u64 dma_addr;
    unsigned size;
    void* addr, * addr_virt, *addr_phys, *key;
} spindrv_ioctl_inc_t;

typedef struct spindrv_ioctl_pread {
    ssize_t read_return;
    int fd;
    void* buf;
    size_t count;
    off_t offset;
    void* m_pDBuffer;
    int o_d;
} spindrv_ioctl_pread_t;

typedef union spindrv_ioctl_param_u {
    spindrv_ioctl_inc_t set;
    spindrv_ioctl_pread_t readArgs;
} spindrv_ioctl_param_union;


#define SPIN_MAGIC 't'

#define SPIN_IOCTL_NEW_BUFFER    _IOW(SPIN_MAGIC, 1, int)
#define SPIN_IOCTL_REMOVE    _IOW(SPIN_MAGIC, 2, int)
#define SPIN_IOCTL_READ    _IOW(SPIN_MAGIC, 3, int)
#define SPIN_IOCTL_READ_O    _IOW(SPIN_MAGIC, 4, int)


#endif /* SPIN_H */

