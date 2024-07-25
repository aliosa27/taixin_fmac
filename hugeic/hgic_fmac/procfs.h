
#ifndef _HGICF_PROCFS_H_
#define _HGICF_PROCFS_H_

#ifdef __RTOS__
struct hgicf_procfs {};
#define hgicf_create_procfs(hg)
#define hgicf_delete_procfs(hg)

#else

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

struct hgicf_wdev;

#define HGIC_TESTMODE_BUFF_SIZE (4096)
struct hgicf_procfs {
    struct proc_dir_entry *rootdir;
    struct proc_dir_entry *status;
    struct proc_dir_entry *ota;
    struct proc_dir_entry *iwpriv;
    u8                     iwpriv_buf[4096];
    u32                    iwpriv_result;
    struct proc_dir_entry *fwevent;
};

void hgicf_create_procfs(struct hgicf_wdev *hg);
void hgicf_delete_procfs(struct hgicf_wdev *hg);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,36)
static inline struct proc_dir_entry *PDE(const struct inode *inode)
{
    return PROC_I(inode)->pde;
}
static inline void *PDE_DATA(const struct inode *inode)
{
    return PDE(inode)->data;
}
#endif

#endif

#endif

