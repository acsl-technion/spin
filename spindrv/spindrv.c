#include <linux/init.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/hash.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>
#include <linux/interval_tree_generic.h>
#include "spindrv.h"
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/mmu_notifier.h>
#include <linux/radix-tree.h>

#define RAV 1024*1024                /* Max size to consider PC RA (Bytes)  */
#define CONS 256                     /* Minimum streak of PC read (Pages)   */
#define RAPC 512                     /* Size of PC (Pages)                  */
#define RAWM 128                     /* Low PC water mark diff (Pages)      */
#define RING_SIZE 12*1024*1024  

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define RING_SIZE_PAGES DIV_ROUND_UP(RING_SIZE, 4096) + 1
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

SETPAGEFLAG(f, arch_1)
CLEARPAGEFLAG(f, arch_1)

static int major_number;
static struct class* spindrv_class = NULL;
static struct device* spindrv_device = NULL;
static int only_p2p = 0;
static int disable_ra_pc = 0;
struct cache_lru;
static unsigned long curr_pc = 0;

struct file_operations orig_ops;
const struct file_operations *orig_ops_ptr;
ssize_t(*orig_read) (struct file *, char __user *, size_t, loff_t *);

module_param(only_p2p, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(disable_ra_pc, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

struct files_fd {
	unsigned int tgid;
	int fd;
	void* mdata;
	struct list_head list;
};

struct pid_pages {
	unsigned int pid;
	int count;
	struct page ** pages;
	unsigned long length;
	struct mm_struct* mm;
	struct list_head list;
};

struct fd_priv;

struct cache_lru {
	struct address_space *f_mapping;
	unsigned long offset;
	unsigned long length;
	struct list_head list;
	struct fd_priv* pfd;
};

struct gpu_mappings {
	unsigned int pid;
	unsigned int tgida;
	int line;
	void* gpu_addr;
	void* key;
	void* virt_addr;
	unsigned long length;
	struct list_head list;
};

struct pdev {
	unsigned int major;
	struct list_head list;
};

struct fd_priv {
	spinlock_t fdal;
	struct radix_tree_root mypc_tree;
	unsigned long p2p;
	unsigned long last_offset;
	struct cache_lru* current_l;
	struct file myfile;
};

static struct pid_pages pid_pages_list;
static struct files_fd files_fd_list;
static spinlock_t fd_listlock;

static spinlock_t listlock;
static int m_ringSize = DIV_ROUND_UP(RING_SIZE, 4096) + 1;
static spinlock_t checklock;

static struct gpu_mappings gpu_mappings_list;
static spinlock_t gpu_listlock;

static struct cache_lru cache_lru_list;
static spinlock_t caches_lru_listlock;

static struct pdev pdev_list;
static spinlock_t pdev_listlock;

static u64 get_dma(u64* helper)
{
	struct gpu_mappings* gpu_mapping;
	struct list_head *pos, *pos2;
	void* temp;
	u64 length;
	int line = -1;

	spin_lock(&gpu_listlock);

	list_for_each(pos2, &(gpu_mappings_list.list))
	{
		gpu_mapping = list_entry(pos2, struct gpu_mappings, list);
		if (gpu_mapping->pid == current->pid) {
			line = gpu_mapping->line;
		}
	}

	if (line != -1) {
		length = helper[2 * line];

		list_for_each(pos, &(gpu_mappings_list.list))
		{
			gpu_mapping = list_entry(pos, struct gpu_mappings, list);
			if (gpu_mapping->key == (void*) helper[2 * line + 1] &&
				length <= gpu_mapping->length && length >= 0) {
				temp = gpu_mapping->gpu_addr;
				spin_unlock(&gpu_listlock);
				return(u64) ((u64) (temp) + (u64) (length));
			}
		}
	}

	spin_unlock(&gpu_listlock);
	return 0;
}
EXPORT_SYMBOL(get_dma);

static void recalc_pc(void)
{
	struct cache_lru* ce;
	struct list_head *pos;
	unsigned long temp_pc;

	temp_pc = 0;
	spin_lock(&caches_lru_listlock);

	list_for_each(pos, &(cache_lru_list.list))
	{
		ce = list_entry(pos, struct cache_lru, list);
		temp_pc += ce->length;
	}

	curr_pc = temp_pc;
	spin_unlock(&caches_lru_listlock);
}

static void remove_from_rt(struct radix_tree_root * rt, unsigned long size,
	unsigned long offset)
{
	int i;
	for (i = offset; i < size + offset; i++)
		radix_tree_delete(rt, i);
}

static void remove_mypc(struct address_space *f_mapping, size_t count,
	off_t offset)
{
	int curr_page, vpages, start_index, end_index;

	curr_page = 0;
	vpages = 0;
	start_index = offset;
	end_index = offset + count;

	invalidate_mapping_pages(f_mapping, start_index, end_index);
	return;
}

static void maintain_pc(void)
{
	struct list_head *pos, *q;
	unsigned long to_remove, cur_rem, cur_off;
	struct address_space * cur_mapping;
	struct cache_lru* ce;

	to_remove = RAWM + curr_pc - (RAPC);

	spin_lock(&caches_lru_listlock);

	list_for_each_safe(pos, q, &(cache_lru_list.list))
	{
		ce = list_entry(pos, struct cache_lru, list);
		cur_mapping = ce->f_mapping;
		cur_off = ce->offset;

		if (ce->length < to_remove) {
			ce->pfd->current_l = NULL;
			to_remove -= ce->length;
			cur_rem = ce->length;
			remove_from_rt(&(ce->pfd->mypc_tree), cur_rem, cur_off);
			list_del(pos);
			kfree(ce);
			remove_mypc(cur_mapping, cur_rem, cur_off);
		} else {
			cur_rem = to_remove;
			ce->offset += to_remove;
			ce->length -= to_remove;
			remove_from_rt(&(ce->pfd->mypc_tree), cur_rem, cur_off);
			remove_mypc(cur_mapping, cur_rem, cur_off);
			break;
		}
	}
	curr_pc = RAPC - RAWM;
	spin_unlock(&caches_lru_listlock);
}

static struct cache_lru* add_my_lru(struct address_space *f_mapping, int* ubuffer,
	unsigned long ubuffer_size, size_t offset, loff_t count, struct fd_priv* pfd)
{
	struct cache_lru* ce;
	ce = (struct cache_lru*) kmalloc(sizeof(struct cache_lru), GFP_KERNEL);

	ce->offset = offset;
	ce->f_mapping = f_mapping;
	ce->pfd = pfd;
	ce->length = count;

	INIT_LIST_HEAD(&ce->list);
	list_add_tail(&(ce->list), &(cache_lru_list.list));

	return ce;
}

static void* get_key(void* addr, int pid, unsigned long *offset, int* line)
{
	struct gpu_mappings* gpu_mapping;
	struct list_head *pos;
	void* myret;

	spin_lock(&gpu_listlock);

	list_for_each(pos, &(gpu_mappings_list.list))
	{
		unsigned long gpu_virt;
		unsigned long addr_ul;

		gpu_mapping = list_entry(pos, struct gpu_mappings, list);
		gpu_virt = (unsigned long) gpu_mapping->virt_addr;
		addr_ul = (unsigned long) addr;

		if (addr_ul >= gpu_virt &&
			addr_ul <= gpu_virt + gpu_mapping->length &&
			pid == gpu_mapping->pid) {
			*offset = addr_ul - gpu_virt;
			*line = gpu_mapping->line;
			myret = gpu_mapping->key;
			spin_unlock(&gpu_listlock);
			return myret;
		}
	}
	spin_unlock(&gpu_listlock);
	return NULL;
}

static void add_device(int major)
{
	struct pdev* mypdev;
	mypdev = (struct pdev *) kmalloc(sizeof(struct pdev), GFP_KERNEL);

	mypdev->major = major;

	spin_lock(&pdev_listlock);
	INIT_LIST_HEAD(&mypdev->list);
	list_add_tail(&(mypdev->list), &(pdev_list.list));
	spin_unlock(&pdev_listlock);

}
EXPORT_SYMBOL(add_device);

static void remove_device(int major)
{
	struct list_head *pos, *q;
	struct pdev* mypdev;

	spin_lock(&pdev_listlock);

	list_for_each_safe(pos, q, &(pid_pages_list.list))
	{
		mypdev = list_entry(pos, struct pdev, list);
		if (mypdev->major == major) {
			list_del(pos);
			kfree(mypdev);
		}
	}
	spin_unlock(&pdev_listlock);
}
EXPORT_SYMBOL(remove_device);

static int check_device(int major)
{
	struct pdev* mypdev;
	struct list_head *pos;
	spin_lock(&pdev_listlock);

	list_for_each(pos, &(pdev_list.list))
	{
		mypdev = list_entry(pos, struct pdev, list);
		if (mypdev->major == major) {
			spin_unlock(&pdev_listlock);
			return 1;
		}
	}
	spin_unlock(&pdev_listlock);
	return 0;
}

static ssize_t my_read(struct fd f, void* buf, size_t count, loff_t offset,
	int o_direct)
{
	ssize_t ret;
	void* f_priv;

	ret = -EBADF;
	if (offset < 0) {
		return -EINVAL;
	}

	ret = -ESPIPE;
	f_priv = f.file->private_data;
	if ((f.file)->f_mode & FMODE_PREAD) {
		if (o_direct == 1) {
			ret = vfs_read(&(((struct fd_priv *) (f_priv))->myfile),
				buf, count, &offset);
		} else {
			ret = vfs_read(f.file, buf, count, &offset);
		}
	}

	if ((unsigned long) (f_priv) != 1 && (unsigned long) (f_priv) != 0) {
		((struct fd_priv *) (f_priv))->last_offset = offset + count;
	}

	if (curr_pc > RAPC && !disable_ra_pc) {
		maintain_pc();
	}

	return ret;
}
EXPORT_SYMBOL(my_read);

static int spindrv_open(struct inode *inode, struct file *file)
{
	struct task_struct *t;
	struct pid_pages* pid_page;
	t = current;
	do {

		list_for_each_entry(pid_page, &(pid_pages_list.list), list)
		{
			if (pid_page->pid == t->tgid) {
				return -1;
			}
		}
		t = t->parent;
	} while (t->pid != 0);


	return 0;
}

static int spindrv_close(struct inode *inode, struct file *file)
{
	return 0;
}

static void spindrv_remove(int pid, struct mm_struct* mm)
{
	struct list_head *pos, *q, *pos2, *q2, *pos3, *q3, *pos4, *q4;
	int j;
	struct pid_pages* pid_page;
	struct gpu_mappings* gpu_mapping;
	struct files_fd* filefd;
	struct cache_lru* ce;

	spin_lock(&listlock);

	list_for_each_safe(pos, q, &(pid_pages_list.list))
	{
		pid_page = list_entry(pos, struct pid_pages, list);
		if (((mm != NULL) && mm == pid_page->mm) || (mm == NULL &&
			(pid == pid_page->pid))) {
			for (j = 0; j < pid_page->count; j++) {
				ClearPagef(pid_page->pages[j]);
				put_page(pid_page->pages[j]);
			}

			if (pid == 0) {
				pid = pid_page->pid;
			}
			kfree(pid_page->pages);
			list_del(pos);
			kfree(pid_page);
		}
	}

	spin_unlock(&listlock);

	spin_lock(&gpu_listlock);

	list_for_each_safe(pos2, q2, &(gpu_mappings_list.list))
	{
		gpu_mapping = list_entry(pos2, struct gpu_mappings, list);
		if (pid == gpu_mapping->tgida) {
			list_del(pos2);
			kfree(gpu_mapping);
		}
	}

	spin_unlock(&gpu_listlock);

	spin_lock(&fd_listlock);

	list_for_each_safe(pos3, q3, &(files_fd_list.list))
	{
		struct fd f;
		struct fd_priv * t_mdata;
		struct file* mf_t;

		filefd = list_entry(pos3, struct files_fd, list);
		t_mdata = (struct fd_priv *) filefd->mdata;
		mf_t = (struct file *) &t_mdata->myfile;

		if (pid == filefd->tgid) {
			if (!disable_ra_pc) {

				spin_lock(&caches_lru_listlock);

				list_for_each_safe(pos4, q4, &(cache_lru_list.list))
				{
					ce = list_entry(pos4, struct cache_lru, list);
					if (mf_t->f_mapping == ce->f_mapping) {
						list_del(pos4);
						kfree(ce);
					}
				}
				spin_unlock(&caches_lru_listlock);
			}

			recalc_pc();
			list_del(pos3);

			f = fdget(filefd->fd);
			if (f.file) {
				if (f.file->f_inode != NULL) {
					if (!disable_ra_pc) {
						f.file->f_inode->i_fop = orig_ops_ptr;
					}
					f.file->f_inode->i_private = NULL;
				}
				fdput(f);
			}

			kfree(t_mdata);
			kfree(filefd);
		}
	}
	spin_unlock(&fd_listlock);
}

static void spindrv_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	spindrv_remove(0, mm);
}

static const struct mmu_notifier_ops no_ops = {
	.release = spindrv_release,
};

static struct mmu_notifier notify = {
	.ops = &no_ops,
};

static void* translate_virt(void* addr_virt, struct mm_struct *mm,
	unsigned long * length, void** virt_start)
{
	struct vm_area_struct *vma = NULL;
	unsigned long pfn;
	if (addr_virt) {
		vma = find_vma(mm, (unsigned long) (addr_virt));
		if (!vma || !(vma->vm_flags & VM_PFNMAP)) {
			return NULL;
		}

		if (follow_pfn(vma, (unsigned long) (vma->vm_start), &pfn)) {
			return NULL;
		}

		*length = (vma->vm_end - vma->vm_start);
		*virt_start = (void*) vma->vm_start;

		return(void*) (pfn << PAGE_SHIFT);

	} else {
		return NULL;
	}
}

static int get_mypc(struct fd f, size_t count, off_t offset, int* ubuffer)
{
	int curr_page, my_num_pages, vpages;
	struct page* mypage;

	mypage = NULL;
	curr_page = 0;
	vpages = 0;
	my_num_pages = DIV_ROUND_UP(count + (offset % PAGE_SIZE), PAGE_SIZE);

	while (curr_page < my_num_pages) {
		mypage = find_get_page(f.file->f_mapping, curr_page + (offset / PAGE_SIZE));
		if (mypage) {
			ubuffer[curr_page] = 1;
			vpages++;
			put_page(mypage);
		}
		curr_page++;
	}

	return(vpages * 100) / my_num_pages;
}

static void * add_gpu_mapping(void* addr_virt, void* addr_phys,
	unsigned long length, int* line)
{
	struct gpu_mappings* gpu_mapping, *gpu_mapping2;
	int newLine, outflag, outflag2;
	struct list_head *pos, *pos2;
	void* tgpu_addr, *tkey, *tvirt_addr, *tempret;

	newLine = 0;
	outflag = 0;
	outflag2 = 0;

	spin_lock(&gpu_listlock);

	list_for_each(pos2, &(gpu_mappings_list.list))
	{
		gpu_mapping2 = list_entry(pos2, struct gpu_mappings, list);
		if ((u64) (gpu_mapping2->gpu_addr) <= (u64) (addr_phys) &&
			(u64) (addr_phys) < (u64) ((u64) (gpu_mapping2->gpu_addr) + (u64) (length))) {
			tgpu_addr = gpu_mapping2->gpu_addr;
			tvirt_addr = gpu_mapping2->virt_addr;
			tkey = gpu_mapping2->key;
			outflag2 = 2;
		}
		if (gpu_mapping2->line == newLine && gpu_mapping2->pid == current->pid) {
			newLine = gpu_mapping2->line;
			outflag = 1;
		}
	}

	if (!outflag) {
		while (true) {
			int inflag = 0;

			list_for_each(pos, &(gpu_mappings_list.list))
			{
				gpu_mapping2 = list_entry(pos, struct gpu_mappings, list);

				if (gpu_mapping2->line == newLine &&
					gpu_mapping2->tgida == current->tgid) {
					newLine++;
					inflag = 1;
				}
			}
			if (!inflag) {
				break;
			}
		}
	}

	if (addr_phys == NULL || addr_virt == NULL) {
		return NULL;
	}

	gpu_mapping = (struct gpu_mappings *) kmalloc(sizeof(struct gpu_mappings), GFP_KERNEL);

	gpu_mapping->length = length;
	gpu_mapping->pid = current->pid;
	gpu_mapping->line = newLine;
	gpu_mapping->tgida = current->tgid;

	if (outflag2 == 2) {
		gpu_mapping->gpu_addr = tgpu_addr;
		gpu_mapping->virt_addr = tvirt_addr;
		gpu_mapping->key = tkey;
	} else {
		gpu_mapping->gpu_addr = addr_phys;
		gpu_mapping->virt_addr = addr_virt;
		get_random_bytes(&(gpu_mapping->key), sizeof(gpu_mapping->key));
	}

	INIT_LIST_HEAD(&gpu_mapping->list);
	list_add_tail(&(gpu_mapping->list), &(gpu_mappings_list.list));
	tempret = gpu_mapping->key;
	spin_unlock(&gpu_listlock);
	*line = newLine;
	return tempret;
}

static ssize_t ring_read(struct fd f, void* dest, size_t sizeBytes, off_t offset,
	void* m_destKey, int line, void *m_pDBuffer)
{
	long origSize = sizeBytes;
	long readOffsetBytes = 0;

	if (origSize < 512 || origSize % 512 != 0 || offset % 512 != 0) {
		return 0;
	}

	while (sizeBytes > 0) {
		unsigned long destPage = (unsigned long) dest & ((unsigned long) (~0xFFF));
		unsigned long destOffset = (unsigned long) dest & ((unsigned long) 0xFFF);
		int readSize;
		long readSizeBytes = sizeBytes; //This iterations read size
		int rett, j;

		if (sizeBytes + destOffset > m_ringSize * 4096) {
			readSizeBytes = m_ringSize * 4096 - destOffset;
		}

		if (sizeBytes - readSizeBytes < 512 && sizeBytes - readSizeBytes > 0) {
			continue;
		}

		readSize = DIV_ROUND_UP(readSizeBytes + destOffset, 4096);

		for (j = 0; j < readSize; ++j) {
			*((unsigned long long*) (void*) (unsigned long)
				(((unsigned long) m_pDBuffer) + (((unsigned long) j)
				* (unsigned long) 4096) +(unsigned long) 8 * line * 2)) =
				destPage + j * 4096;

			*((unsigned long long*) (void*) (unsigned long)
				((((unsigned long) m_pDBuffer) + (((unsigned long) j)
				* (unsigned long) 4096)) + (unsigned long) 8 + (unsigned long) 8 * line * 2)) =
				(unsigned long) m_destKey;
		}

		sizeBytes -= readSizeBytes;
		dest = (void *) ((unsigned long) dest + readSizeBytes);

		rett = my_read(f, (void*) ((unsigned long) m_pDBuffer + destOffset),
			(readSizeBytes), offset + readOffsetBytes, 1);

		if (rett < 0) {
			return -1;
		}

		readOffsetBytes += readSizeBytes;
	}
	return(ssize_t) origSize;
}

static ssize_t prep_ring_read(struct fd f, void *buf, size_t count, off_t offset,
	void* key_return, int line, unsigned long ubuffer_size, int* ubuffer,
	unsigned long offset_return, void* m_pDBuffer)
{
	unsigned long lastp, currp, startp;
	unsigned int sstate, j, cons;
	int ret;

	lastp = 0;
	ret = 0;
	currp = MIN(4096 - (offset % 4096), count);
	startp = 0;
	sstate = *(ubuffer);

	if (!sstate) {
		startp = currp;
	}

	j = 1;
	cons = sstate;

	if (only_p2p) {
		ret += ring_read(f, (void*) (offset_return + lastp), count,
			offset + lastp, (void*) (key_return), line, m_pDBuffer);
		return ret;

	} else {
		while (1) {
			while (j < ubuffer_size) {
				if (*(ubuffer + j) == 1) {
					cons++;
				} else {
					if (cons >= CONS || (4096 * 100 * cons) / count >= 20) {
						break;
					}
					sstate = 0;
					cons = 0;
				}

				j++;
				if (j < ubuffer_size) {
					currp += 4096;

				} else {
					currp = count;
				}
				if (cons == 0) {
					startp = currp;
				}
			}

			if (sstate == 0) {
				if (cons >= CONS || (4096 * 100 * cons) / count >= 20) {
					ret += ring_read(f, (void*) (offset_return + lastp),
						startp - lastp, offset + lastp,
						(void*) (key_return), line, m_pDBuffer);
				} else {
					ret += ring_read(f, (void*) (offset_return + lastp),
						currp - lastp, offset + lastp,
						(void*) (key_return), line, m_pDBuffer);
				}
			}

			if (cons >= CONS || (4096 * 100 * cons) / count >= 20 || sstate == 1) {
				ret += my_read(f, (void*) ((unsigned long) buf + startp),
					currp - startp, offset + startp, 0);
			}

			if (j < ubuffer_size) {
				sstate = *(ubuffer + j);
				lastp = currp;
				startp = currp;
				cons = sstate;
			} else {
				return ret;
			}
		}
	}
}

ssize_t cusread(struct file * f, char __user * u, size_t s, loff_t *o)
{
	unsigned long base_off, num_pages, res;
	struct cache_lru * tree_l = NULL;
	struct radix_tree_root * rtr;

	res = 0;
	base_off = (*o) / 4096;
	num_pages = DIV_ROUND_UP(s, 4096);

	if (f->f_inode->i_private != NULL) {
		spin_lock(&caches_lru_listlock);
		rtr = &(((struct fd_priv *) (f->f_inode->i_private))->mypc_tree);
		res = radix_tree_gang_lookup(rtr, (void**) &tree_l, base_off, 1);
		if (res) {
			if (res == 1 && tree_l->offset < base_off + num_pages) {
				remove_from_rt(rtr, tree_l->length, tree_l->offset);
				list_del(&(tree_l->list));
				kfree(tree_l);
			}
		}
		spin_unlock(&caches_lru_listlock);
	}
	return orig_read(f, u, s, o);
}

static long spindrv_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
	int ret = 0;
	int pid = current->tgid;
	spindrv_ioctl_param_union local_param;

	if (copy_from_user((void *) &local_param, (void *) ioctl_param,
		sizeof(spindrv_ioctl_param_union))) {
		return -ENOMEM;
	}

	switch (ioctl_num) {

	case SPIN_IOCTL_NEW_BUFFER:
	{
		int count, err, offset, j;
		void* addr;
		struct pid_pages* pid_page;
		unsigned long length;

		addr = local_param.set.addr;
		length = local_param.set.size;

		if (!addr) {
			dev_err(spindrv_device, "No ring buffer\n");
			return -1;
		}

		if (!(addr) && (unsigned long) addr & 3) {
			dev_err(spindrv_device, "Allocation not aligned\n");
			return -1;
		}

		offset = offset_in_page(addr);
		count = DIV_ROUND_UP(offset + length, PAGE_SIZE);

		pid_page = (struct pid_pages *) kmalloc(sizeof(struct pid_pages), GFP_KERNEL);
		pid_page->length = length;
		pid_page->pages = (struct page **) kcalloc(count, sizeof(struct page *), GFP_KERNEL);
		pid_page->pid = pid;
		pid_page->mm = current->mm;
		pid_page->count = count;

		if (!pid_page->pages) {
			dev_err(spindrv_device, "Kalloc pages failed\n");
			return -1;
		}

		err = get_user_pages_fast((unsigned long) addr, count, 1, pid_page->pages);

		for (j = 0; j < count; j++) {
			SetPagef(pid_page->pages[j]);
		}

		spin_lock(&listlock);
		INIT_LIST_HEAD(&pid_page->list);
		list_add_tail(&(pid_page->list), &(pid_pages_list.list));

		j = 0;

		list_for_each_entry(pid_page, &(pid_pages_list.list), list)
		{
			if (pid_page->pid == pid) {
				j++;
			}
		}

		if (j <= 1) {
			struct mm_struct* mm;
			mm = get_task_mm(current);
			mmu_notifier_register(&notify, mm);
			mmput(mm);
		}

		spin_unlock(&listlock);

		copy_to_user((void *) ioctl_param, (void*) &local_param, sizeof(spindrv_ioctl_param_union));

		break;
	}

	case SPIN_IOCTL_REMOVE:
	{
		spindrv_remove(pid, NULL);
		break;
	}

	case SPIN_IOCTL_READ:
	{
		void* gpu_addr_phys, *virt_start, *key_return;
		unsigned long gpu_length, offset_return, ubuffer_size;
		int line, perinPC;
		int* ubuffer;
		struct fd f;
		line = 0;
		f = fdget(local_param.readArgs.fd);
		if (f.file) {
			do {
				ubuffer_size = DIV_ROUND_UP(local_param.readArgs.count + (local_param.readArgs.offset % 4096), 4096);
				ubuffer = (int *) kzalloc(ubuffer_size * sizeof(int), GFP_KERNEL);
				perinPC = get_mypc(f, local_param.readArgs.count, local_param.readArgs.offset, ubuffer);

				if ((unsigned long) (f.file->private_data) == 0) {
					if (f.file->f_inode != NULL) {
						if (f.file->f_inode->i_sb != NULL) {
							if (f.file->f_inode->i_sb->s_bdev != NULL) {
								if (check_device(MAJOR(f.file->f_inode->i_sb->s_bdev->bd_dev))) { /*|| MAJOR(f.file->f_inode->i_sb->s_bdev->bd_dev) == 252*/
									struct files_fd * new_fd;
									struct fd_priv * temp;

									spin_lock(&fd_listlock);

									temp = (struct fd_priv *) kzalloc(sizeof(struct fd_priv), GFP_KERNEL);

									temp->p2p = 2;
									temp->last_offset = 512 * 4096;
									temp->current_l = NULL;
									temp->myfile = *(f.file);
									temp->myfile.f_flags |= O_DIRECT;
									INIT_RADIX_TREE(&(temp->mypc_tree), GFP_KERNEL);

									if (!disable_ra_pc) {
										orig_ops = *(f.file->f_inode->i_fop);
										orig_ops_ptr = (f.file->f_inode->i_fop);
										orig_read = orig_ops.read;
										orig_ops.read = cusread;
										f.file->f_inode->i_fop = &orig_ops;
									}

									new_fd = (struct files_fd *) kzalloc(sizeof(struct files_fd), GFP_KERNEL);
									new_fd->mdata = (void*) temp;
									new_fd->tgid = current->tgid;
									new_fd->fd = local_param.readArgs.fd;

									INIT_LIST_HEAD(&new_fd->list);
									list_add_tail(&(new_fd->list), &(files_fd_list.list));
									(f.file->private_data) = (void*) temp;
									f.file->f_inode->i_private = (void*) temp;


									spin_unlock(&fd_listlock);
									break;
								} else {
									(f.file->private_data) = (void *) 1;
								}
							}
						}
					}
				}

				if ((unsigned long) (f.file->private_data) == 1) {
					local_param.readArgs.read_return = my_read(f, local_param.readArgs.buf,
						local_param.readArgs.count,
						local_param.readArgs.offset, 0);
					fdput(f);
					copy_to_user((void *) ioctl_param, (void*) &local_param, sizeof(spindrv_ioctl_param_union));
					kfree(ubuffer);
					return 2;
				}
			} while (false);

			spin_lock(&checklock);

			key_return = get_key(local_param.readArgs.buf, current->pid, &(offset_return), &(line));

			if (key_return) {
				spin_unlock(&checklock);

				if (only_p2p) {
					local_param.readArgs.read_return = prep_ring_read(f, local_param.readArgs.buf, local_param.readArgs.count, local_param.readArgs.offset,
						key_return, line, ubuffer_size, ubuffer, offset_return, local_param.readArgs.m_pDBuffer);
				} else {
					if (local_param.readArgs.count < RAV && local_param.readArgs.offset <= ((struct fd_priv *) (f.file->private_data))->last_offset &&
						((struct fd_priv *) (f.file->private_data))->last_offset <= local_param.readArgs.offset + local_param.readArgs.count) {

						if (!disable_ra_pc) {
							int p_iter;
							unsigned long base_off;
							unsigned long num_pages;
							struct cache_lru * tree_l = NULL;
							struct radix_tree_root * rtr;
							struct cache_lru * cur_cache;
							base_off = local_param.readArgs.offset / 4096;
							num_pages = DIV_ROUND_UP(local_param.readArgs.count, 4096);
							rtr = &(((struct fd_priv *) (f.file->private_data))->mypc_tree);
							spin_lock(&caches_lru_listlock);
							tree_l = (struct cache_lru *) radix_tree_lookup(rtr, base_off);
							if (tree_l) {

							} else {

								cur_cache = ((struct cache_lru *) (((struct fd_priv *) (f.file->private_data))->current_l));

								if (cur_cache == NULL || (cur_cache != NULL && cur_cache->offset + cur_cache->length != base_off)) {
									cur_cache = add_my_lru(f.file->f_mapping, ubuffer, ubuffer_size, base_off, num_pages, ((struct fd_priv *) (f.file->private_data)));
									((struct fd_priv *) (f.file->private_data))->current_l = cur_cache;
								} else {
									cur_cache->length += num_pages;
								}

								for (p_iter = 0; p_iter < num_pages; p_iter++) {
									radix_tree_insert(rtr, base_off + p_iter, cur_cache);
								}
								curr_pc += num_pages;
							}
							spin_unlock(&caches_lru_listlock);
						}

						local_param.readArgs.read_return = my_read(f, (void*) local_param.readArgs.buf,
							local_param.readArgs.count, local_param.readArgs.offset, 0);
					} else {
						local_param.readArgs.read_return = prep_ring_read(f, local_param.readArgs.buf, local_param.readArgs.count, local_param.readArgs.offset,
							key_return, line, ubuffer_size, ubuffer, offset_return, local_param.readArgs.m_pDBuffer);
					}
				}
				fdput(f);

				copy_to_user((void *) ioctl_param, (void*) &local_param, sizeof(spindrv_ioctl_param_union));

				kfree(ubuffer);
				return 1;
			}

			gpu_addr_phys = translate_virt(local_param.readArgs.buf, current->mm, &(gpu_length), &virt_start);

			if (!gpu_addr_phys) {
				spin_unlock(&checklock);
				local_param.readArgs.read_return = my_read(f, local_param.readArgs.buf,
					local_param.readArgs.count,
					local_param.readArgs.offset, 2);
				fdput(f);

				copy_to_user((void *) ioctl_param, (void*) &local_param, sizeof(spindrv_ioctl_param_union));

				kfree(ubuffer);
				return 2;
			}

			key_return = add_gpu_mapping(virt_start, gpu_addr_phys, gpu_length, &(line));
			spin_unlock(&checklock);

			if (only_p2p) {
				offset_return = local_param.readArgs.buf - virt_start;
				local_param.readArgs.read_return = prep_ring_read(f, local_param.readArgs.buf, local_param.readArgs.count, local_param.readArgs.offset,
					key_return, line, ubuffer_size, ubuffer, offset_return, local_param.readArgs.m_pDBuffer);
			} else {
				if (local_param.readArgs.count < RAV && local_param.readArgs.offset <= ((struct fd_priv *) (f.file->private_data))->last_offset &&
					((struct fd_priv *) (f.file->private_data))->last_offset <= local_param.readArgs.offset + local_param.readArgs.count) {
					local_param.readArgs.read_return = my_read(f, (void*) local_param.readArgs.buf,
						local_param.readArgs.count, local_param.readArgs.offset, 0);
				} else {
					offset_return = local_param.readArgs.buf - virt_start;
					local_param.readArgs.read_return = prep_ring_read(f, local_param.readArgs.buf, local_param.readArgs.count, local_param.readArgs.offset,
						key_return, line, ubuffer_size, ubuffer, offset_return, local_param.readArgs.m_pDBuffer);
				}
			}
			fdput(f);

			copy_to_user((void *) ioctl_param, (void*) &local_param, sizeof(spindrv_ioctl_param_union));

			kfree(ubuffer);
			return 1;

		} else {
			local_param.readArgs.read_return = my_read(f, local_param.readArgs.buf,
				local_param.readArgs.count,
				local_param.readArgs.offset, 0);
			fdput(f);
			copy_to_user((void *) ioctl_param, (void*) &local_param, sizeof(spindrv_ioctl_param_union));
			return 2;
		}
		break;
	}

	default:
	{
		ret = -EINVAL;
	}
	}

	return 0;
}

struct file_operations spindrv_dev_fops = {
	.unlocked_ioctl = spindrv_ioctl,
	.open = spindrv_open,
	.release = spindrv_close,
};

static int __init spindrv_init(void)
{
	printk("spin: Initializing spin\n");
	major_number = register_chrdev(0, DEVICE_NAME, &spindrv_dev_fops);

	if (major_number < 0) {
		printk("spin: failed to register a major number\n");
		return major_number;
	}

	printk("spin: registered correctly with major number %d\n", major_number);

	spindrv_class = class_create(THIS_MODULE, CLASS_NAME);

	if (IS_ERR(spindrv_class)) { // Check for error and clean up if there is
		unregister_chrdev(major_number, DEVICE_NAME);
		printk(KERN_ALERT "spin: Failed to register device class\n");
		return PTR_ERR(spindrv_class); // Correct way to return an error on a pointer
	}


	spindrv_device = device_create(spindrv_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
	if (IS_ERR(spindrv_device)) { // Clean up if there is an error
		class_destroy(spindrv_class); // Repeated code but the alternative is goto statements
		unregister_chrdev(major_number, DEVICE_NAME);
		printk("spin: Failed to create the device\n");
		return PTR_ERR(spindrv_device);
	}

	dev_info(spindrv_device,"device class registered correctly\n");

	INIT_LIST_HEAD(&pid_pages_list.list);
	INIT_LIST_HEAD(&gpu_mappings_list.list);
	INIT_LIST_HEAD(&pdev_list.list);
	INIT_LIST_HEAD(&files_fd_list.list);
	INIT_LIST_HEAD(&cache_lru_list.list);
	if (only_p2p) {
		dev_info(spindrv_device, "only p2p!!\n");
	}
	return 0;
}

static void __exit spindrv_exit(void)
{
	device_destroy(spindrv_class, MKDEV(major_number, 0));
	class_unregister(spindrv_class);
	class_destroy(spindrv_class);
	unregister_chrdev(major_number, DEVICE_NAME);
	printk("spin: Goodbye from spin!\n");

}

module_init(spindrv_init);
module_exit(spindrv_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NVME P2P helper");
MODULE_AUTHOR("Shai Bergman");
