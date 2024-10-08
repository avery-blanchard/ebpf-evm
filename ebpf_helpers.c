#define _GNU_SOURCE
#define MODULE_NAME "eBPF-EVM"

#include "ebpf_helpers.h"
#include <linux/unistd.h>
#include <linux/mount.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/evm.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/integrity.h>
#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/fcntl.h>
#include <linux/bpf_trace.h>
#include <uapi/linux/bpf.h>
#include <linux/bpf_lirc.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/sysfs.h>
#include <linux/bpfptr.h>
#include <linux/btf_ids.h>

/* 
 * bpf___vfs_getxattr 
 * 	void *mem: pointer to struct ebpf_data to allow though verifier
 * 	int mem__sz: size of pointer 
 */
noinline int bpf___vfs_getxattr(void *mem, int mem__sz)
{
	int ret;
	struct dentry *dentry;
	struct inode *inode;
	const char *name;
	void *value;
	size_t size;
	
	struct ebpf_data *data = (struct ebpf_data *) mem;
	
	dentry = data->dentry;
	inode = data->inode;
	name = data->name;
	value = data->value;
	size = data->size;

	ret = __vfs_getxattr(dentry, inode, name, value, size);

	return ret;
}


/*
 * bpf_vfs_getxattr
 *      void *mem: pointer to struct ebpf_data to allow though verifier
 *      int mem__sz: size of pointer
 */
noinline int bpf_vfs_getxattr(void *mem, int mem__sz)
{
        int ret;
        struct dentry *dentry;
        struct mnt_idmap *idmap;
	const char *name;
        void *value;
        size_t size;

        struct ebpf_data *data = (struct ebpf_data *) mem;

        dentry = data->dentry;
        idmap = data->idmap;
        name = data->name;
        value = data->value;
        size = data->size;

        ret = vfs_getxattr(dentry, inode, name, value, size);

        return ret;
}

/*
 * bpf_evm_verifyxattr
 *      void *mem: pointer to struct ebpf_data to allow though verifier
 *      int mem__sz: size of pointer
 */
noinline enum integrity_status bpf_evm_verifyxattr(void *mem, int mem__sz) 
{
	struct dentry *dentry;
	const char *name;
	void *value;
	size_t size;
	
	
        struct ebpf_data *data = (struct ebpf_data *) mem;

        dentry = data->dentry;
        name = data->name;
        value = data->value;
        size = data->size;

	return evm_verifyxattr(dentry, name, value, size);
}

BTF_SET8_START(evm_kfunc_ids)
BTF_ID_FLAGS(func, bpf___vfs_getxattr, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_vfs_getxattr, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_evm_verifyxattr, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_SET8_END(evm_kfunc_ids)

static const struct btf_kfunc_id_set bpf_emv_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &evm_kfunc_ids,
};
static int ebpf_helpers_init(void)
{
	int ret;
	
	/* Register kernel module functions wiht libbpf */
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &bpf_evm_kfunc_set);
	if (ret < 0)
		return ret;

	/* Attach kprobe to kaalsysms_lookup_name to 
	 * get function address (symbol no longer exported */
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
	

	
	/* Use kallsyms_lookup_name to retrieve kernel EVM functions */
	__vfs_getxattr = (ssize_t (*)(struct dentry *, struct inode *, const char *, void *, size_t))
			kallsyms_lookup_name("__vfs_getxattr");
	if (__vfs_getxattr == 0) {
		pr_err("Lookup fails\n");
		return -1;
	}	
	vfs_getxattr = (ssize_t (*)(struct mnt_idmap *, struct dentry *, const char *,
			void *, size_t)) kallsyms_lookup_name("vfs_getxattr");
	if (vfs_getxattr == 0) {
		pr_err("Lookup fails\n");
		return -1;
	}

	evm_verifyxattr = (enum integrity_status (*)(struct dentry *, const char *, void *, size_t))
			kallsyms_lookup_name("evm_verifyxattr");
	if (evm_verifyxattr == 0) {
		pr_err("Lookup fails\n");
		return -1;
	}

	vfs_setxattr = (int (*)(struct mnt_idmap *, struct dentry *, const char *, 
			const void *, size_t, int)) kallsyms_lookup_name("vfs_setxattr");
	if (vfs_setxattr == 0) {
		pr_err("Lookup fails\n");
		return -1;
	} 
	
	vfs_listxattr = (int (*)(struct dentry *, char *, size_t)) kallsyms_lookup_name("vfs_listxattr");
	if (vfs_listxattr == 0) {
		pr_err("Lookup fails\n");
		return -1;
	}
	
	vfs_removexattr = (int (*)(struct mnt_idmap *, struct dentry *, const char *))
				kallsyms_lookup_name("vfs_removexattr");
	if (vfs_removexattr == 0) {
		pr_err("Lookup fails\n");
		return -1;
	}
	return ret;	

}
static void ebpf_helpers_exit(void)
{
	pr_info("Exiting eBPF helpers\n");
	return;
}

module_init(ebpf_helpers_init);
module_exit(ebpf_helpers_exit);


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");
