#ifndef FPROBERS_H
#define FPROBERS_H

struct mmap_info_f
{
	const char *name;
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
};

struct addr_info_f
{
	struct vm_area_struct *vma;
	unsigned int flags;
	unsigned long addr;
	unsigned long pte;
};

extern int mprotect_handler(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *entry_data);

extern int change_protection_handler(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *entry_data);

#ifdef ZONE_KERNEL_SYNC_CHECK
extern int invalid_op_handler(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data);
#endif

extern int exec_handler(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data);

extern int handle_exit(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data);

extern int sig_handler(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data);

extern int sig_handler_2(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data);

extern void should_fault_around_handler_f(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data);

extern int filemap_handler(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip, struct pt_regs *regs,void *data);




extern  int kernel_clone_handler_f(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip,  struct pt_regs *regs,void *data);
extern  void kernel_clone_ret_handler_f (struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct pt_regs  *regs,
    void *data);

extern int do_mmap_handler_f(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip,  struct pt_regs *regs,void *entry_data);
extern void do_mmap_ret_handler_f (struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct pt_regs *regs,
    void *data);

extern  int do_fault_handler_f(struct fprobe *fp, unsigned long entry_ip,unsigned long ret_ip,  struct pt_regs *regs,void *data);
extern  void do_fault_ret_handler_f (struct fprobe *fp, unsigned long ip,
    unsigned long ret_ip, struct pt_regs *regs,
    void *data);

#endif