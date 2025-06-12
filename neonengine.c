#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/highmem.h>
#include <linux/ptrace.h>
#include <asm/io.h>

#define DEV "neonengine"
#define CLS "neon"
#define MAG 'N'

#define RD _IOWR(MAG, 1, struct mem_op)
#define WR _IOWR(MAG, 2, struct mem_op)
#define FD _IOWR(MAG, 3, struct pat_op)
#define MP _IOWR(MAG, 4, struct maps_op)
#define PR _IOWR(MAG, 5, struct prot_op)

struct mem_op {
    pid_t pid;
    unsigned long adr;
    void __user *buf;
    size_t sz;
    int res;
};

struct pat_op {
    pid_t pid;
    unsigned long s_adr;
    unsigned long e_adr;
    void __user *pat;
    size_t psz;
    unsigned long r_adr;
    int res;
};

struct maps_op {
    pid_t pid;
    void __user *buf;
    size_t bsz;
    size_t asz;
    int res;
};

struct prot_op {
    pid_t pid;
    unsigned long adr;
    size_t sz;
    unsigned long prt;
    int res;
};

static int maj;
static struct class *cls = NULL;
static struct device *dev = NULL;
static struct cdev cdev;
static dev_t dnum;

static long get(struct mem_op *op) {
    struct task_struct *tsk;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    void *kbuf;
    unsigned long cpy = 0;
    int ret = 0;

    rcu_read_lock();
    tsk = pid_task(find_vpid(op->pid), PIDTYPE_PID);
    if (!tsk) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(tsk);
    rcu_read_unlock();

    mm = get_task_mm(tsk);
    if (!mm) {
        put_task_struct(tsk);
        return -EINVAL;
    }

    kbuf = kmalloc(op->sz, GFP_KERNEL);
    if (!kbuf) {
        mmput(mm);
        put_task_struct(tsk);
        return -ENOMEM;
    }

    down_read(&mm->mmap_lock);
    vma = find_vma(mm, op->adr);
    if (!vma || op->adr < vma->vm_start || op->adr + op->sz > vma->vm_end) {
        up_read(&mm->mmap_lock);
        kfree(kbuf);
        mmput(mm);
        put_task_struct(tsk);
        return -EFAULT;
    }

    cpy = access_process_vm(tsk, op->adr, kbuf, op->sz, FOLL_FORCE);
    up_read(&mm->mmap_lock);

    if (cpy > 0) {
        if (copy_to_user(op->buf, kbuf, cpy)) {
            ret = -EFAULT;
        } else {
            ret = cpy;
        }
    } else {
        ret = -EFAULT;
    }

    kfree(kbuf);
    mmput(mm);
    put_task_struct(tsk);
    return ret;
}

static long put(struct mem_op *op) {
    struct task_struct *tsk;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    void *kbuf;
    unsigned long cpy = 0;
    int ret = 0;

    rcu_read_lock();
    tsk = pid_task(find_vpid(op->pid), PIDTYPE_PID);
    if (!tsk) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(tsk);
    rcu_read_unlock();

    mm = get_task_mm(tsk);
    if (!mm) {
        put_task_struct(tsk);
        return -EINVAL;
    }

    kbuf = kmalloc(op->sz, GFP_KERNEL);
    if (!kbuf) {
        mmput(mm);
        put_task_struct(tsk);
        return -ENOMEM;
    }

    if (copy_from_user(kbuf, op->buf, op->sz)) {
        kfree(kbuf);
        mmput(mm);
        put_task_struct(tsk);
        return -EFAULT;
    }

    down_read(&mm->mmap_lock);
    vma = find_vma(mm, op->adr);
    if (!vma || op->adr < vma->vm_start || op->adr + op->sz > vma->vm_end) {
        up_read(&mm->mmap_lock);
        kfree(kbuf);
        mmput(mm);
        put_task_struct(tsk);
        return -EFAULT;
    }

    cpy = access_process_vm(tsk, op->adr, kbuf, op->sz, FOLL_FORCE | FOLL_WRITE);
    up_read(&mm->mmap_lock);

    ret = (cpy == op->sz) ? 0 : -EFAULT;

    kfree(kbuf);
    mmput(mm);
    put_task_struct(tsk);
    return ret;
}

static long scan(struct pat_op *op) {
    struct task_struct *tsk;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    void *pbuf, *sbuf;
    unsigned long a, found = 0;
    size_t ssz = PAGE_SIZE;
    int ret = -ENOENT;

    rcu_read_lock();
    tsk = pid_task(find_vpid(op->pid), PIDTYPE_PID);
    if (!tsk) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(tsk);
    rcu_read_unlock();

    mm = get_task_mm(tsk);
    if (!mm) {
        put_task_struct(tsk);
        return -EINVAL;
    }

    pbuf = kmalloc(op->psz, GFP_KERNEL);
    sbuf = kmalloc(ssz, GFP_KERNEL);
    
    if (!pbuf || !sbuf) {
        kfree(pbuf);
        kfree(sbuf);
        mmput(mm);
        put_task_struct(tsk);
        return -ENOMEM;
    }

    if (copy_from_user(pbuf, op->pat, op->psz)) {
        kfree(pbuf);
        kfree(sbuf);
        mmput(mm);
        put_task_struct(tsk);
        return -EFAULT;
    }

    down_read(&mm->mmap_lock);
    
    for (a = op->s_adr; a < op->e_adr; a += ssz - op->psz + 1) {
        size_t rsz = min(ssz, (size_t)(op->e_adr - a));
        unsigned long cpy;
        void *m;

        vma = find_vma(mm, a);
        if (!vma || a < vma->vm_start)
            continue;

        rsz = min(rsz, (size_t)(vma->vm_end - a));
        cpy = access_process_vm(tsk, a, sbuf, rsz, FOLL_FORCE);
        
        if (cpy < op->psz)
            continue;

        m = memmem(sbuf, cpy, pbuf, op->psz);
        if (m) {
            found = a + (m - sbuf);
            ret = 0;
            break;
        }
    }

    up_read(&mm->mmap_lock);
    
    if (ret == 0) {
        op->r_adr = found;
    }

    kfree(pbuf);
    kfree(sbuf);
    mmput(mm);
    put_task_struct(tsk);
    return ret;
}

static long maps(struct maps_op *op) {
    struct task_struct *tsk;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    char *mbuf;
    size_t pos = 0;
    int ret = 0;

    rcu_read_lock();
    tsk = pid_task(find_vpid(op->pid), PIDTYPE_PID);
    if (!tsk) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(tsk);
    rcu_read_unlock();

    mm = get_task_mm(tsk);
    if (!mm) {
        put_task_struct(tsk);
        return -EINVAL;
    }

    mbuf = kmalloc(op->bsz, GFP_KERNEL);
    if (!mbuf) {
        mmput(mm);
        put_task_struct(tsk);
        return -ENOMEM;
    }

    down_read(&mm->mmap_lock);
    
    for (vma = mm->mmap; vma && pos < op->bsz - 128; vma = vma->vm_next) {
        int l = snprintf(mbuf + pos, op->bsz - pos,
                      "%08lx-%08lx %c%c%c%c\n",
                      vma->vm_start, vma->vm_end,
                      vma->vm_flags & VM_READ ? 'r' : '-',
                      vma->vm_flags & VM_WRITE ? 'w' : '-',
                      vma->vm_flags & VM_EXEC ? 'x' : '-',
                      vma->vm_flags & VM_MAYSHARE ? 's' : 'p');
        if (l > 0)
            pos += l;
    }

    up_read(&mm->mmap_lock);
    
    op->asz = pos;
    
    if (pos > 0) {
        if (copy_to_user(op->buf, mbuf, min(pos, op->bsz))) {
            ret = -EFAULT;
        }
    }

    kfree(mbuf);
    mmput(mm);
    put_task_struct(tsk);
    return ret;
}

static long prot(struct prot_op *op) {
    struct task_struct *tsk;
    struct mm_struct *mm;
    unsigned long flags = 0;
    int ret;

    rcu_read_lock();
    tsk = pid_task(find_vpid(op->pid), PIDTYPE_PID);
    if (!tsk) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(tsk);
    rcu_read_unlock();

    mm = get_task_mm(tsk);
    if (!mm) {
        put_task_struct(tsk);
        return -EINVAL;
    }

    if (op->prt & PROT_READ) flags |= VM_READ;
    if (op->prt & PROT_WRITE) flags |= VM_WRITE;
    if (op->prt & PROT_EXEC) flags |= VM_EXEC;

    down_write(&mm->mmap_lock);
    ret = do_mprotect_pkey(mm, op->adr, op->sz, op->prt, -1);
    up_write(&mm->mmap_lock);

    mmput(mm);
    put_task_struct(tsk);
    return ret;
}

static long ctl(struct file *f, unsigned int cmd, unsigned long arg) {
    long ret = 0;
    
    switch (cmd) {
        case RD: {
            struct mem_op op;
            if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
                return -EFAULT;
            
            ret = get(&op);
            op.res = ret;
            
            if (copy_to_user((void __user *)arg, &op, sizeof(op)))
                return -EFAULT;
            break;
        }
        
        case WR: {
            struct mem_op op;
            if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
                return -EFAULT;
            
            ret = put(&op);
            op.res = ret;
            
            if (copy_to_user((void __user *)arg, &op, sizeof(op)))
                return -EFAULT;
            break;
        }
        
        case FD: {
            struct pat_op op;
            if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
                return -EFAULT;
            
            ret = scan(&op);
            op.res = ret;
            
            if (copy_to_user((void __user *)arg, &op, sizeof(op)))
                return -EFAULT;
            break;
        }
        
        case MP: {
            struct maps_op op;
            if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
                return -EFAULT;
            
            ret = maps(&op);
            op.res = ret;
            
            if (copy_to_user((void __user *)arg, &op, sizeof(op)))
                return -EFAULT;
            break;
        }
        
        case PR: {
            struct prot_op op;
            if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
                return -EFAULT;
            
            ret = prot(&op);
            op.res = ret;
            
            if (copy_to_user((void __user *)arg, &op, sizeof(op)))
                return -EFAULT;
            break;
        }
        
        default:
            return -ENOTTY;
    }
    
    return 0;
}

static int open(struct inode *i, struct file *f) {
    return 0;
}

static int shut(struct inode *i, struct file *f) {
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = open,
    .release = shut,
    .unlocked_ioctl = ctl,
    .compat_ioctl = ctl,
};

static int __init load(void) {
    int ret;

    ret = alloc_chrdev_region(&dnum, 0, 1, DEV);
    if (ret < 0) {
        printk(KERN_ERR "Err: major\n");
        return ret;
    }
    maj = MAJOR(dnum);

    cdev_init(&cdev, &fops);
    cdev.owner = THIS_MODULE;
    
    ret = cdev_add(&cdev, dnum, 1);
    if (ret < 0) {
        unregister_chrdev_region(dnum, 1);
        printk(KERN_ERR "Err: cdev\n");
        return ret;
    }

    cls = class_create(THIS_MODULE, CLS);
    if (IS_ERR(cls)) {
        cdev_del(&cdev);
        unregister_chrdev_region(dnum, 1);
        printk(KERN_ERR "Err: class\n");
        return PTR_ERR(cls);
    }

    dev = device_create(cls, NULL, dnum, NULL, DEV);
    if (IS_ERR(dev)) {
        class_destroy(cls);
        cdev_del(&cdev);
        unregister_chrdev_region(dnum, 1);
        printk(KERN_ERR "Err: dev\n");
        return PTR_ERR(dev);
    }

    printk(KERN_INFO "Init OK\n");
    return 0;
}

static void __exit unload(void) {
    device_destroy(cls, dnum);
    class_destroy(cls);
    cdev_del(&cdev);
    unregister_chrdev_region(dnum, 1);
    printk(KERN_INFO "Unload OK\n");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NeonEngine");
MODULE_DESCRIPTION("Droid Memory Mngr");
MODULE_VERSION("0.1"); 