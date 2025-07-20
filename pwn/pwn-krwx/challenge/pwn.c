#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("prosti");
MODULE_DESCRIPTION("ToH CTF 2025");

#define DEV_NAME "pwn"

#define CMD_PWN_WRITE 0x1337
#define CMD_PWN_READ  0x1338
#define CMD_PWN_EXEC  0x1339

static void (* pwn_function)(void);
static unsigned long exec_called = 0xdeadbeefcafebabe;

static DEFINE_MUTEX(mutex);

static void pwn_nop(void);
static int pwn_open(struct inode *inode, struct file *file);
static int pwn_release(struct inode *inode, struct file *file);
static long int pwn_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

static struct file_operations pwn_ops = {
    .owner = THIS_MODULE,
    .open = pwn_open,
    .release = pwn_release,
    .unlocked_ioctl = pwn_ioctl
};

struct miscdevice pwn_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEV_NAME,
    .fops = &pwn_ops
};

static void pwn_nop(void){
    return;
}

static long int pwn_ioctl(struct file *filp, unsigned int cmd, unsigned long arg){
    long int result = 0;

    mutex_lock(&mutex);

    switch(cmd){
        case CMD_PWN_WRITE:
            if((result = copy_from_user(&pwn_function, (void (*)(void))arg, sizeof(pwn_function))))
                printk(KERN_INFO "pwn: copy_from_user failed");
            break;
        case CMD_PWN_READ:
            if((result = copy_to_user((void (*)(void))arg, &pwn_function, sizeof(pwn_function))))
                printk(KERN_INFO "pwn: copy_to_user failed");
            
            break;
        case CMD_PWN_EXEC:
            if(exec_called != 0xdeadbeefcafebabe){
                result = -1;
                goto pwn_ioctl_end;
            }
            
            pwn_ops.unlocked_ioctl = NULL;
            pwn_dev.fops = NULL;
            exec_called = 0;

            pwn_function();
            break;
    }

pwn_ioctl_end:
    mutex_unlock(&mutex);

    return result;
}

static int pwn_open(struct inode *inode, struct file *file){
    return 0;
}

static int pwn_release(struct inode *inode, struct file *file){
    return 0;
}

static int __init pwn_init(void){
    int result = 0;
    printk(KERN_INFO "pwn: initializing device");
    
    mutex_init(&mutex);

    result = misc_register(&pwn_dev);

    if(result < 0){
        printk(KERN_WARNING "pwn: misc_register failed");
        return result;
    }

    pwn_function = pwn_nop;
    return 0;
}

static void __exit pwn_exit(void){
    printk(KERN_INFO "pwn: unregistering device");
    misc_deregister(&pwn_dev);
}

module_init(pwn_init);
module_exit(pwn_exit);