#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/mutex.h>

#define DEV_NAME "ringbuffer"
#define RING_BUFFER_SIZE 4096

static dev_t dev_num;
static struct cdev c_dev;
static struct class *cl;
static char *ring_buffer;
static int write_ptr = 0;
static int read_ptr = 0;
static DEFINE_MUTEX(ring_buffer_mutex);

static int dev_open(struct inode *i, struct file *f) {
    printk(KERN_INFO "Device %s opened\n", DEV_NAME);
    return 0;
}

static int dev_close(struct inode *i, struct file *f) {
    printk(KERN_INFO "Device %s closed\n", DEV_NAME);
    return 0;
}

static ssize_t dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
    int bytes_to_write;
    int bytes_written = 0;

    mutex_lock(&ring_buffer_mutex);

    while (len > 0) {
        bytes_to_write = min(len, (size_t)(RING_BUFFER_SIZE - write_ptr));

        if (bytes_to_write > 0) {
            if (copy_from_user(&ring_buffer[write_ptr], buf, bytes_to_write)) {
                mutex_unlock(&ring_buffer_mutex);
                return -EFAULT;
            }

            write_ptr = (write_ptr + bytes_to_write) % RING_BUFFER_SIZE;
            bytes_written += bytes_to_write;
            len -= bytes_to_write;
            buf += bytes_to_write;
        } else {
            mutex_unlock(&ring_buffer_mutex);
            return bytes_written;
        }
    }

    mutex_unlock(&ring_buffer_mutex);

    return bytes_written;
}

static ssize_t dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
    int bytes_to_read;
    int bytes_read = 0;

    mutex_lock(&ring_buffer_mutex);

    while (len > 0) {
        if (read_ptr == write_ptr) {
            mutex_unlock(&ring_buffer_mutex);
            return bytes_read;
        }

        bytes_to_read = min(len, (size_t)(write_ptr - read_ptr));
        if (bytes_to_read > 0) {
            if (copy_to_user(buf, &ring_buffer[read_ptr], bytes_to_read)) {
                mutex_unlock(&ring_buffer_mutex);
                return -EFAULT;
            }

            read_ptr = (read_ptr + bytes_to_read) % RING_BUFFER_SIZE;
            bytes_read += bytes_to_read;
            len -= bytes_to_read;
            buf += bytes_to_read;
        }
    }

    mutex_unlock(&ring_buffer_mutex);

    return bytes_read;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = dev_open,
    .release = dev_close,
    .write = dev_write,
    .read = dev_read
};

static int __init ringbuffer_init(void) {
    int ret;

    if ((ret = alloc_chrdev_region(&dev_num, 0, 1, DEV_NAME)) < 0) {
        printk(KERN_ERR "Failed to allocate character device region\n");
        return ret;
    }

    if (IS_ERR(cl = class_create(THIS_MODULE, "chardrv"))) {
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(cl);
    }

    if (IS_ERR(device_create(cl, NULL, dev_num, NULL, DEV_NAME))) {
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(cl);
    }

    cdev_init(&c_dev, &fops);

    if ((ret = cdev_add(&c_dev, dev_num, 1)) < 0) {
        device_destroy(cl, dev_num);
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    ring_buffer = kmalloc(RING_BUFFER_SIZE, GFP_KERNEL);
    if (!ring_buffer) {
        cdev_del(&c_dev);
        device_destroy(cl, dev_num);
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -ENOMEM;
    }

    printk(KERN_INFO "Ringbuffer device initialized\n");
    return 0;
}

static void __exit ringbuffer_exit(void) {
    kfree(ring_buffer);
    cdev_del(&c_dev);
    device_destroy(cl, dev_num);
    class_destroy(cl);
    unregister_chrdev_region(dev_num, 1);
    printk(KERN_INFO "Ringbuffer device unloaded\n");
}

module_init(ringbuffer_init);
module_exit(ringbuffer_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Ringbuffer Device Driver");
