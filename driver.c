#include "driver.h"
#include "libs/hlist_lock_free.h"

dev_t dev = 0;

struct class *dev_class;
struct cdev insp_cdev;

long insp_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

struct file_operations fops =
    {
        .owner = THIS_MODULE,
        .unlocked_ioctl = insp_ioctl,
};

unsigned int generate_id(unsigned long start_address, unsigned long end_address, pid_t pid)
{
    unsigned int data[3] = {start_address, end_address, pid};
    return jhash(data, 3, 0);
}

long insp_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
#ifdef DOS_PROTECTION
    struct user_hash_node *cur = NULL;
    unsigned long read = 0;
#endif

#ifdef ZONE_KERNEL_SYNC_CHECK
    struct zone_hash_node *curr = NULL;
    struct user_zone *empty_info = NULL;
    struct user_zone *user_zone = NULL;
    unsigned long zone_size = 0;
    kuid_t uid;
#else
    unsigned long flags;
    struct page_hash_node *temp = NULL;
    struct user_page_info *empty_info = NULL;
    struct user_page_info *user_page_info = NULL;

    int bucket = 0;
#endif
    struct hlist_node *tmp = NULL;
    int bkt = 0;
    struct mem_info *mem_info = NULL;
    /* printk("Called IO\n"); */
    switch (cmd)
    {

    case RD_MEM:

        AUDIT printk("%s: Command RD_MEM: 0x%x invoked\n", MODULE_NAME, cmd);

        mem_info = kmalloc(sizeof(struct mem_info), GFP_KERNEL);
        if (mem_info == NULL)
        {
            pr_err("%s: Data Read : Err!\n", MODULE_NAME);
            return -EFAULT;
        }

        mem_info->tot_memory_bytes = tot_num_of_pages * sizeof(struct page_info) + total_zones_size + tot_num_of_zones * sizeof(struct open_zone);
        // ktime_get_real_ts64(&mem_info->ts);

        // printk("%s: tot_num_of_pages: %d\n", MODULE_NAME, tot_num_of_pages);
        // printk("%s: total_zones_size: %lu\n", MODULE_NAME, total_zones_size);
        // printk("%s: tot_num_of_zones: %d\n", MODULE_NAME, tot_num_of_zones);

        if (copy_to_user((struct mem_info *)arg, mem_info, sizeof(struct mem_info)))
        {
            pr_err("%s: Data Read : Err!\n", MODULE_NAME);
            kfree(mem_info);
            return -EFAULT;
        }

        kfree(mem_info);

        break;

#ifdef ZONE_KERNEL_SYNC_CHECK

    case RD_VALUE:

        //printk("%s: Command RD_VALUE: 0x%x invoked\n", MODULE_NAME, cmd);

        // if (zone_hash_table != NULL && started)
        if (zone_hash_table != NULL)
        {
            hash_for_each_safe(zone_hash_table, bkt, tmp, curr, node)
            {
                if (curr != NULL && curr->zone != NULL)
                {
                    zone_size = curr->zone->end - curr->zone->start;
                    uid = curr->zone->uid;

                    user_zone = kmalloc(sizeof(struct user_zone), GFP_ATOMIC);

                    if (user_zone == NULL)
                    {
                        pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                        return -EFAULT;
                    }

                    if (zone_size <= MAX_PAGES * PAGE_SIZE)
                        memcpy(user_zone->data, curr->zone->data, zone_size);

                    user_zone->pid = curr->pid;

                    /* memcpy(&(user_zone->ptid), &(curr->zone->ptid), sizeof(struct user_zone) - offsetof(struct user_zone, ptid)); */
                    user_zone->ptid = curr->zone->ptid; // Parent Thread ID
                    user_zone->tid = curr->zone->tid; // Thread ID
                    user_zone->start = curr->zone->start;
                    user_zone->end = curr->zone->end;
                    user_zone->ts = curr->zone->ts;
                    user_zone->stats = curr->zone->stats;


                    //printk("timestamp %lx %lx\n", user_zone->ts.tv_sec, user_zone->ts.tv_nsec);
                    if (copy_to_user((struct user_zone *)arg, user_zone, sizeof(struct user_zone)))
                    {
                        pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                        kfree(user_zone);
                        return -EFAULT;
                    }

                    kfree(user_zone);

                    // spin_lock_irqsave(zone_spinlocks + bkt, flags);
                    // hash_del(&curr->node);
                    // spin_unlock_irqrestore(zone_spinlocks + bkt, flags);
                    hash_del_atomic(&curr->node);

                    kfree(curr->zone->data);
                    kfree(curr->zone);
                    kfree(curr);

                    tot_num_of_zones--;
                    total_zones_size -= zone_size;

#ifdef DOS_PROTECTION
                    // fix up user hash
                    hash_for_each_possible(user_hash, cur, node, uid.val)
                    {
                        if (uid_eq(cur->uid, uid))
                        {
                            // pr_info("%s: bytes_allocated: %lu\n", MODULE_NAME, cur->bytes_allocated);

                            __sync_fetch_and_or(&cur->is_being_updated, 1);

                            read = cur->bytes_allocated;

                            if (read > 0)
                            {
                                if (read > __sync_fetch_and_sub(&cur->bytes_allocated, zone_size))
                                {
                                    // overflow - just go to 0
                                    cur->bytes_allocated = 0;
                                }
                            }

                            break;
                        }
                    }
#endif
                    return 0;
                }
            }

            // if (curr == NULL && finished)
            if (curr == NULL)
            {
                AUDIT printk(KERN_INFO "%s: No more data\n", MODULE_NAME);

                empty_info = kzalloc(sizeof(struct user_zone), GFP_KERNEL);
                if (empty_info == NULL)
                {
                    pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                    break;
                }

                empty_info->pid = -1; // no more data
                if (copy_to_user((struct user_zone *)arg, empty_info, sizeof(struct user_zone)))
                {
                    pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                }

                kfree(empty_info);
            }
            else
                goto empty;
        }

        else
        {
        empty:
            empty_info = kzalloc(sizeof(struct user_zone), GFP_KERNEL);
            if (empty_info == NULL)
            {
                pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                break;
            }

            empty_info->pid = 0;
            if (copy_to_user((struct user_zone *)arg, empty_info, sizeof(struct user_zone)))
            {
                pr_err("%s: Data Read : Err!\n", MODULE_NAME);
            }

            kfree(empty_info);
        }

        break;

    case GET_CFG_BY_PID:

        pid_t pid = 0;

        AUDIT printk("%s: Command GET_CFG_BY_PID: 0x%x invoked\n", MODULE_NAME, cmd);

        if (zone_hash_table != NULL && started)
        {
            user_zone = kmalloc(sizeof(struct user_zone), GFP_ATOMIC);

            if (!user_zone)
            {
                pr_err("%s: Data Read : Error in kmalloc for node!\n", MODULE_NAME);
                return -EFAULT;
            }

            if (copy_from_user(user_zone, (void __user *)arg, sizeof(struct user_zone)))
            {
                pr_err("%s: Data Read : Error in copy_from_user!\n", MODULE_NAME);
                kfree(user_zone);
                return -EFAULT;
            }

            printk("%s: Searching for pid %d\n", MODULE_NAME, user_zone->pid);

            pid = user_zone->pid;

            hash_for_each_possible_safe(zone_hash_table, curr, tmp, node, pid)
            {
                if (curr != NULL && curr->zone != NULL && curr->pid == pid)
                {
                    zone_size = curr->zone->end - curr->zone->start;
                    uid = curr->zone->uid;

                    memcpy(user_zone->data, curr->zone->data, curr->zone->end - curr->zone->start);

                    user_zone->pid = curr->pid;

                    memcpy(&(user_zone->ptid), &(curr->zone->ptid), sizeof(struct user_zone) - offsetof(struct user_zone, ptid));

                    if (copy_to_user((struct user_zone *)arg, user_zone, sizeof(struct user_zone)))
                    {
                        pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                        kfree(user_zone);
                        return -EFAULT;
                    }

                    kfree(user_zone);

                    // spin_lock_irqsave(zone_spinlocks + bkt, flags);
                    // hash_del(&curr->node);
                    // spin_unlock_irqrestore(zone_spinlocks + bkt, flags);
                    hash_del_atomic(&curr->node);

                    kfree(curr->zone->data);
                    kfree(curr->zone);
                    kfree(curr);

                    tot_num_of_zones--;
                    total_zones_size -= zone_size;

#ifdef DOS_PROTECTION
                    // fix up user hash
                    hash_for_each_possible(user_hash, cur, node, curr->zone->uid.val)
                    {
                        if (uid_eq(cur->uid, curr->zone->uid))
                        {
                            __sync_fetch_and_or(&cur->is_being_updated, 1);
                            read = cur->bytes_allocated;

                            if (read > __sync_fetch_and_sub(&cur->bytes_allocated, curr->zone->end - curr->zone->start))
                            {
                                // overflow - just go to 0
                                cur->bytes_allocated = 0;
                            }

                            break;
                        }
                    }
#endif
                    return 0;
                }
            }

            if (curr == NULL && finished)
            {
                AUDIT printk(KERN_INFO "%s: No more data\n", MODULE_NAME);

                empty_info = kmalloc(sizeof(struct user_zone), GFP_KERNEL);
                if (empty_info == NULL)
                {
                    pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                    break;
                }

                empty_info->pid = -1; // no more data
                if (copy_to_user((struct user_zone *)arg, empty_info, sizeof(struct user_zone)))
                {
                    pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                }

                kfree(empty_info);
            }
            else
                goto empty_2;
        }
        else
        {
        empty_2:
            empty_info = kmalloc(sizeof(struct user_zone), GFP_KERNEL);
            if (empty_info == NULL)
            {
                pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                return -EFAULT;
            }

            empty_info->pid = 0;
            if (copy_to_user((struct user_zone *)arg, empty_info, sizeof(struct user_zone)))
            {
                pr_err("%s: Data Read : Err!\n", MODULE_NAME);
            }

            kfree(empty_info);
        }

        break;
#else
    case RD_VALUE:

        // AUDIT printk(KERN_INFO "%s: Command RD_VALUE: 0x%x invoked\n", MODULE_NAME, cmd);

        if (page_hash_table != NULL)
        {

            hash_for_each_safe(page_hash_table, bkt, tmp, temp, node)
            {
                if (temp != NULL && temp->info != NULL)
                {
                    DRIVER_PRINT pr_info("Sending page address: %lx", temp->address);
                    user_page_info = kmalloc(sizeof(struct user_page_info), GFP_KERNEL);
                    if (user_page_info == NULL)
                    {
                        pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                        return -EFAULT;
                    }

                    user_page_info->address = temp->address;
                    user_page_info->pid = temp->pid;
                    user_page_info->uid = temp->info->uid;
                    memcpy(user_page_info->data, temp->info->data, PAGE_SIZE);

                    if (copy_to_user((struct user_page_info *)arg, user_page_info, sizeof(struct user_page_info)))
                    {
                        pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                        kfree(user_page_info);
                        return -EFAULT;
                    }

                    kfree(user_page_info);

                    bucket = get_bucket(temp->pid, page_hash_table);
                    spin_lock_irqsave(page_hash_table_spinlocks + bucket, flags);
                    hash_del(&temp->node);
                    spin_unlock_irqrestore(page_hash_table_spinlocks + bucket, flags);

                    kfree(temp->info);
                    kfree(temp);

                    tot_num_of_pages--;

#ifdef DOS_PROTECTION
                    // fix up user hash
                    hash_for_each_possible(user_hash, cur, node, temp->info->uid.val)
                    {
                        if (uid_eq(cur->uid, temp->info->uid))
                        {
                            // pr_info("%s: page_allocated: %d\n",  MODULE_NAME, cur->page_allocated);
                            __sync_fetch_and_or(&cur->is_being_updated, 1);
                            read = cur->page_allocated;
                            if (read > 0)
                                if (read > __sync_fetch_and_sub(&cur->page_allocated, 1))
                                {
                                    // overflow - just go to 0
                                    cur->page_allocated = 0;
                                }

                            break;
                        }
                    }
#endif
                    return 0;
                }
            }

            if (temp == NULL)
            {
                AUDIT printk(KERN_INFO "%s: No more data\n", MODULE_NAME);

                empty_info = kmalloc(sizeof(struct user_page_info), GFP_KERNEL);
                if (empty_info == NULL)
                {
                    pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                    break;
                }

                empty_info->pid = -1; // no more data
                if (copy_to_user((struct user_page_info *)arg, empty_info, sizeof(struct user_page_info)))
                {
                    pr_err("%s: Data Read : Err!\n", MODULE_NAME);
                }

                kfree(empty_info);
            }
        }

        else
        {
            empty_info = kmalloc(sizeof(struct user_page_info), GFP_KERNEL);

            empty_info->pid = 0;
            if (copy_to_user((struct user_page_info *)arg, empty_info, sizeof(struct user_page_info)))
            {
                pr_err("%s: Data Read : Err!\n", MODULE_NAME);
            }

            kfree(empty_info);
        }

        break;
#endif

    default:
        // pr_info("%s: Default\n",  MODULE_NAME);
        break;
    }
    return 0;
}
