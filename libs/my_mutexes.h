
#ifndef H_WAIT_LOCK
#define H_WAIT_LOCK


#include <linux/mutex.h> // Add missing include directive for mutex functions

#define lock(x, y, label, page_addr)                                                                                                                                 \
    do                                                                                                                                                               \
    {                                                                                                                                                                \
        mutex_lock(&mutexes[x][y]);                                                                                                                                  \
        AUDIT printk(KERN_CRIT "%s: (%s) The [%s] pid %d (%d) has locked (%d, %d) the page %lx\n", MODULE_NAME, label, current->comm, pid, current->pid, x, y, page_addr); \
    } while (0)

#define unlock(x, y, label, page_addr)                                                                                                                                     \
    do                                                                                                                                                                     \
    {                                                                                                                                                                      \
        if (y != -1)                                                                                                                                                       \
        {                                                                                                                                                                  \
            mutex_unlock(&mutexes[x][y]);                                                                                                                                  \
            AUDIT printk(KERN_CRIT "%s: (%s) The [%s] pid %d (%d) has unlocked (%d, %d) the page %lx\n", MODULE_NAME, label, current->comm, pid, current->pid, x, y, page_addr); \
        }                                                                                                                                                                  \
    } while (0)

#endif
