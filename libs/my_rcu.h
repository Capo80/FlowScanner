#ifndef MY_RCU_H
#define MY_RCU_H


#include <linux/lockdep_types.h>
#include <linux/types.h>

#include "fprobes/fprobes_helper.h"

#define NUM_BUCKETS (1 << PAGE_BUCKET_BITS)

extern struct lock_class_key rcu_lock_keys[NUM_BUCKETS];
extern struct lockdep_map my_rcu_lock_map[NUM_BUCKETS];
extern void my_synchronize_rcu(int bucket);

static __always_inline void my_rcu_read_lock(int bucket)
{
    __rcu_read_lock();
    __acquire(RCU);
    rcu_lock_acquire(&my_rcu_lock_map[bucket]);
    RCU_LOCKDEP_WARN(!rcu_is_watching(),
                     "my_rcu_read_lock() used illegally while idle");
}

static inline void my_rcu_read_unlock(int bucket)
{
    RCU_LOCKDEP_WARN(!rcu_is_watching(),
                     "my_rcu_read_unlock() used illegally while idle");
    __release(RCU);
    __rcu_read_unlock();
    rcu_lock_release(&my_rcu_lock_map[bucket]); /* Keep acq info for rls diags. */
}


#endif