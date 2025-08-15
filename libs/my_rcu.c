#include "my_rcu.h"

struct lock_class_key rcu_lock_keys[NUM_BUCKETS];
struct lockdep_map my_rcu_lock_map[NUM_BUCKETS];

void my_synchronize_rcu(int bucket)
{
    RCU_LOCKDEP_WARN(lock_is_held(&rcu_bh_lock_map) ||
                         lock_is_held(&my_rcu_lock_map[bucket]) ||
                         lock_is_held(&rcu_sched_lock_map),
                     "Illegal synchronize_rcu() in RCU read-side critical section");
    return;
}