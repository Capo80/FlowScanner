#ifndef HLIST_LOCK_FREE_H
#define HLIST_LOCK_FREE_H



/*#define WRITE_ONCE_ATOMIC(ptr, val)                                 \
    do                                                              \
    {                                                               \
        typeof(ptr) __old_val = ptr;                              \
        while (!__sync_bool_compare_and_swap(&ptr, __old_val, val)) \
            __old_val = ptr;                                       \
    } while (0)
*/

static inline void hlist_add_head_atomic(struct hlist_node *n,
                                         struct hlist_head *h)
{
    struct hlist_node *first = NULL;

    do
    {
        first = READ_ONCE(h->first);
        WRITE_ONCE(n->next, first);
        WRITE_ONCE(n->pprev, &h->first);
        if (first)
            WRITE_ONCE(first->pprev, &n->next);

    } while (!__sync_bool_compare_and_swap(&h->first, first, n));
}

#define hash_add_atomic(hashtable, node, key) \
    hlist_add_head_atomic(node, &hashtable[hash_min(key, HASH_BITS(hashtable))])

#define hash_add_atomic_last(hashtable, node, bits) \
    hlist_add_head_atomic(node, &hashtable[1 << bits])

static inline void __hlist_del_atomic(struct hlist_node *n)
{
    struct hlist_node *next = NULL;
    struct hlist_node **pprev = NULL;

    do
    {
        next = READ_ONCE(n->next);
        pprev = READ_ONCE(n->pprev);

        if (next)
            WRITE_ONCE(next->pprev, pprev);

    } while (!__sync_bool_compare_and_swap(n->pprev, *pprev, next));
}

static inline void hlist_del_init_atomic(struct hlist_node *n)
{
    if (!hlist_unhashed(n))
    {
        __hlist_del_atomic(n);
        INIT_HLIST_NODE(n);
    }
}

static inline void hash_del_atomic(struct hlist_node *node)
{
    hlist_del_init_atomic(node);
}

#endif // HLIST_LOCK_FREE_H