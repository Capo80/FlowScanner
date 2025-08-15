#include "kernel_checks.h"
#include "linux/atomic/atomic-instrumented.h"
#include "linux/kref.h"
#include "linux/spinlock.h"
#include "linux/types.h"
#include "utils.h"
#include "../mod.h"

struct check_function_node {

	// int check(void* data, unsigned long start, unsigned long end)
	check_function_t check;
	unsigned char active; //deactivate function without unloading
	struct kref refcount; // every time the function is called the ref counter is raised

	struct list_head node;
};

LIST_HEAD(check_functions_list);
rwlock_t check_functions_lock = __RW_LOCK_UNLOCKED(check_functions_lock);


/* atomic_t active_check_functions = ATOMIC_INIT(0); */


/**
 * @brief add a check function to the list
 * 
 * @param check check function to add
 * @param module module handle where the function resides
 * 
 * @return <0 if error, 0 if success
 */
int add_check_function(check_function_t check, struct module *module) {

	unsigned long flags;
	struct check_function_node* new_node;
	
	/* if (!try_module_get(module)) { */
	/* 	DCE_DEBUG pr_err("(add_check_function) Uanble to get module ref, will not add check\n"); */
	/* 	return -1; */
	/* } */


	new_node = kmalloc(sizeof(struct check_function_node), GFP_ATOMIC);
	new_node->active = 1;
	new_node->check = check;
	kref_init(&new_node->refcount);

	write_lock_irqsave(&check_functions_lock, flags);
	list_add(&new_node->node, &check_functions_list);
	write_unlock_irqrestore(&check_functions_lock, flags);
	
	/* atomic_inc(&active_check_functions); */

	DCE_DEBUG pr_info("(add_check_function) Check function added: %lx\n", (unsigned long) check);
	return 0;
}

/**
 * @brief remove a check function from the list
 * 
 * @param check function to remove (address is used as key)
 * @param module module handle where the function resides
 * 
 * @return int <0 if errore, 0 if success
 */
int remove_check_function(check_function_t check, struct module *module) {

	unsigned long flags;
	struct list_head* pos;
	struct check_function_node* curr;

	list_for_each(pos, &check_functions_list) {
		curr = list_entry(pos, struct check_function_node, node);

		DCE_DEBUG pr_info("(remove_check_function) list entry: %lx\n", (unsigned long) curr->check);
		if (curr->check == check) 
			break;

	}

	curr->active = 0;
	write_lock_irqsave(&check_functions_lock, flags);
	list_del(&curr->node);
	write_unlock_irqrestore(&check_functions_lock, flags);

	/* atomic_dec(&active_check_functions); */
	/* module_put(module); */

	return 0;
}


int run_kernel_check(char *data, unsigned long start, unsigned long end) {

	unsigned long flags;
	struct list_head* pos;
	struct check_function_node* curr;
	unsigned long total_run = 0, total_negative = 0;

	DCE_DEBUG pr_info("(run_kernel_check) running check");
	list_for_each(pos, &check_functions_list) {
		curr = list_entry(pos, struct check_function_node, node);

		read_lock_irqsave(&check_functions_lock, flags);
		if (curr->active) {
			int res = curr->check(data, start, end);
			DCE_DEBUG pr_info("(run_kernel_check) running: %lx - res: %d\n", (unsigned long) curr->check, res);			
			total_run++;
			total_negative += res;
		}
		read_unlock_irqrestore(&check_functions_lock, flags);

	}

#if DCE_CHECK_MODE == 0
	
	DCE_DEBUG pr_info("(run_kernel_check) check mode AT LEAST ONE, %lu, %lu", total_negative, total_run);
	
	if (total_negative != total_run)
		return 0;
	else
		return 1;

#elif DCE_CHECK_MODE == 1
	DCE_DEBUG pr_info("(run_kernel_check) check mode MAJORITY");

	if (total_negative < (total_run-total_negative))
		return 0;
	else
		return 1;

#elif DCE_CHECK_MODE == 2
	DCE_DEBUG pr_info("(run_kernel_check) check mode ALL OR NOTHING");
	if (total_negative == total_run)
		return 0;
	else
		return 1;
#endif

}
