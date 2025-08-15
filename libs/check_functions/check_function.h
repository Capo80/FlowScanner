#ifndef H_CHECK_FUNCTIONS
#define H_CHECK_FUNCITONS

#include <linux/kernel.h>
#include <linux/module.h>

#include "../utils.h"
#include "../../mod.h"

int check_function_1(void *data, unsigned long start, unsigned long end);
int check_function_2(void *data, unsigned long start, unsigned long end);


#endif
