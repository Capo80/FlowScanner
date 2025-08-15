#include "check_function.h"

const char *shellcodes[] = {
	"\x6a\x0a\x5e\x31\xdb\xf7\xe3\x53\x43\x53\x6a",
	"\x57\x6a\x23\x58\x6a\x00\x6a\x05\x48\x89\xe7",
	//"bar",
};

void *dumb_memmem(const void *haystack, size_t hs_len, const void *needle, size_t ne_len)
{

	const unsigned char *hs = (const unsigned char *)haystack;
	const unsigned char *ne = (const unsigned char *)needle;
	const unsigned char *end;

	/* Ensure haystack length is >= needle length.  */
	if (hs_len < ne_len)
		return NULL;

	end = hs + hs_len - ne_len;

	for (; hs < end; hs++)
		if (memcmp(hs, ne, ne_len) == 0)
			return (void *)hs;

	return NULL;
}

int check_function_1(void *data, unsigned long start, unsigned long end) {

	unsigned long size = end - start;
	int i = 0;
	char *buffer = NULL;
	int num_bytes_until_end = 0;

	DCE_DEBUG pr_err("%s: (check_function_1) called\n", MODULE_NAME);
		
	if (end <= start)
	{
		DCE_DEBUG pr_err("%s: (check_function_1) run_kernel_check: end <= start [%lx, %lx]\n", MODULE_NAME, start, end);
		return 1;
	}

	buffer = data;
	
	//printk("%s: run_kernel_check: start: %lx, end: %lx, size: %ld\n", MODULE_NAME, start, end, size);
	//print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1, buffer, size, false);

	if (PAGE_ALIGNED(end)) // end of page reached, the shellcode is checked until the end of the page
	{

		for (i = 0; i < num_of_sync_checks; i++, buffer++, size--)
		{
			if (dumb_memmem(buffer, size, shellcodes[1], 11) != NULL)
			{
				// found shellcode - kill
				DCE_DEBUG pr_info("%s: (check_function_1) killed sync\n", MODULE_NAME);
				return 0;
			}
		}
	}
	/**
	 * end of page not reached, the shellcode is checked each time in the 1 byte shifted zone.
	 * The zone is shifted each time by 1 byte for at most num_of_sync_checks times.
	 * If the shifted zone reaches the end of the page, it's shifted but size is decresead.
	 */

	else if (PAGE_ALIGN_UP(end) - end >= num_of_sync_checks) // end of page not reached, the shellcode is checked each time in the 1 byte shifted zone
	{
		for (i = 0; i < num_of_sync_checks; i++, buffer++)
		{
			if (dumb_memmem(buffer, size, shellcodes[1], 11) != NULL)
			{
				// found shellcode - kill
				DCE_DEBUG pr_info("%s: (check_function_1) killed sync\n", MODULE_NAME);
				return 0;
			}
		}
	}
	else // PAGE_ALIGN_UP(end) - end < num_of_sync_checks
	{
		num_bytes_until_end = PAGE_ALIGN_UP(end) - end;

		for (i = 0; i < num_of_sync_checks; i++, buffer++)
		{
			if (i < num_bytes_until_end)
			{
				if (dumb_memmem(buffer, size, shellcodes[1], 11) != NULL)
				{
					// found shellcode - kill
					DCE_DEBUG pr_info("%s: (check_function_1) killed sync\n", MODULE_NAME);
					return 0;
				}
			}
			else // i >= num_bytes_until_end
			{
				if (dumb_memmem(buffer, size--, shellcodes[1], 11) != NULL)
				{
					// found shellcode - kill
					DCE_DEBUG printk("%s: (check_function_1) killed sync\n", MODULE_NAME);
					return 0;
				}
			}
		}
	}

	return 1;

}


int check_function_2(void *data, unsigned long start, unsigned long end) {

	DCE_DEBUG pr_err("%s: (check_function_2) called\n", MODULE_NAME);
	return 1;

} 
