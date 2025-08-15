#include "zone.h"
#include "fprobes/fprobes_helper.h"
#include "instruction.h"
#include "utils.h"
#include "my_rcu.h"
#include "hlist_lock_free.h"

DEFINE_HASHTABLE(zone_hash_table, BUCKET_BITS);
spinlock_t zone_spinlocks[1 << BUCKET_BITS];

/**
 * Transfer a zone from the user to the kernel.
 * @param data - data of the zone
 * @param start - start address of the zone
 * @param end - end address of the zone
 * @return the zone on success, NULL on failure.
 */
struct open_zone *transfer_zone(char *data, unsigned long start, unsigned long end, struct stats *stats)
{
    struct open_zone *zone = NULL;
    struct zone_hash_node *new_hash_node = NULL;
    unsigned long zone_size = end - start;
    // unsigned long flags;
    pid_t pid = current->tgid;
    pid_t tid = current->pid;

    AUDIT printk(KERN_INFO "%s: transfer_zone_to_user: [%lx, %lx]\n", MODULE_NAME, start, end);

    if (start == 0 || end == 0)
    {
        printk(KERN_ERR "%s: (transfer_zone) Error: start or end is 0\n", MODULE_NAME);
        return NULL;
    }

    if (end < start)
    {
        printk(KERN_ERR "%s: (transfer_zone) Error: end <= start\n", MODULE_NAME);
        return NULL;
    }

    zone = kmalloc(sizeof(struct open_zone), GFP_ATOMIC);

    if (zone == NULL)
    {
        printk(KERN_ERR "%s: (transfer_zone) Error allocating page info\n", MODULE_NAME);
        return NULL;
    }

    ktime_get_real_ts64(&zone->ts);
    zone->tid = tid;
    zone->ptid = current->parent->pid;
    zone->start = start;
    zone->end = end;
    zone->uid = current->cred->uid;

    if (stats != NULL)
        memcpy(&zone->stats, stats, sizeof(struct stats));
    else
        memset(&zone->stats, -1, sizeof(struct stats));

    zone->data = kmalloc(zone_size, GFP_ATOMIC);
    if (zone->data == NULL)
    {
        printk(KERN_ERR "%s: (transfer_zone) Error allocating zone data\n", MODULE_NAME);
        kfree(zone);
        return NULL;
    }

    memcpy(zone->data, data, zone_size);

    new_hash_node = kmalloc(sizeof(struct zone_hash_node), GFP_ATOMIC);

    if (new_hash_node == NULL)
    {
        printk(KERN_ERR "%s: (transfer_zone) Error allocating zone hash node\n", MODULE_NAME);
        kfree(zone->data);
        kfree(zone);

        return NULL;
    }

    new_hash_node->zone = zone;
    new_hash_node->pid = pid;

    AUDIT printk("%s: Adding zone %lx - %lx to the page hash table\n", MODULE_NAME, start, end);
    hash_add_atomic(zone_hash_table, &new_hash_node->node, pid);

    total_zones_size += zone_size;
    tot_num_of_zones++;

    return zone;
}

/**
 * Create a new zone.
 *
 * @param data - data of the zone
 * @param start - start address of the zone
 * @param end - end address of the zone
 * @param num_pages - number of pages
 * @param is_zone - is data is a zone
 * @param stats - stats of the zone
 *
 * @return the zone on success, NULL on failure.
 */
struct open_zone *create_zone(char *data, unsigned long start, unsigned long end, int num_pages, bool is_zone, struct stats *stats)
{
    struct open_zone *zone = NULL;
    struct zone_hash_node *new_hash_node = NULL;
    unsigned long zone_size = end - start;
    unsigned long base_addr = start & PAGE_MASK;
    unsigned long start_offset = start & ~PAGE_MASK;
    unsigned long end_offset = (PAGE_ALIGNED(end)) ? num_pages * PAGE_SIZE : (end & ~PAGE_MASK) + (num_pages - 1) * PAGE_SIZE;

    pid_t pid = current->tgid;
    pid_t tid = current->pid;

    // AUDIT printk("%s: transfer_zone_to_user: %lx\n", MODULE_NAME, page_addr + start_offset);

    if (data == NULL)
    {
        printk(KERN_ERR "%s: (create_zone) Error: data is NULL\n", MODULE_NAME);
        return NULL;
    }

    if (zone_size <= 0)
    {
        printk(KERN_ERR "%s: (create_zone) Error: zone_size <= 0\n", MODULE_NAME);
        return NULL;
    }

    zone = kmalloc(sizeof(struct open_zone), GFP_ATOMIC);

    if (zone == NULL)
    {
        printk(KERN_ERR "%s: (create_zone) Error allocating page info\n", MODULE_NAME);
        return NULL;
    }

    ktime_get_real_ts64(&zone->ts);
    zone->tid = tid;
    zone->ptid = current->parent->pid;
    zone->start = base_addr + start_offset;
    zone->end = base_addr + end_offset;
    zone->uid = current->cred->uid;

    if (stats != NULL)
        memcpy(&zone->stats, stats, sizeof(struct stats));
    else
        memset(&zone->stats, -1, sizeof(struct stats));

    zone->data = kzalloc(zone_size, GFP_ATOMIC);
    if (zone->data == NULL)
    {
        printk(KERN_ERR "%s: (create_zone) Error allocating zone data\n", MODULE_NAME);
        kfree(zone);
        return NULL;
    }

    if (is_zone)
        memcpy(zone->data, data, zone_size);
    else
        memcpy(zone->data, data + start_offset, zone_size);

    new_hash_node = kmalloc(sizeof(struct zone_hash_node), GFP_ATOMIC);

    if (new_hash_node == NULL)
    {
        printk(KERN_ERR "%s: (create_zone) Error allocating zone hash node\n", MODULE_NAME);
        kfree(zone->data);
        kfree(zone);
        return NULL;
    }

    new_hash_node->zone = zone;
    new_hash_node->pid = pid;

    AUDIT printk("%s: Adding zone %lx - %lx to the page hash table\n", MODULE_NAME, zone->start, zone->end);
    hash_add_atomic(zone_hash_table, &new_hash_node->node, pid);

    total_zones_size += zone_size;
    tot_num_of_zones++;

    return zone;
}

/**
 * The function searches for the first jump, call or ret instruction from the current byte to the end of the page.
 *
 * disassemble_code is a function that should find the first jmp, jcc, call, ret instruction.
 * The byte start shoud be compared with all prefixes and op-codes, if it's still a prefix we should consider also the following byte and so on, until a complete match is found
 * @param start The starting address.
 * @param end The ending address.
 * @param stats The stats of the zone to be filled.
 *
 * @return 1 if found, -1 on failure, 0 if the op-code falls in the next page.
 */

int disassemble_code(unsigned long start, unsigned long *end, struct stats *stats)
{

    unsigned long size = *end - start;
    uint8_t *cur = NULL;
    unsigned long aux = start; // The first byte of the previous instruction.
    unsigned long num_prefixes = 0;
    unsigned long op_code_size = 1;
    unsigned long offset = 0;

    uint8_t modrm_byte = 0;
    uint8_t sib_byte = 0;
    uint8_t prefix_byte = 0;
    uint8_t *first_op = 0;
    uint8_t op = 0;
    uint8_t m_mmmm_byte = 0;

    bool rex_w_found = 0;
    bool evex_pref_found = 0;
    bool vex_pref_found = 0;
    bool multibyte = 0;
    bool has_modrm = 0;

    unsigned int ddef = DWORD_SIZE, mdef = DWORD_SIZE;
    unsigned int msize = 0, dsize = 0; // msize is related to the memory operand (moffs), dsize is related to the immediate operand (immediate).
    unsigned int total_size = 0;
    int instruction_type = 0;

    // Searching a jump, call or ret instruction from the current byte to the end of the page.

    DEBUG_INFO printk(KERN_INFO "%s: (disassemble_code) Searching for a JMP, JCC, CALL and RET instruction from %lx to %lx\n", MODULE_NAME, start, *end);

    if (start == 0 || *end == 0)
    {
        printk(KERN_ERR "%s: (disassemble_code) Error: start or end is 0\n", MODULE_NAME);
        return -1;
    }

    if (*end <= start)
    {
        printk(KERN_ERR "%s: (disassemble_code) Error: end <= start\n", MODULE_NAME);
        return -1;
    }

    cur = (uint8_t *)start;

    while ((unsigned long)cur < start + size)
    {

    found_prefixes:

        prefix_byte = *cur;

        if (CHECK_PREFIX(prefix_byte))
        {
            if (CHECK_EVEX(prefix_byte))
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) EVEX_PREFIX found\n", MODULE_NAME);
                num_prefixes += 4;
                evex_pref_found = 1;
                m_mmmm_byte = *(cur + 1);
                cur += 4;
                goto cont;
            }
            else if (CHECK_VEX_2(prefix_byte) || CHECK_VEX_3(prefix_byte))
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) VEX_PREFIX_%d found\n", MODULE_NAME, CHECK_VEX_2(prefix_byte) ? 2 : 3);
                num_prefixes += CHECK_VEX_2(prefix_byte) ? 2 : 3;
                vex_pref_found = 1;
                if (CHECK_VEX_3(prefix_byte))
                    m_mmmm_byte = *(cur + 1);
                cur += CHECK_VEX_2(prefix_byte) ? 2 : 3; // The VEX prefix is 2 or 3 bytes long.
                goto cont;
            }
            else if (CHECK_PREFIX_66(prefix_byte))
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) OPERAND_OVERRIDE_PREFIX found.\n", MODULE_NAME);
                ddef = WORD_SIZE;
                goto skip_byte;
            }
            else if (CHECK_PREFIX_67(prefix_byte))
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) ADDRESS_SIZE_OVERRIDE_PREFIX found.\n", MODULE_NAME);
                mdef = WORD_SIZE;
                goto skip_byte;
            }
        }

        else if (CHECK_REX(prefix_byte))
        {
            if (CHECK_REXW(prefix_byte))
                rex_w_found = 1;

            goto skip_byte;
        }

        else
            goto cont;

    skip_byte:

        CHECK_CROSS_PAGE(++cur, start + size, "prefix");

        num_prefixes++;
        goto found_prefixes;

    cont:

        CHECK_CROSS_PAGE(cur, start + size, "op-code");

        /**----------------------------------------------------- STARTING HERE -----------------------------------------------------------------------------*/

        op = *cur;      // The first byte of the op-code
        first_op = cur; // ptr to the first byte of the op-code

        /**--------------------------------------------------------------- VEX and EVEX --------------------------------------------------------------------------------------*/

        if (vex_pref_found) // 1 byte op-code
        {

            op_code_size = 1;

            INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is VEX\n", MODULE_NAME);

            if (CHECK_VEX_2(prefix_byte)) // The 2-byte VEX implies a leading 0Fh opcode byte), has no m_mmmm_byte
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is 2 byte VEX\n", MODULE_NAME);

                if (VEX_NO_MODRM(op))
                    goto next;

                if (CHECK_VEX_0F_IMM8(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is 2 byte VEX and has an imm8\n", MODULE_NAME);
                    dsize++; // For the imm8
                }

                goto check_mod_rm_byte;
            }
            // VEX with 3 byte prefix
            if (CHECK_m_mmmm_field(m_mmmm_byte) == _0F38)
            {
                if (CHECK_VEX_0F38(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is 3 byte VEX and 0F38 n", MODULE_NAME);

                    if (CHECK_VEX_0F38_IMM8(op))
                    {
                        INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is 3 byte VEX and 0F38 and has an imm8\n", MODULE_NAME);
                        dsize++; // For the imm8
                    }
                }
                else
                {
                    PRINT_INSTR_ERROR
                    {
                        printk(KERN_INFO "%s: (disassemble_code) Instruction is 3 byte VEX and 0F38 but the op-code is not valid\n", MODULE_NAME);
                        print_hex_dump(KERN_INFO, "JIT: The op_code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                }
            }
            else if (CHECK_m_mmmm_field(m_mmmm_byte) == _0F3A)
            {
                if (CHECK_VEX_0F3A(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is 3 byte VEX and 0F3A\n", MODULE_NAME);

                    if (!CHECK_VEX_0F3A_NO_IMM8(op))
                    {
                        INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is 3 byte VEX and 0F3A and has imm8\n", MODULE_NAME);
                        dsize++; // For the imm8
                    }
                }
                else
                {
                    PRINT_INSTR_ERROR
                    {
                        printk(KERN_INFO "%s: (disassemble_code) Instruction is 3 byte VEX and 0F3A but the op-code is not valid\n", MODULE_NAME);
                        print_hex_dump(KERN_INFO, "JIT: The op_code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                }
            }
            else if (CHECK_m_mmmm_field(m_mmmm_byte) == _0F)
            {

                if (CHECK_VEX_0F(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is 3 byte VEX and 0F\n", MODULE_NAME);

                    if (VEX_NO_MODRM(op))
                        goto next;

                    if (CHECK_VEX_0F_IMM8(op))
                    {
                        INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is 3 byte VEX and 0F and has imm8\n", MODULE_NAME);
                        dsize++; // For the imm8
                    }
                }
                else
                {
                    PRINT_INSTR_ERROR
                    {
                        printk(KERN_INFO "%s: (disassemble_code) Instruction is 3 byte VEX and 0F but the op-code is not valid\n", MODULE_NAME);
                        print_hex_dump(KERN_INFO, "JIT: The op_code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                }
            }
            else
            {
                PRINT_INSTR_ERROR
                {
                    printk(KERN_INFO "%s: (disassemble_code) Instruction is 3 byte VEX but the m_mmmm_byte is not valid\n", MODULE_NAME);
                }
                goto error_exit;
            }

            goto check_mod_rm_byte;
        }

        else if (evex_pref_found) // 1 byte op-code
        {

            op_code_size = 1;

            INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is EVEX\n", MODULE_NAME);

            if (CHECK_mm_field(m_mmmm_byte) == _0F38)
            {

                if (CHECK_EVEX_0F38(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is EVEX and 0F38\n", MODULE_NAME);
                }
                else
                {
                    PRINT_INSTR_ERROR
                    {
                        printk(KERN_INFO "%s: (disassemble_code) Instruction is EVEX and 0F38 but the op-code is not valid\n", MODULE_NAME);
                        print_hex_dump(KERN_INFO, "JIT: The op_code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                }
            }
            else if (CHECK_mm_field(m_mmmm_byte) == _0F)
            {
                if (CHECK_EVEX_0F(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is EVEX and 0F\n", MODULE_NAME);
                    if (CHECK_EVEX_0F_IMM8(op))
                    {
                        INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is EVEX and 0F and has imm8\n", MODULE_NAME);
                        dsize++; // For the imm8
                    }
                }
                else
                {
                    PRINT_INSTR_ERROR
                    {
                        printk(KERN_INFO "%s: (disassemble_code) Instruction is EVEX and 0F but the op-code is not valid\n", MODULE_NAME);
                        print_hex_dump(KERN_INFO, "JIT: The op_code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                }
            }
            else if (CHECK_mm_field(m_mmmm_byte) == _0F3A)
            {
                if (CHECK_EVEX_0F3A(op))
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is EVEX and 0F3A\n", MODULE_NAME);
                    dsize++; // For the imm8
                }
                else
                {
                    PRINT_INSTR_ERROR
                    {
                        printk(KERN_INFO "%s: (disassemble_code) Instruction is EVEX and 0F3A but the op-code is not valid\n", MODULE_NAME);
                        print_hex_dump(KERN_INFO, "JIT: The op_code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                }
            }
            else
            {
                PRINT_INSTR_ERROR
                {
                    printk(KERN_INFO "%s: (disassemble_code) Instruction is EVEX but the m_mmmm_byte is not valid\n", MODULE_NAME);
                }
                goto error_exit;
            }

            goto check_mod_rm_byte;
        }

        /**--------------------------------------------------------------- GENERAL INSTRUCTION --------------------------------------------------------------------------------------*/
        if (CHECK_0F(op)) /* two and three byte opcode */
        {
            INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction has a multibyte op-code\n", MODULE_NAME);

            CHECK_CROSS_PAGE(++cur, start + size, "op-code");
            op = *(cur); // The second byte of the op-code

            multibyte = 1;

            if (CHECK_38(op))
            {
                op_code_size = 3;

                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction has a three byte 38 table op-code\n", MODULE_NAME);

                CHECK_CROSS_PAGE(++cur, start + size, "op-code");
                op = *(cur); // The third byte of the op-code

                if (CHECK_THREE_BYTE_038_UD(op))
                {
                    PRINT_INSTR_ERROR
                    {
                        print_hex_dump(KERN_ERR, "JIT: (disassemble_code) The UD 3-byte (0x38) op-code is (with prefix if exists): ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                }

                if (CHECK_MODRM38(op))
                    has_modrm = 1;
                if (CHECK_THREE_BYTE_038_ARITHMETIC(op))
                    instruction_type = ARITHMETIC;
                else if (CHECK_THREE_BYTE_038_MEMORY(op))
                    instruction_type = MEMORY;
                else if (CHECK_THREE_BYTE_038_CONTROL(op))
                    instruction_type = CONTROL;
                else
                    instruction_type = OTHER;
            }
            else if (CHECK_3A(op)) /* Three-byte 3A table */
            {
                op_code_size = 3;

                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction has a three byte 3A table op-code\n", MODULE_NAME);

                CHECK_CROSS_PAGE(++cur, start + size, "op-code");
                op = *(cur); // The third byte of the op-code

                if (CHECK_THREE_BYTE_03A_UD(op))
                {
                    PRINT_INSTR_ERROR
                    {
                        print_hex_dump(KERN_ERR, "JIT: (disassemble_code) The UD 3-byte (3A) op-code is (with prefix if exists) ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                }

                dsize++; // For the imm8, all the instructions in the 3A table have an imm8

                if (CHECK_MODRM3A(op))
                    has_modrm = 1;

                if (CHECK_THREE_BYTE_03A_ARITHMETIC(op))
                    instruction_type = ARITHMETIC;
                else if (CHECK_THREE_BYTE_03A_MEMORY(op))
                    instruction_type = MEMORY;
                else
                    instruction_type = OTHER;
            }

            /* Two-byte table */
            else
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction has a two byte op-code\n", MODULE_NAME);

                op_code_size = 2;

                if (CHECK_TWO_BYTE_UD(op))
                {
                    PRINT_INSTR_ERROR
                    {
                        print_hex_dump(KERN_ERR, "JIT: (disassemble_code) The UD 2-byte op-code (with prefix if exists) is: ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                    }
                    goto error_exit;
                }

                if (CHECK_MODRM2(op))
                    has_modrm = 1;
                if (CHECK_DATA1_2(op))
                    dsize++;
                if (CHECK_DATA66_2(op))
                    dsize += ddef;

                if (CHECK_TWO_BYTE_ARITHMETIC(op))
                    instruction_type = ARITHMETIC;
                else if (CHECK_TWO_BYTE_CONTROL(op))
                    instruction_type = CONTROL;
                else if (CHECK_TWO_BYTE_LOGICAL(op))
                    instruction_type = LOGICAL;
                else if (CHECK_TWO_BYTE_MEMORY(op))
                    instruction_type = MEMORY;
                else if (CHECK_TWO_BYTE_SYSTEM(op))
                    instruction_type = SYSTEM;
                else if (CHECK_TWO_BYTE_JCC(op))
                    instruction_type = JCC;
                else
                    instruction_type = OTHER;
            }
        }
        else /* one byte opcode */
        {
            INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction has a one byte op-code\n", MODULE_NAME);

            op_code_size = 1;

            if (CHECK_ONE_BYTE_UD(op))
            {
                PRINT_INSTR_ERROR
                {
                    print_hex_dump(KERN_ERR, "JIT: (disassemble_code) The UD 1-byte op-code (with prefix if exists) is: ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - (op_code_size - 1), num_prefixes + op_code_size, false);
                }

                goto error_exit;
            }

            if (CHECK_MODRM(op))
                has_modrm = 1;

            if (CHECK_TEST(op)) // 0xf6 e 0xf7 con OP-code-extension 0,1,2 ha un immediate rispettivamente a 8, 32 bit
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction is TEST\n", MODULE_NAME);

                CHECK_CROSS_PAGE(cur + 1, start + size, "op-code");
                modrm_byte = *(cur + 1); // The modrm byte

                if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_0)
                    dsize += (op & 1) ? ddef : 1;
            }
            if (CHECK_DATA1(op))
                dsize++;
            if (CHECK_DATA2(op))
                dsize += 2;
            if (CHECK_DATA66(op))
                dsize += ddef;
            if (CHECK_MEM67(op))
                msize += mdef;

            if (CHECK_ONE_BYTE_ARITH(op))
                instruction_type = ARITHMETIC;
            else if (CHECK_ONE_BYTE_CONTROL(op))
                instruction_type = CONTROL;
            else if (CHECK_ONE_BYTE_LOGICAL(op))
                instruction_type = LOGICAL;
            else if (CHECK_ONE_BYTE_MEMORY(op))
                instruction_type = MEMORY;
            else if (CHECK_ONE_BYTE_SYSTEM(op))
                instruction_type = SYSTEM;
            else if (CHECK_ONE_BYTE_JCC(op))
                instruction_type = JCC;
            else if (CHECK_ONE_BYTE_JMP(op))
                instruction_type = JMP;
            else if (CHECK_ONE_BYTE_CALL(op))
                instruction_type = CALL;
            else if (CHECK_ONE_BYTE_RET(op))
                instruction_type = RET;
            else
                instruction_type = OTHER;
        }

        /**------------------------------------------------------------------ MODRM BYTE -------------------------------------------------------------------------------------*/
        if (has_modrm)
        { // The instruction has a modrm byte.

        check_mod_rm_byte:

            CHECK_CROSS_PAGE(++cur, start + size, "modrm");
            modrm_byte = *(cur); // The modrm byte

            INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) The modrm byte is %x\n", MODULE_NAME, modrm_byte);

            if (!multibyte && CHECK_OP_CODE_EXT(op)) // Group 0x80, 0x81, 0x83, 0xf6, 0xf7, 0xff
            {
                if (MODRM_REG_OPCODE(modrm_byte) > OPCODE_EXTENSION_7) // Consistency check
                {
                    PRINT_INSTR_ERROR printk(KERN_ERR "%s: (disassemble_code) Error: MODRM_REG_OPCODE is not valid and the instruction should have an OP_CODE_EXTENSION\n", MODULE_NAME);
                    goto error_exit;
                }

                if (CHECK_80_81_83(op))
                {
                    // OR, AND, XOR
                    if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_1 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_4 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_6)
                        instruction_type = LOGICAL;
                    // CMP
                    else if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_7)
                        instruction_type = CONTROL;
                }
                else if (CHECK_F6_F7(op))
                {
                    // NOT, NEG
                    if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_2 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_3)
                        instruction_type = LOGICAL;
                    // MUL, IMUL, DIV, IDIV
                    else if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_4 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_5 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_6 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_7)
                        instruction_type = ARITHMETIC;
                }
                else if (CHECK_FF(op))
                {

                    // CALL
                    if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_2 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_3)
                        instruction_type = CALL;
                    // JMP
                    else if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_4 || MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_5)
                        instruction_type = JMP;
                    // PUSH
                    else if (MODRM_REG_OPCODE(modrm_byte) == OPCODE_EXTENSION_6)
                        instruction_type = MEMORY;
                }
            }

            // INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Checking ModRM_MOD\n", MODULE_NAME);

            if (MODRM_MOD(modrm_byte) == REGISTER)
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) ModRM_MOD is REGISTER\n", MODULE_NAME);
                goto no_sib;
            }

            else if (MODRM_MOD(modrm_byte) == INDIRECT)
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) ModRM_MOD is INDIRECT\n", MODULE_NAME);
                if (MODRM_R_M(modrm_byte) == EIP_DISP32)
                {
                    INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) ModRM_R_M [EIP] + DISP32\n", MODULE_NAME);
                    if (mdef == 2) // operand_ovveride_prefix found
                        msize += WORD_SIZE;
                    else
                        msize += DWORD_SIZE;
                }
            }

            else if (MODRM_MOD(modrm_byte) == INDIRECT_DISP8)
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) ModRM_MOD is INDIRECT_DISP8\n", MODULE_NAME);
                msize += BYTE_SIZE;
            }

            else if (MODRM_MOD(modrm_byte) == INDIRECT_DISP32)
            {
                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) ModRM_MOD is INDIRECT_DISP32\n", MODULE_NAME);

                if (mdef == 2) // operand_ovveride_prefix found
                    msize += WORD_SIZE;
                else
                    msize += DWORD_SIZE;
            }

            else
            {
                PRINT_INSTR_ERROR
                {
                    printk(KERN_INFO "%s: (disassemble_code) ModRM_MOD is not valid\n", MODULE_NAME);
                }
                goto error_exit;
            }

            if (MODRM_R_M(modrm_byte) == SIB) // The instruction has a SIB byte.
            {

                INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) ModRM_R_M is SIB\n", MODULE_NAME);

                CHECK_CROSS_PAGE(++cur, start + size, "sib");
                sib_byte = *(cur); // The SIB byte

                /**
                 *
                 *      SIB Note 1                                    SIB Note 2
                 *  Mod bits	base                           Mod bits	        base
                 *  00	        disp32                         00	            disp32
                 *  01	        RBP/EBP+disp8                  01	            R13/R13D+disp8 <-- Il displacement è già indicato dal MOD R/M byte
                 *  10	        RBP/EBP+disp32                 10	            R13/R13D+disp32 <-- Il displacement è già indicato dal MOD R/M byte
                 *
                 */

                if (SIB_BASE(sib_byte) == SIB_DISPLACEMENT && MODRM_MOD(modrm_byte) == INDIRECT)
                {

                    INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) ModRM_MOD is 00 and SIB_BASE is 101\n", MODULE_NAME);
                    if (mdef == 2) // operand_ovveride_prefix found
                        msize += WORD_SIZE;
                    else
                        msize += DWORD_SIZE;
                }
            }
        no_sib:
        }

        /**--------------------------------------------------------------- NO MODRM BYTE -------------------------------------------------------------------------------*/
        else // NO MODR/M byte
        {
            INSTRUCTION_INFO printk(KERN_INFO "%s: (disassemble_code) Instruction has no modrm byte\n", MODULE_NAME);
        }

        /* REX.W causes 66h to be ignored */
        if (rex_w_found && !multibyte)
        {
            if (CHECK_IMM64(op))
                dsize = 8;
            if (CHECK_OFF64(op))
                msize = 8;
        }

    next:
        cur += msize + dsize + 1; // The next byte after the instruction.

        total_size = cur - first_op;

        CHECK_CROSS_PAGE(cur - 1, start + size, "operand"); // The instruction is within the page.

        offset = (unsigned long)cur - start;
        aux = start + offset; // Following byte of the latest found instruction.

        PRINT_INSTRUCTION
        {
            print_hex_dump(KERN_INFO, "JIT: (disassemble_code) The complete instruction is ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - total_size, total_size + num_prefixes, false);
        }

        if (instruction_type == JCC)
        {
            // We found a jcc instruction.
            DEBUG_INFO print_hex_dump(KERN_INFO, "JIT: (disassemble_code) JCC is ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - total_size, total_size + num_prefixes, false);
            goto found_exit;
        }

        else if (instruction_type == JMP)
        {
            // We found a jmp instruction.
            DEBUG_INFO print_hex_dump(KERN_INFO, "JIT: (disassemble_code) JMP is ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - total_size, total_size + num_prefixes, false);
            goto found_exit;
        }
        else if (instruction_type == CALL)
        {
            // We found a call instruction.
            DEBUG_INFO print_hex_dump(KERN_INFO, "JIT: (disassemble_code) CALL is ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - total_size, total_size + num_prefixes, false);
            goto found_exit;
        }

        else if (instruction_type == RET)
        {
            // We found a ret or iret instruction.
            DEBUG_INFO print_hex_dump(KERN_INFO, "JIT: (disassemble_code) RET is ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - total_size, total_size + num_prefixes, false);
            goto found_exit;
        }

        else if (instruction_type == ARITHMETIC)
            stats->num_of_arithmetic_instructions++;

        else if (instruction_type == CONTROL)
            stats->num_of_control_instructions++;

        else if (instruction_type == LOGICAL)
            stats->num_of_logical_instructions++;

        else if (instruction_type == MEMORY)
            stats->num_of_data_transfer_instructions++;

        else if (instruction_type == SYSTEM)
            stats->num_of_system_instructions++;

        else if (instruction_type == OTHER)
            stats->num_of_miscellaneous_instructions++;

        else if (evex_pref_found || vex_pref_found)
            stats->num_of_vex_or_evex_instructions++;

        if ((unsigned long)cur == start + size)
        {
            DEBUG_INFO printk(KERN_INFO "%s: (disassemble_code) The instruction ends exactly at the page end and isn't a JMP/Jcc/CALL/RET \n", MODULE_NAME);
            PRINT_INSTRUCTION print_hex_dump(KERN_INFO, "JIT: (disassemble_code) The (page-end aligned) last instruction is ", DUMP_PREFIX_NONE, 16, 1, cur - num_prefixes - total_size, total_size + num_prefixes, false);
            goto cross_page_exit;
        }

        /**-------------------------------------------------------------------- RESET VARIABLES ---------------------------------------------------------------------------------------------*/

        evex_pref_found = 0;
        vex_pref_found = 0;
        rex_w_found = 0;
        multibyte = 0;
        has_modrm = 0;

        ddef = DWORD_SIZE;
        mdef = DWORD_SIZE;

        msize = 0;
        dsize = 0;
        total_size = 0;
        num_prefixes = 0;
        op_code_size = 1; // We need to reset the size of the current string. We found a matching instruction
        instruction_type = 0;
    }

cross_page_exit:

    if (aux == start) // No istruction found at the page end. It's a cross-instuction and the disassembler started from that one.
    {
        DEBUG_INFO printk(KERN_INFO "%s: (disassemble_code) Found no instructions until page end\n", MODULE_NAME);
    }

    *end = aux; // We need to return the byte that follows the last instruction found in the page.
    return DISASSEMBLE_CONTINUE;

error_exit:

    return DISASSEMBLE_ERROR; // We didn't find any matching instruction.

found_exit: // We found a matching instruction.

    stats->num_of_control_instructions++;

    offset = (unsigned long)cur - start;
    *end = start + offset; // We need to return the first byte of the instruction after the found one.

    if (instruction_type == JCC)
        return DISASSEMBLE_SUCCESS | JCC_SUCCESS;
    else if (instruction_type == JMP)
        return DISASSEMBLE_SUCCESS | JMP_SUCCESS;
    else if (instruction_type == CALL)
        return DISASSEMBLE_SUCCESS | CALL_SUCCESS;
    else
        return DISASSEMBLE_SUCCESS | RET_SUCCESS;
}

/**
 * Substitute the bytes except the ones between start and end with illegal instructions.
 * @param data The data of the pages of the zone.
 * @param start The start byte of the zone to not substitute.
 * @param end The end byte of the zone to not substitute.
 * @param num_pages The number of pages to substitute.
 * @param vma The vm_area_struct of the zone.
 *
 * @return 0 on success, -1 on failure.
 */
int close_outer_zone(char *data, unsigned long start, unsigned long end, int num_pages, struct vm_area_struct *vma)
{
    unsigned long base_addr = start & PAGE_MASK;
    unsigned long start_offset = start & ~PAGE_MASK;
    unsigned long end_offset = (end & ~PAGE_MASK) + (num_pages - 1) * PAGE_SIZE;
    unsigned long size = num_pages * PAGE_SIZE;
    unsigned long int ret = 0;
    char *k_data = NULL;

    DELETE_ME printk(KERN_INFO "%s: Closing the bytes outside the zone [%lx, %lx) from page %lx\n", MODULE_NAME, start, end, base_addr);

    if (start == 0 || end == 0)
    {
        printk(KERN_ERR "%s: (close_outer_zone) Error: start or end is 0\n", MODULE_NAME);
        return -1;
    }

    if (end <= start)
    {
        printk(KERN_ERR "%s: (close_outer_zone) Error: end <= start: [%lx, %lx]\n", MODULE_NAME, start, end);
        return -1;
    }

    k_data = kmalloc(num_pages * PAGE_SIZE, GFP_ATOMIC);
    if (!k_data)
    {
        printk(KERN_ERR "%s: (close_outer_zone) Failed to allocate memory for the page\n", MODULE_NAME);
        return -1;
    }

    memcpy(k_data, data, size);

#ifdef LUAJIT_TEST
    /** Luajit uses the first 10 bytes of read-exe pages to save the rbp. Something strange ...*/
    // memset(k_data + 10, INVALID_ONE_BYTE_OPCODE, start_offset - 10); // Substitute the bytes before the start with illegal instructions.
#else
    memset(k_data, INVALID_ONE_BYTE_OPCODE, start_offset); // Substitute the bytes before the start with illegal instructions.
#endif

    memset(k_data + end_offset, INVALID_ONE_BYTE_OPCODE, size - end_offset); // Substitute the bytes after the end with illegal instructions.

    ret = write_pages_on_not_writable_user_pages(base_addr, k_data, num_pages, vma);
    if (ret != 0)
    {
        printk(KERN_ERR "%s: (close_outer_zone) Failed to write to the user space\n", MODULE_NAME);
        kfree(k_data);
        return -1;
    }

    kfree(k_data);
    return 0;
}


/**
 * Substitute the bytes with illegal instructions.
 * @param start The start byte of the zone to substitute.
 * @param end The end byte of the zone to substitute.
 * @param num_pages The number of pages to substitute.
 * @param vma The vm_area_struct of the zone.
 *
 * @return 0 on success, -1 on failure.
 */
int close_inner_zone(unsigned long start, unsigned long end, int num_pages)
{

    unsigned long start_offset = start & ~PAGE_MASK;
    unsigned long end_offset = (end & ~PAGE_MASK) + (num_pages - 1) * PAGE_SIZE;
    unsigned long size = end - start;
    unsigned long int ret = 0;
    char *k_data = NULL;

    DELETE_ME printk(KERN_INFO "%s: Closing inner zone [%lx, %lx) from page %lx\n", MODULE_NAME, start, end, start & PAGE_MASK);

    if (start == 0 || end == 0)
    {
        printk(KERN_ERR "%s: (close_inner_zone) Error: start or end is 0\n", MODULE_NAME);
        return -1;
    }

    if (end <= start)
    {
        printk(KERN_ERR "%s: (close_inner_zone) Error: end <= start: [%lx, %lx]\n", MODULE_NAME, start, end);
        return -1;
    }

    k_data = kmalloc(size, GFP_ATOMIC);
    if (!k_data)
    {
        printk(KERN_ERR "%s: (close_inner_zone) Failed to allocate memory for the page\n", MODULE_NAME);
        return -1;
    }

#ifdef LUAJIT_TEST
    // TODO: FIX
    /** Luajit uses the first 10 bytes of read-exe pages to save the rbp. Something strange ...*/
    // memset(k_data + 10, INVALID_ONE_BYTE_OPCODE, start_offset - 10); // Substitute the bytes before the start with illegal instructions.
#else
    memset(k_data, INVALID_ONE_BYTE_OPCODE, size); // Substitute the bytes before the start with illegal instructions.
#endif

    ret = write_zone_on_not_writable_user_pages(k_data, start, end, num_pages);
    if (ret != 0)
    {
        printk(KERN_ERR "%s: (close_inner_zone) Failed to write to the user space\n", MODULE_NAME);
        kfree(k_data);
        return -1;
    }

    kfree(k_data);
    return 0;

}
/**
 * Restore the bytes of the zone.
 *
 * @param data The data of the zone.
 * @param start The start byte of the zone.
 * @param end The end byte of the zone.
 * @param num_pages The number of pages of the zone.
 *
 * @return 0 on success, -1 on failure.
 */
int restore_zone_bytes(char *data, unsigned long start, unsigned long end, int num_pages)
{
    unsigned char compare_value[1] = {INVALID_ONE_BYTE_OPCODE};
    int ret = 0;
    bool all_invalid_one_byte_opcode = false;


    /* DELETE_ME print_hex_dump(KERN_INFO, "(restonre_zone_bytes) trying to restore: ", DUMP_PREFIX_NONE, 16, 1, data, end - start, false); */
                    
    DEBUG_INFO printk(KERN_INFO "%s: Restoring zone [%lx, %lx) \n", MODULE_NAME, start, end);

    if (data == NULL)
    {
        printk(KERN_ERR "%s: (restore_zone_bytes) Error: data is NULL\n", MODULE_NAME);
        return -1;
    }

    if (end <= start)
    {
        printk(KERN_ERR "%s: (restore_zone_bytes) Error: end <= start\n", MODULE_NAME);
        return -1;
    }

    if (memcmp(data, compare_value, 1) == 0) // The first byte of the first instruction cannot be 0x0E
        all_invalid_one_byte_opcode = true;

    if (all_invalid_one_byte_opcode == true) // If all the bytes are 0x0E there is a problem
    {
        printk(KERN_ERR "%s: (restore_zone_bytes) Error: all the bytes are 0x0E\n", MODULE_NAME);
        return ALL_INVALID_ONE_BYTE_OPCODE;
    }

    // // Writing the zone in the user space
    ret = write_zone_on_not_writable_user_pages(data, start, end, num_pages);
    if (ret != 0)
    {
        printk(KERN_ERR "%s: (restore_zone_bytes) Failed to write to the user space\n", MODULE_NAME);
        return -1;
    }

    AUDIT printk(KERN_INFO "%s: Zone bytes correctly restored\n", MODULE_NAME);
    return 0;
}

/**
 * Restore the page with the given address.
 *
 * @param addr The address of the page to restore.
 *
 * @return 0 on success, -1 on failure.
 */
int restore_page(unsigned long addr)
{
    unsigned long page_addr = addr & PAGE_MASK;
    int ret = 0;
    int bkt = get_shared_page_bucket(PAGE_BUCKET_BITS);
    struct page_hash_node *curr = NULL;
    pid_t pid = current->tgid;
    struct page_hash_node *curr_shared = NULL;
    int orig_exe_bit = -1;
    int orig_write_bit = -1;

    hash_for_each_possible(page_hash_table, curr, node, pid)
    {
        if (curr->info != NULL && curr->pid == pid && curr->address == page_addr)
        {
            AUDIT printk(KERN_INFO "%s: Found page %lx for pid %d\n", MODULE_NAME, curr->address, pid);
            break;
        }
    }

    if (curr == NULL || curr->info == NULL)
    {
        orig_exe_bit = is_bit_set(page_addr, ORIG_EXE_BIT);
        orig_write_bit = is_bit_set(page_addr, ORIG_WRITE_BIT);

        AUDIT printk(KERN_INFO "%s: (restore_page) Failed to find the page %lx - (ORIG_EXE: %d - ORIG_WRITE: %d) for pid %d\n", MODULE_NAME, page_addr, orig_exe_bit, orig_write_bit, pid);
        return PAGE_NOT_FOUND;
    }

    if (is_bit_set(page_addr, WRITE_BIT) == true)
    {
        ret = copy_to_user((char *)page_addr, curr->info->data, PAGE_SIZE);
        if (ret != 0)
        {
            printk(KERN_ERR "%s: (restore_page) Failed to copy the page from the user space\n", MODULE_NAME);
            return WRITE_ERROR;
        }
    }
    else
    {
        ret = write_pages_on_not_writable_user_pages(page_addr, curr->info->data, 1, NULL);
        if (ret != 0)
        {
            printk(KERN_ERR "%s: (restore_page) Failed to write to the user space\n", MODULE_NAME);
            return WRITE_ERROR;
        }
    }

    hash_del_atomic(&curr->node);

    if (curr->info->is_shared) // Remove the shared page from the hash table
    {
        hlist_for_each_entry(curr_shared, &page_hash_table[bkt], node)
        {
            if (curr_shared->info != NULL && curr_shared->address == page_addr)
            {
                AUDIT printk(KERN_INFO "%s: Found shared page %lx for pid %d\n", MODULE_NAME, curr_shared->address, pid);

                hash_del_atomic(&curr_shared->node);
                kfree(curr_shared);
                break;
            }
        }
    }

    kfree(curr->info);
    kfree(curr);

    AUDIT printk(KERN_INFO "%s: Page correctly restored\n", MODULE_NAME);
    return PAGE_FOUND;
}

/**
 * Restore the shared page with the given address.
 *
 * @param addr The address of the page to restore.
 *
 * @return 0 on success, -1 on failure.
 */
int restore_sh_page(unsigned long addr)
{
    unsigned long page_addr = addr & PAGE_MASK;
    int ret = 0;
    int bkt = get_shared_page_bucket(PAGE_BUCKET_BITS);
    struct page_hash_node *curr = NULL;
    pid_t pid = current->tgid;
    int orig_exe_bit = -1;
    int orig_write_bit = -1;

    hlist_for_each_entry(curr, &page_hash_table[bkt], node)
    {
        if (curr->info != NULL && curr->address == page_addr)
        {
            AUDIT printk(KERN_INFO "%s: Found shared page %lx\n", MODULE_NAME, curr->address);
            break;
        }
    }

    if (curr == NULL || curr->info == NULL)
    {
        orig_exe_bit = is_bit_set(page_addr, ORIG_EXE_BIT);
        orig_write_bit = is_bit_set(page_addr, ORIG_WRITE_BIT);

        AUDIT printk(KERN_INFO "%s: (restore_page) Failed to find the shared page %lx - (ORIG_EXE: %d - ORIG_WRITE: %d) for pid %d\n", MODULE_NAME, page_addr, orig_exe_bit, orig_write_bit, pid);
        return PAGE_NOT_FOUND;
    }

    if (is_bit_set(page_addr, WRITE_BIT) == true)
    {
        ret = copy_to_user((char *)page_addr, curr->info->data, PAGE_SIZE);
        if (ret != 0)
        {
            printk(KERN_ERR "%s: (restore_page) Failed to copy the shared page from the user space\n", MODULE_NAME);
            return WRITE_ERROR;
        }
    }
    else
    {

        ret = write_pages_on_not_writable_user_pages(page_addr, curr->info->data, 1, NULL);
        if (ret != 0)
        {
            printk(KERN_ERR "%s: (restore_page) Failed to write to the user space\n", MODULE_NAME);
            return WRITE_ERROR;
        }
    }

    hash_del_atomic(&curr->node);
    kfree(curr->info);
    kfree(curr);

    AUDIT printk(KERN_INFO "%s: Page correctly restored\n", MODULE_NAME);
    return PAGE_FOUND;
}
