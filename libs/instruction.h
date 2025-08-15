#ifndef INSTRUCTION_MAP_H
#define INSTRUCTION_MAP_H

#include "ld.h"

enum instruction_type
{
    ARITHMETIC = 1, // ADD,SUB, MUL, DIV, FSIN, FCOS, PADDW, PSUBW, ADDPS, ADDPD, PMULLD, PAVGW, DPPD, SHR and SHL.

    // CONTROL INSTUCTIONS
    JCC,  // 2
    JMP,  // 3
    RET,  // 4
    CALL, // 5

    CONTROL,   // 6  // CMP, CMPS, CMPPS, PCMPEQW, REP and LOOP instructions.
    NOT_VALID, // 7 // Invalid Instruction in 64-Bit Mode
    UD,        // 8     // Invalid op-code
    LOGICAL,   // 9   // AND, OR, and NOT.
    MEMORY,    // 10   // MOV,CMOV, XCHG, PUSH, POP, LODS, STOS, MOVS, MOVAPS, MOVAPD, IN,OUT, INS, OUTS, LAHF, SAHF, PREFETCH, FLDPI, FLDCW, FXSAVE, LEA,and LDS
    SYSTEM,    // 11   // LOCK, LGDT, SGDT, LTR, STR and XSAVE,
    OTHER,     // 12   // NOP, CPUID, SCAS, CLC, STC, CLI, HLT, WAIT, MFENCE, PACKSSWB, MAXPS, MINPS, PAVGB, PAVGW, PEXTRW, PINSRW, PMAXSW, PMAXUB, PMINSW, PMINUB, PMOVMSK

    EVEX, // 13
    VEX   // 14
};

#define MAX_INSTRUCTION_SIZE 15

/**
Nell'architettura x86, la determinazione se un operando (es. r/m8) è un registro o un byte in memoria è fatta attraverso il byte ModR/M che segue l'opcode.
 7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
| Mod  | Reg/Opcode |    R/M    |
+---+---+---+---+---+---+---+---+

Mod: Questi due bit determinano se l'operando è un registro o un indirizzo di memoria.
Se Mod è 11, allora l'operando è un registro. Altrimenti, l'operando è un indirizzo di memoria.
0 = 00 = Indirizzamento indiretto (es. [eax])
1 = 01 = Indirizzamento indiretto con offset di 8 bit (es. [eax+0x10])
2 = 10 = Indirizzamento indiretto con offset di 32 bit (es. [eax+0x1000])
3 = 11 = Registro (es. eax)
*/
#define MODRM_MOD(x) ((x & 0xC0) >> 6)

/**
Reg/Opcode: Questi tre bit sono usati per estendere l'opcode o per specificare un registro (es. r32).
Nel caso di op code extension 2 indica ADC, 0 ADD, 4 AND e cosi via
*/
#define MODRM_REG_OPCODE(x) ((x & 0x38) >> 3)
/**
R/M: Questi tre bit sono usati per specificare un registro o un indirizzo di memoria (es r/m32), a seconda del valore di Mod.
*/
#define MODRM_R_M(x) (x & 0x07)

#define NO_OPERAND_SIZE 0
#define BYTE_SIZE 1
#define WORD_SIZE 2
#define DWORD_SIZE 4
#define QWORD_SIZE 8
#define XMMWORD_SIZE 128 / 8
#define YMMWORD_SIZE 256 / 8
#define ZMMWORD_SIZE 512 / 8

/**
0 = 0 = Indirizzamento indiretto (es. [eax])
*/
#define INDIRECT 0x0
/**
1 = 01 = Indirizzamento indiretto con offset di 8 bit (es. [eax+0x10])
*/
#define INDIRECT_DISP8 0x1
/**
2 = 10 = Indirizzamento indiretto con offset di 32 bit (es. [eax+0x1000])
*/
#define INDIRECT_DISP32 0x2
/**
3 = 11 = Registro (es. eax)
*/
#define REGISTER 0x3

#define EIP_DISP32 0x05

/**
 *  Il byte SIB (Scale-Index-Base) è un byte opzionale nell'architettura x86 che viene utilizzato per calcolare un indirizzo di memoria. Il byte SIB è diviso in tre campi: Scale, Index e Base.
 *
 *  7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * | Scale |  Index   |    Base    |
 * +---+---+---+---+---+---+---+---+
 *
 * - Scale (2 bit): Determina il fattore di moltiplicazione per il registro indice. I valori possono essere 00 (moltiplica per 1), 01 (moltiplica per 2), 10 (moltiplica per 4) e 11 (moltiplica per 8).
 *
 * - Index (3 bit): Specifica il registro indice. Questo registro viene moltiplicato per il valore del campo Scale e aggiunto al valore del registro base per calcolare l'indirizzo. I valori possono variare da 000 (registro eax) a 111 (registro edi). Un valore di 100 indica che non c'è un registro indice.
 *
 * - Base (3 bit): Specifica il registro base. Il valore di questo registro viene aggiunto al risultato del campo Index moltiplicato per il campo Scale per calcolare l'indirizzo. I valori possono variare da 000 (registro eax) a 111 (registro edi).
 * Un valore di 101 nel campo Base con un valore di 00 nel campo Mod del byte ModR/M indica che c'è un displacement a 32 bit ma non c'è un registro base.
 *
 *
 * Nell'architettura x86-64, il campo Base del byte SIB può avere un valore speciale di `101` (5 in esadecimale), che normalmente rappresenta il registro RBP o R13. Tuttavia, quando i bit Mod del byte ModR/M sono `00`, il campo Base `101` non rappresenta più il registro RBP o R13, ma indica invece un displacement a 32 bit (disp32).
 * Le tabelle stanno quindi mostrando come interpretare il campo Base quando ha un valore di `101`, in base ai bit Mod:
 * - SIB Note 1:
  - Se i bit Mod sono `00`, il campo Base `101` indica un displacement a 32 bit.
  - Se i bit Mod sono `01`, il campo Base `101` indica il registro RBP/EBP più un displacement a 8 bit (disp8).
  - Se i bit Mod sono `10`, il campo Base `101` indica il registro RBP/EBP più un displacement a 32 bit (disp32).

  - SIB Note 2:
  - Se i bit Mod sono `00`, il campo Base `101` indica un displacement a 32 bit.
  - Se i bit Mod sono `01`, il campo Base `101` indica il registro R13/R13D più un displacement a 8 bit (disp8).
  - Se i bit Mod sono `10`, il campo Base `101` indica il registro R13/R13D più un displacement a 32 bit (disp32).

Queste tabelle sono specifiche per l'architettura x86-64. In altre varianti dell'architettura x86, l'interpretazione del campo Base può essere diversa.
 */
/**
4 = 100 = SIB (Scale Index Base)
*/
#define SIB 0x04
#define SIB_DISPLACEMENT 0x05
/**
Scale: These two bits determine the scale factor for the index register.
*/
#define SIB_SCALE(x) ((x & 0xC0) >> 6)

/**
Index: These three bits specify the index register.
*/
#define SIB_INDEX(x) ((x & 0x38) >> 3)

/**
Base: These three bits specify the base register.
*/
#define SIB_BASE(x) (x & 0x07)

/**
 * The following are the possible values of the REX prefix.
 *
I prefissi REX (Register Extension) sono utilizzati nell'architettura x86-64 per estendere la dimensione e il numero di registri disponibili.
Questi prefissi sono utilizzati per indicare l'uso di registri a 64 bit e per accedere ai registri aggiuntivi disponibili in x86-64.

REX: Indica l'uso di un'istruzione REX. Non estende nessun campo specifico.
REX_B: Estende il campo ModR/M o SIB base.
REX_X: Estende il campo SIB index.
REX_R: Estende il campo ModR/M reg.
REX_W: Indica l'uso di operandi a 64 bit.
Le varianti con più di una lettera (come REX_RB, REX_RX, ecc.) combinano le estensioni di più campi.
*/

#define REX 0x40
#define REX_B 0x41
#define REX_X 0x42
#define REX_XB 0x43
#define REX_R 0x44
#define REX_RB 0x45
#define REX_RX 0x46
#define REX_RXB 0x47
#define REX_W 0x48
#define REX_WB 0x49
#define REX_WX 0x4A
#define REX_WXB 0x4B
#define REX_WR 0x4C
#define REX_WRB 0x4D
#define REX_WRX 0x4E
#define REX_WRXB 0x4F

#define FS_PREFIX 0x64
#define GS_PREFIX 0x65
#define OPERAND_OVERRIDE_PREFIX 0x66
#define ADDRESS_SIZE_OVERRIDE_PREFIX 0x67

#define LOCKPREFIX 0xF0
#define REPNE_PREFIX 0xF2 // sse2 too
#define REP_PREFIX 0xF3   // sse1 too

#define EVEX_PREFIX 0x62
#define VEX_PREFIX_2 0xC5
#define VEX_PREFIX_3 0xC4

#define NULL_PREFFIX_1 0x26
#define NULL_PREFFIX_2 0x2E
#define NULL_PREFFIX_3 0x36
#define NULL_PREFFIX_4 0x3E

enum modrm_usage
{
    NO_MODRM = 0xFF,           // L'istruzione non ha un byte ModR/M
    MODRM = 0xFE,              // L'istruzione ha un byte ModR/M
    OPCODE_EXTENSION_0 = 0x00, // Il byte ModR/M è utilizzato come estensione dell'opcode
    OPCODE_EXTENSION_1 = 0x01,
    OPCODE_EXTENSION_2 = 0x02,
    OPCODE_EXTENSION_3 = 0x03,
    OPCODE_EXTENSION_4 = 0x04,
    OPCODE_EXTENSION_5 = 0x05,
    OPCODE_EXTENSION_6 = 0x06,
    OPCODE_EXTENSION_7 = 0x07,
};

#endif