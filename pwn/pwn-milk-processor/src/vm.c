#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#define MAX_PROGRAM_SIZE 4096 
#define MAX_STACK_SIZE 256    
#define NUM_REGISTERS 8

typedef enum {
    // Control Flow
    OP_NOP  = 0x00,
    OP_JMP  = 0x01,
    OP_JE   = 0x02,
    OP_JNE  = 0x03, 
    OP_CALL = 0x04, 
    OP_RET  = 0x05, 

    // Data Movement
    OP_MOV_REG_IMM = 0x10,
    OP_MOV_REG_REG = 0x11,

    // Stack Operations
    OP_PUSH_IMM = 0x20, 
    OP_PUSH_REG = 0x21, 
    OP_POP_REG  = 0x22, 

    // Arithmetic
    OP_ADD_REG_IMM = 0x30,
    OP_ADD_REG_REG = 0x31,
    OP_SUB_REG_IMM = 0x32,
    OP_SUB_REG_REG = 0x33,
    
    // Logical
    OP_XOR_REG_IMM = 0x40,
    OP_XOR_REG_REG = 0x41,

    // Comparison
    OP_CMP_REG_IMM = 0x50,
    OP_CMP_REG_REG = 0x51,  

    // System
    OP_HALT = 0xFF 
} Opcode;


typedef struct {
    unsigned char instructions[MAX_PROGRAM_SIZE];
    int32_t stack[MAX_STACK_SIZE];

    int32_t sp; 
    int32_t ip; 
    
    int32_t regs[NUM_REGISTERS];

    bool zf;

    bool running;
} VM;
VM vm;

void banner();
void run_vm();
int32_t fetch_imm32();
uint8_t fetch_reg_idx();


void banner() {
    puts("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    puts("        Welcome to the Milk Processor™       ");
    puts("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    puts("Give me your best MILK byte-code.");
}


void run_vm() {
    vm.running = true;
    while (vm.running && vm.ip < MAX_PROGRAM_SIZE) {
        uint8_t opcode = vm.instructions[vm.ip++];
        
        uint8_t r1_idx, r2_idx;
        int32_t imm_val;

        switch (opcode) {
            case OP_NOP:
                break;
            case OP_JMP:
                imm_val = fetch_imm32();
                vm.ip = imm_val;
                break;
            case OP_JE:
                imm_val = fetch_imm32();
                if (vm.zf) {
                    vm.ip = imm_val;
                }
                break;
            case OP_JNE:
                imm_val = fetch_imm32();
                if (!vm.zf) {
                    vm.ip = imm_val;
                }
                break;
            case OP_CALL:
                imm_val = fetch_imm32();
                if (vm.sp >= MAX_STACK_SIZE) {
                    vm.running = false;
                    break;
                }
                vm.stack[vm.sp++] = vm.ip; 
                vm.ip = imm_val; 
                break;
            case OP_RET:
                if (vm.sp <= 0) {
                    vm.running = false;
                    break;
                }
                vm.ip = vm.stack[--vm.sp];
                break;
            case OP_MOV_REG_IMM:
                r1_idx = fetch_reg_idx();
                imm_val = fetch_imm32();
                vm.regs[r1_idx] = imm_val;
                break;
            case OP_MOV_REG_REG:
                r1_idx = fetch_reg_idx();
                r2_idx = fetch_reg_idx();
                vm.regs[r1_idx] = vm.regs[r2_idx];
                break;
            case OP_PUSH_IMM:
                imm_val = fetch_imm32();
                if (vm.sp >= MAX_STACK_SIZE) {
                    vm.running = false;
                    break;
                }
                vm.stack[vm.sp++] = imm_val;
                break;
            case OP_PUSH_REG:
                r1_idx = fetch_reg_idx();
                if (vm.sp > MAX_STACK_SIZE) {
                    vm.running = false;
                    break;
                }
                vm.stack[vm.sp++] = vm.regs[r1_idx];
                break;
            case OP_POP_REG:
                r1_idx = fetch_reg_idx();
                if (vm.sp <= 0) {
                    vm.running = false;
                    break;
                }
                vm.regs[r1_idx] = vm.stack[--vm.sp];
                break;
            case OP_ADD_REG_IMM:
                r1_idx = fetch_reg_idx();
                imm_val = fetch_imm32();
                vm.regs[r1_idx] += imm_val;
                break;
            case OP_ADD_REG_REG:
                r1_idx = fetch_reg_idx();
                r2_idx = fetch_reg_idx();
                vm.regs[r1_idx] += vm.regs[r2_idx];
                break;
            case OP_SUB_REG_IMM:
                r1_idx = fetch_reg_idx();
                imm_val = fetch_imm32();
                vm.regs[r1_idx] -= imm_val;
                break;
            case OP_SUB_REG_REG:
                r1_idx = fetch_reg_idx();
                r2_idx = fetch_reg_idx();
                vm.regs[r1_idx] -= vm.regs[r2_idx];
                break;
            case OP_XOR_REG_IMM:
                r1_idx = fetch_reg_idx();
                imm_val = fetch_imm32();
                vm.regs[r1_idx] ^= imm_val;
                break;
            case OP_XOR_REG_REG:
                r1_idx = fetch_reg_idx();
                r2_idx = fetch_reg_idx();
                vm.regs[r1_idx] ^= vm.regs[r2_idx];
                break;
            case OP_CMP_REG_IMM:
                r1_idx = fetch_reg_idx();
                imm_val = fetch_imm32();
                vm.zf = (vm.regs[r1_idx] == imm_val);
                break;
            case OP_CMP_REG_REG:
                r1_idx = fetch_reg_idx();
                r2_idx = fetch_reg_idx();
                vm.zf = (vm.regs[r1_idx] == vm.regs[r2_idx]);
                break;
            case OP_HALT:
                vm.running = false;
                break;
            default:
                vm.running = false;
                break;
        }
    }
}

int32_t fetch_imm32() {
    int32_t val;
    memcpy(&val, &vm.instructions[vm.ip], sizeof(int32_t));
    vm.ip += sizeof(int32_t);
    return val;
}

uint8_t fetch_reg_idx() {
    uint8_t idx = vm.instructions[vm.ip++];
    if (idx >= NUM_REGISTERS) {
        fprintf(stdout, "[ERROR] Invalid register index %d at IP=0x%x\n", idx, vm.ip - 1);
        vm.running = false;
        return 0;
    }
    return idx;
}

void ignore_buffering() {
    setvbuf(stdout, NULL, _IONBF, 0); 
    setvbuf(stderr, NULL, _IONBF, 0); 
    setvbuf(stdin, NULL, _IONBF, 0);  
}


int main() {
    ignore_buffering(); 
    banner();
    memset(&vm, 0, sizeof(VM));
    printf("> ");
    if (fread(vm.instructions, 1, MAX_PROGRAM_SIZE, stdin) <= 0) {
        fprintf(stdout, "[ERROR] Failed to read instructions from stdin.\n");
        return 1;
    }
    run_vm();
    return 0;
}
