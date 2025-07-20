/***************************************************************************
 *   Copyright (C) 2025 by Terraneo Federico                               *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   As a special exception, if other files instantiate templates or use   *
 *   macros or inline functions from this file, or you compile this file   *
 *   and link it with other works to produce a work based on this file,    *
 *   this file does not by itself cause the resulting work to be covered   *
 *   by the GNU General Public License. However the source code for this   *
 *   file must still be made available in accordance with the GNU General  *
 *   Public License. This exception does not invalidate any other reasons  *
 *   why a work based on this file might be covered by the GNU General     *
 *   Public License.                                                       *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, see <http://www.gnu.org/licenses/>   *
 ***************************************************************************/

#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include "runtime.h"

//
// Clock setup and sleep code
//

void setupClock()
{
    if(useHse==false)
    {
        //HSI is 24MHz, set clock divider accordingly to requested cpuFrequency
        switch(cpuFrequency)
        {
            case 48000000: RCC->CFGR0=RCC_HPRE_DIV1;  break;
            case 24000000: RCC->CFGR0=RCC_HPRE_DIV1;  break;
            case 12000000: RCC->CFGR0=RCC_HPRE_DIV2;  break;
            case 6000000:  RCC->CFGR0=RCC_HPRE_DIV4;  break;
            case 3000000:  RCC->CFGR0=RCC_HPRE_DIV8;  break;
            case 1500000:  RCC->CFGR0=RCC_HPRE_DIV16; break;
            case 750000:   RCC->CFGR0=RCC_HPRE_DIV32; break;
            // We could go lower but the power consumption does not seem to
            // decrease further so why bother?

            // What to do if the frequency isn't supported by the hardware?
            // TODO: find a way to fail at compile-time, meanwhile we lock up
            default: for(;;) ;
        }
    } else {
        //Assume HSE runs at cpuFrequency (or half of it, if cpuFrequency>24MHz)
        RCC->CFGR0=RCC_HPRE_DIV1; //div1 is not default, contrary to datasheet
        RCC->CTLR |= RCC_HSEON; //Keep HSI on for debug
        while((RCC->CTLR & RCC_HSERDY)==0) ;
        RCC->CFGR0=(RCC->CFGR0 & ~0x03) | RCC_SW_HSE;
        while((RCC->CFGR0 & RCC_SWS)!=RCC_SWS_HSE) ;
    }
    if(cpuFrequency>24000000)
    {
        //cpuFrequency cannot be achieved by dividing clock, use x2 PLL
        if(useHse) RCC->CFGR0 |= RCC_PLLSRC;  //Choose HSE or HSI as PLL input
        FLASH->ACTLR=FLASH_ACTLR_LATENCY_1; //1 FLASH wait state is required
        RCC->CTLR |= RCC_PLLON;
        while((RCC->CTLR & RCC_PLLRDY)==0) ;
        RCC->CFGR0=(RCC->CFGR0 & ~0x03) | RCC_SW_PLL;
        while((RCC->CFGR0 & RCC_SWS)!=RCC_SWS_PLL) ;
    }
    SysTick->CTLR=SYSTICK_CTLR_STCLK | SYSTICK_CTLR_STE; //Increment at CPU freq
    NVIC_EnableIRQ(SysTicK_IRQn);
}

/**
 * We use the SysTick interrupt to implement delay function by sleeping instead
 * of spinning. This optimization reduces power consumption during sleep to
 * about half.
 * NOTE: interrupt service routines must be marked with the interrupt attribute
 * as the compiler must end them with the "mret" instruction
 */
void __attribute__((interrupt,used)) SysTick_Handler()
{
    SysTick->SR=0; //Clear interrupt flag
}

void sleepTick(unsigned int tick)
{
    unsigned int wakeup=SysTick->CNT+tick;
    SysTick->CMP=wakeup;
    SysTick->CTLR |= SYSTICK_CTLR_STIE;
    while((static_cast<int>(SysTick->CNT-wakeup))<0) __WFI();
    SysTick->CTLR &= ~SYSTICK_CTLR_STIE;
}

//
// Syscalls, to get the C and C++ standard library at least somewhat working
//

extern "C" __attribute__((used)) void _exit(int ec)
{
    for(;;) ; //TODO: how to reboot?
}

extern "C" __attribute__((used)) int _kill(pid_t pid, int sig)
{
    return -1; //Stub, required for linking but operation is not supported
}

extern "C" __attribute__((used)) pid_t _getpid()
{
    return 0; //Stub, required for linking but operation is not supported
}

extern "C" __attribute__((used)) int _close(int fd)
{
    return 0; //Stub, required for linking but operation is not supported
}

extern "C" __attribute__((used)) off_t _lseek(int fd, off_t pos, int whence)
{
    return -1; //Stub, required for linking but operation is not supported
}

extern "C" __attribute__((used)) ssize_t _read(int fd, void *buf, size_t size)
{
    return -1;  //Stub, required for linking but operation is not supported
}

extern "C" __attribute__((used)) ssize_t _write(int fd, const void *buf, size_t size)
{
    // Make printf work, currently redirecting it to what appears an equivalent
    // of ARM's debug communication channel (DCC)
    auto buffer=reinterpret_cast<const char *>(buf);
    // The DMDATA0 debug register is entirely undocumented
    if((DMDATA0 & 0xc0)==0xc0) return 0;
    for(size_t i=0;i<size;i++)
    {
        for(int j=0;j<100;j++)
        {
            if(!(DMDATA0 & 0x80)) break;
            if(j==99)
            {
                DMDATA0|=0xc0;
                return i;
            }
            sleepMs(1);
        }
        DMDATA0=0x85 | static_cast<unsigned int>(buffer[i])<<8;
    }
    return size;
}

extern "C" __attribute__((used)) int _fstat(int fd, struct stat *pstat)
{
    memset(pstat,0,sizeof(struct stat));
    pstat->st_mode=S_IFCHR; // Character device
    // Use BUFSIZ as block size. Unfortunately I tried passing a size here but
    // a malloc(BUFSIZ) occurs anyway, so there's no alternative to patching
    // newlib to set a reasonable BIFSIZ value
    pstat->st_blksize=0;
    return 0;
}

extern "C" __attribute__((used)) int _isatty(int fd)
{
    return 1; // Only files we support are stdin,stdout,stderr which are tty
}

extern "C" __attribute__((used)) void *_sbrk(intptr_t incr)
{
    // Make malloc work
    extern char _end asm("_end"); // Defined in the linker script
    static char *curHeapEnd=nullptr;
    if(curHeapEnd==nullptr) curHeapEnd=&_end;
    char *prevHeapEnd=curHeapEnd;
    curHeapEnd+=incr;
    return reinterpret_cast<void*>(prevHeapEnd);
}

//
// Boot code
//

int main();

/**
 * \internal
 * Calls C++ global constructors
 * \param start first function pointer to call
 * \param end one past the last function pointer to call
 */
static void callConstructors(unsigned long *start, unsigned long *end)
{
    for(unsigned long *i=start; i<end; i++)
    {
        void (*funcptr)();
        funcptr=reinterpret_cast<void (*)()>(*i);
        funcptr();
    }
}

/**
 * \internal
 * Called by BootCode, perform initial setup and call main
 */
void __attribute__((used)) mainLoader()
{
    // These debug registers are entirely undocumented
    DMDATA1=0x00;
    DMDATA0=0x80;

    // Enable GPIOs at boot because what firmware doesn't use them?
    RCC->APB2PCENR |= RCC_APB2Periph_GPIOA | RCC_APB2Periph_GPIOC | RCC_APB2Periph_GPIOD;

    setupClock();

    // Add a 100ms busy-wait delay (without sleeping the CPU) to avoid bricking
    // the chip if the application tries to reconfigure the debug and/or reset
    // GPIO. This delay gives us some time to attach with the flasher
    int wakeup=SysTick->CNT+cpuFrequency/10;
    while((static_cast<int>(SysTick->CNT)-wakeup)<0) ;

    extern unsigned char _data_lma asm("_data_lma");
    extern unsigned char _data_vma asm("_data_vma");
    extern unsigned char _edata asm("_edata");
    extern unsigned char _sbss asm("_sbss");
    extern unsigned char _ebss asm("_ebss");

    //Initialize .data section, clear .bss section
    unsigned char *etext=&_data_lma;
    unsigned char *data=&_data_vma;
    unsigned char *edata=&_edata;
    unsigned char *bss_start=&_sbss;
    unsigned char *bss_end=&_ebss;

    memcpy(data, etext, edata-data);
    memset(bss_start, 0, bss_end-bss_start);

    //Initialize application C++ global constructors
    extern unsigned long __preinit_array_start asm("__preinit_array_start");
    extern unsigned long __preinit_array_end asm("__preinit_array_end");
    extern unsigned long __init_array_start asm("__init_array_start");
    extern unsigned long __init_array_end asm("__init_array_end");
    callConstructors(&__preinit_array_start, &__preinit_array_end);
    callConstructors(&__init_array_start, &__init_array_end);

    main();
}

/*
 * Redeclare one of the interrupt functions below to override this default code
 */
extern "C" void Default_Handler()
{
    for(;;) ;
}

void NMI_Handler()              __attribute__((used,weak,alias("Default_Handler")));
void HardFault_Handler()        __attribute__((used,weak,alias("Default_Handler")));
void SVCall_Handler()           __attribute__((used,weak,alias("Default_Handler")));
void WWDG_IRQHandler()          __attribute__((used,weak,alias("Default_Handler")));
void PVD_IRQHandler()           __attribute__((used,weak,alias("Default_Handler")));
void FLASH_IRQHandler()         __attribute__((used,weak,alias("Default_Handler")));
void RCC_IRQHandler()           __attribute__((used,weak,alias("Default_Handler")));
void EXTI7_0_IRQHandler()       __attribute__((used,weak,alias("Default_Handler")));
void AWU_IRQHandler()           __attribute__((used,weak,alias("Default_Handler")));
void DMA1_Channel1_IRQHandler() __attribute__((used,weak,alias("Default_Handler")));
void DMA1_Channel2_IRQHandler() __attribute__((used,weak,alias("Default_Handler")));
void DMA1_Channel3_IRQHandler() __attribute__((used,weak,alias("Default_Handler")));
void DMA1_Channel4_IRQHandler() __attribute__((used,weak,alias("Default_Handler")));
void DMA1_Channel5_IRQHandler() __attribute__((used,weak,alias("Default_Handler")));
void DMA1_Channel6_IRQHandler() __attribute__((used,weak,alias("Default_Handler")));
void DMA1_Channel7_IRQHandler() __attribute__((used,weak,alias("Default_Handler")));
void ADC1_IRQHandler()          __attribute__((used,weak,alias("Default_Handler")));
void I2C1_EV_IRQHandler()       __attribute__((used,weak,alias("Default_Handler")));
void I2C1_ER_IRQHandler()       __attribute__((used,weak,alias("Default_Handler")));
void USART1_IRQHandler()        __attribute__((used,weak,alias("Default_Handler")));
void SPI1_IRQHandler()          __attribute__((used,weak,alias("Default_Handler")));
void TIM1_BRK_IRQHandler()      __attribute__((used,weak,alias("Default_Handler")));
void TIM1_UP_IRQHandler()       __attribute__((used,weak,alias("Default_Handler")));
void TIM1_TRG_COM_IRQHandler()  __attribute__((used,weak,alias("Default_Handler")));
void TIM1_CC_IRQHandler()       __attribute__((used,weak,alias("Default_Handler")));
void TIM2_IRQHandler()          __attribute__((used,weak,alias("Default_Handler")));

void __attribute__((naked,section(".init"))) BootCode()
{
    // The NVIC of the CH32 isn't as clean as the ARM NVIC, as the reset handler
    // slot must contain an instruction, while all other slots contain a pointer
    // TODO: find a way to map this mix of code and data to high-level languages
    asm volatile(
    ".align  2                               \n"
    ".option push                            \n"
    ".option norvc                           \n"
    "    j     .L1                           \n"
    "    .word 0                             \n"
    "    .word _Z11NMI_Handlerv              \n"
    "    .word _Z17HardFault_Handlerv        \n"
    "    .word 0                             \n"
    "    .word 0                             \n"
    "    .word 0                             \n"
    "    .word 0                             \n"
    "    .word 0                             \n"
    "    .word 0                             \n"
    "    .word 0                             \n"
    "    .word 0                             \n"
    "    .word _Z15SysTick_Handlerv          \n"
    "    .word 0                             \n"
    "    .word _Z14SVCall_Handlerv           \n"
    "    .word 0                             \n"
    "    .word _Z15WWDG_IRQHandlerv          \n"
    "    .word _Z14PVD_IRQHandlerv           \n" // PVD through EXTI Line
    "    .word _Z16FLASH_IRQHandlerv         \n"
    "    .word _Z14RCC_IRQHandlerv           \n"
    "    .word _Z18EXTI7_0_IRQHandlerv       \n"
    "    .word _Z14AWU_IRQHandlerv           \n"
    "    .word _Z24DMA1_Channel1_IRQHandlerv \n"
    "    .word _Z24DMA1_Channel2_IRQHandlerv \n"
    "    .word _Z24DMA1_Channel3_IRQHandlerv \n"
    "    .word _Z24DMA1_Channel4_IRQHandlerv \n"
    "    .word _Z24DMA1_Channel5_IRQHandlerv \n"
    "    .word _Z24DMA1_Channel6_IRQHandlerv \n"
    "    .word _Z24DMA1_Channel7_IRQHandlerv \n"
    "    .word _Z15ADC1_IRQHandlerv          \n"
    "    .word _Z18I2C1_EV_IRQHandlerv       \n"
    "    .word _Z18I2C1_ER_IRQHandlerv       \n"
    "    .word _Z17USART1_IRQHandlerv        \n"
    "    .word _Z15SPI1_IRQHandlerv          \n"
    "    .word _Z19TIM1_BRK_IRQHandlerv      \n"
    "    .word _Z18TIM1_UP_IRQHandlerv       \n"
    "    .word _Z23TIM1_TRG_COM_IRQHandlerv  \n"
    "    .word _Z18TIM1_CC_IRQHandlerv       \n"
    "    .word _Z15TIM2_IRQHandlerv          \n"
    ".option pop                             \n"
    // Our reset instruction jumps here, where we perform low-level stuff that
    // are likely only possible in assembly, such as setting the stack pointer
    // mid-function. From here, we'll switch as soon as possible to C++ code
    // to the mainLoader function
    ".L1:                                    \n"
    ".option arch, +zicsr                    \n"
    ".option push                            \n"
    ".option norelax                         \n"
    "    la   gp,      __global_pointer$     \n"
    ".option pop                             \n"
    "    la   sp,      _eusrstack            \n"
    "    li   t0,      0x80                  \n" //MPIE=1, enable IRQ on mret
    "    csrw mstatus, t0                    \n"
    // QingKeV2 Microprocessor Manual INTSYSCR register. Disable all bits
    // EABIEN=0, INESTEN=0, HWSTKEN=0. In theory hardware stacking would be nice
    // but unlike in ARM CPUs, RISCV saves a total of 10 registers that may even
    // slow down simple interrupts that don't use that many registers. Moreover,
    // it appears a mainline GCC compiler has no support for this feature and
    // the compiler would try saving registers in software on top anyway
    "    csrw 0x804,   0                     \n"
    // QingKeV2 Microprocessor Manual chapter 2.2 Entering exception:
    // - mtvec bit 0 enables vectored interrupt handling
    // - mtvec bit 1 decides whether vector table entries are instructions (0)
    //   or pointers (1)
    // We want both bits set but the default at boot is all 0, that's why the
    // reset entry must be an instruction. mtvec bits 31..2 are the vector table
    // base address (or the single entry address if vectored interrupts are
    // disabled) and must be 1KB aligned. Since we want to use the same data
    // structure at boot and for interrupts, we can't move it from address 0.
    "    li   t0,      0x3                   \n"
    "    csrw mtvec,   t0                    \n"
    // Unlike in other architectures, this CPU exits reset as if an interrupt
    // was called, so we actually need to return from this interrupt, which
    // feels weird. We do so by setting the saved program counter and doing mret
    "    la   t0,      _Z10mainLoaderv       \n"
    "    csrw mepc,    t0                    \n"
    "    mret                                \n"
    );
}
