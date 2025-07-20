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

#pragma once

#include "ch32v003.h"

/// Microcontroller clock configuration. Your application must declare a useHse
/// constant set to false if you want to use the internal HSI oscillator, or to
/// true if you provide a 4..24MHz quartz crystal to the appropriate pins
extern const bool useHse;
/// Microcontroller clock configuration. Your application must declare a
/// cpuFrequency constant set to the desired CPU frequency. The choice of this
/// value is subject to the following restrictions:
/// - If useHse is false, only thes frequency values are supported due to
///   limitations in the clock prescaler and PLL:
///   48000000, 24000000, 12000000, 6000000, 3000000, 1500000, 750000
/// - If useHse is true, the HSE oscillator only supports quartz crystals in the
///   4..24MHz range. If cpuFrequency is within this range, it is assumed that
///   the connected crystal is exactly the same frequency of cpuFrequency, and
///   no clock division is done. cpuFrequency can also be set greater than 24MHz
///   and up to 48MHz. In this case, the connected crystal is assumed to be HALF
///   the desired frequency and the x2 PLL is enabled
extern const unsigned int cpuFrequency;

/**
 * \internal
 * Sleep the CPU for the given number of ticks
 * \param tick time in ticks
 */
void sleepTick(unsigned int tick);

/**
 * Sleep the CPU for the given number of microseconds
 * \param us time in microseconds
 */
inline void sleepUs(unsigned int us)
{
    //Pick either the most precise way or the overflow-preventing way.
    //Since cpuFrequency is a constant, the compiler will optimize out the if
    if((cpuFrequency % 1000000)==0) sleepTick(us*(cpuFrequency/1000000));
    else sleepTick(us*cpuFrequency/1000000);
}

/**
 * Sleep the CPU for the given number of milliseconds
 * \param ms time in milliseconds
 */
inline void sleepMs(unsigned int ms)
{
    //Pick either the most precise way or the overflow-preventing way.
    //Since cpuFrequency is a constant, the compiler will optimize out the if
    if((cpuFrequency % 1000)==0) sleepTick(ms*(cpuFrequency/1000));
    else sleepTick(ms*cpuFrequency/1000);
}

/*
 * Convenience shorthands for the GPIO port names
 */
constexpr unsigned int PA=GPIOA_BASE;
constexpr unsigned int PC=GPIOC_BASE;
constexpr unsigned int PD=GPIOD_BASE;

/**
 * GPIO mode (INPUT, OUTPUT, ...)
 * \code pin::mode(Mode::INPUT);\endcode
 */
enum class Mode
{
    INPUT              = 0x4, ///Floating Input             (CNF=01 MODE=00)
    INPUT_PULL_UP_DOWN = 0x8, ///Pullup/Pulldown Input      (CNF=10 MODE=00)
    INPUT_ANALOG       = 0x0, ///Analog Input               (CNF=00 MODE=00)
    OUTPUT             = 0x3, ///Push Pull  50MHz Output    (CNF=00 MODE=11)
    OUTPUT_10MHz       = 0x1, ///Push Pull  10MHz Output    (CNF=00 MODE=01)
    OUTPUT_2MHz        = 0x2, ///Push Pull   2MHz Output    (CNF=00 MODE=10)
    OPEN_DRAIN         = 0x7, ///Open Drain 50MHz Output    (CNF=01 MODE=11)
    OPEN_DRAIN_10MHz   = 0x5, ///Open Drain 10MHz Output    (CNF=01 MODE=01)
    OPEN_DRAIN_2MHz    = 0x6, ///Open Drain  2MHz Output    (CNF=01 MODE=10)
    ALTERNATE          = 0xb, ///Alternate function 50MHz   (CNF=10 MODE=11)
    ALTERNATE_10MHz    = 0x9, ///Alternate function 10MHz   (CNF=10 MODE=01)
    ALTERNATE_2MHz     = 0xa, ///Alternate function  2MHz   (CNF=10 MODE=10)
    ALTERNATE_OD       = 0xf, ///Alternate Open Drain 50MHz (CNF=11 MODE=11)
    ALTERNATE_OD_10MHz = 0xd, ///Alternate Open Drain 10MHz (CNF=11 MODE=01)
    ALTERNATE_OD_2MHz  = 0xe  ///Alternate Open Drain  2MHz (CNF=11 MODE=10)
};

/**
 * Gpio template class
 * \param P PA, PB, ... as #define'd in ch32v003.h
 * \param N which pin (0 to 7)
 * The intended use is to make a typedef to this class with a meaningful name.
 * \code
 * using green_led = Gpio<PA,0>;
 * green_led::mode(Mode::OUTPUT);
 * green_led::high(); //Turn on LED
 * \endcode
 */
template<unsigned int P, unsigned char N>
class Gpio
{
public:
    Gpio() = delete; //Disallow creating instances

    /**
     * Set the GPIO to the desired mode (INPUT, OUTPUT, ...)
     * \param m enum Mode_
     */
    static void mode(Mode m)
    {
        auto modeBits=static_cast<unsigned int>(m);
        auto cfg=reinterpret_cast<GPIO_TypeDef*>(P)->CFGLR;
        cfg &= ~(0xf<<(N*4));
        cfg |= modeBits<<(N*4);
        reinterpret_cast<GPIO_TypeDef*>(P)->CFGLR=cfg;
    }

    /**
     * Set the pin to 1, if it is an output
     */
    static void high()
    {
        reinterpret_cast<GPIO_TypeDef*>(P)->BSHR=1<<N;
    }

    /**
     * Set the pin to 0, if it is an output
     */
    static void low()
    {
        reinterpret_cast<GPIO_TypeDef*>(P)->BCR=1<<N;
    }

    /**
     * Allows to read the pin status
     * \return 0 or 1
     */
    static int value()
    {
        return ((reinterpret_cast<GPIO_TypeDef*>(P)->INDR & 1<<N)? 1 : 0);
    }

    /**
     * Set pullup on pin, if its mode is Mode::INPUT_PULL_UP_DOWN
     */
    static void pullup()
    {
        high();//When in input pullup/pulldown mode ODR=choose pullup/pulldown
    }

    /**
     * Set pulldown on pin, if its mode is Mode::INPUT_PULL_UP_DOWN
     */
    static void pulldown()
    {
        low();//When in input pullup/pulldown mode ODR=choose pullup/pulldown
    }

    /**
     * \return the pin port. One of the constants PORTA_BASE, PORTB_BASE, ...
     */
    static unsigned int getPort() { return P; }

    /**
     * \return the pin number, from 0 to 15
     */
    static unsigned char getNumber() { return N; }
};
