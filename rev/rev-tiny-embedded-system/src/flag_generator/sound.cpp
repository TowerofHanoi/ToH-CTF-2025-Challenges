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

#include "runtime.h"
#include <unistd.h>

extern "C" ssize_t _write(int fd, const void *buf, size_t size);

// Microcontroller clock configuration
const bool useHse=false;
const unsigned int cpuFrequency=48000000;

using outp=Gpio<PC,0>;   // Connect piezo speaker to PC0 and PD5
using outn=Gpio<PD,5>;
using button=Gpio<PA,1>; // Connect button between this pin and ground

void __attribute__((noinline)) high()
{
    outp::high();
    outn::low();
}

void __attribute__((noinline)) low()
{
    outp::low();
    outn::high();
}

void __attribute__((noinline)) pulse(int rep)
{
    for(int i=0;i<rep;i++)
    {
        high();
        sleepUs(500);
        low();
        sleepUs(500);
    }
}

int main()
{
    _write(1,"ch32-cpp-runtime booting\n",25);
    outp::mode(Mode::OUTPUT);
    outn::mode(Mode::OUTPUT);
    button::mode(Mode::INPUT_PULL_UP_DOWN);
    button::pullup();

    for(;;)
    {
        while(button::value()) sleepMs(10);
#include "flag.h"
    }
}
