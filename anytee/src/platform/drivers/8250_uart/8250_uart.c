/** 
 * Bao, a Lightweight Static Partitioning Hypervisor 
 *
 * Copyright (c) Bao Project (www.bao-project.org), 2019-
 *
 * Authors:
 *      Jose Martins <jose.martins@bao-project.org>
 *
 * Bao is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free
 * Software Foundation, with a special exception exempting guest code from such
 * license. See the COPYING file in the top-level directory for details. 
 *
 */

#include <drivers/8250_uart.h>

void uart_init(volatile struct uart8250_hw *uart) {
    
    /* set baudrate */
    uart->lcr |= UART8250_LCR_DLAB;
    /**
     * should set dll and dlh, 
     * to simplify instead lets assume the firmware did this for us.
     * TODO: we should add uart clk and baudrate info to platform descrption
     * and use this to calculate this values in runtime.
     */
    uart->lcr &= ~UART8250_LCR_DLAB;

/* configure 8n1 */
uart->lcr = UART8250_LCR_8BIT;

    /* disable interrupts */
    uart->ier = 0;

    /* no modem */
    uart->mcr = 0;

    /* clear status */
    (void) uart->lsr;
    uart->msr = 0;
}

void uart_enable(volatile struct uart8250_hw *uart){
    uart->fcr = UART8250_FCR_EN;
}

void uart_putc(volatile struct uart8250_hw *uart, int8_t c){
    while(!(uart->lsr & UART8250_LSR_THRE));
    uart->thr = c;
}

void uart_puts(volatile struct uart8250_hw *uart, char const* str){
    while (*str) {
        uart_putc(uart, *str++);
    }
}
