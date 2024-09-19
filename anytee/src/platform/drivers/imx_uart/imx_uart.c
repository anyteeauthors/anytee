#include <drivers/imx_uart.h>

void uart_init(volatile struct imx_uart *uart){
    return;
}

void uart_enable(volatile struct imx_uart *uart){
    return;
}

void uart_putc(volatile struct imx_uart *uart, char c){
    while((uart->ts & 0b1000000) == 0);
    uart->txd = c;
}

void uart_puts(volatile struct imx_uart *uart, char const* str){
    while (*str) {
        uart_putc(uart, *str++);
    }
}

