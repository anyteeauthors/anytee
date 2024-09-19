#include <imx_uart.h>

void imx_uart_init(volatile struct imx_uart *uart){
    return;
}

void imx_uart_enable(volatile struct imx_uart *uart){
    return;
}

void imx_uart_putc(volatile struct imx_uart *uart, char c){
    while((uart->ts & 0b1000));
    uart->txd = c;
}

void imx_uart_puts(volatile struct imx_uart *uart, char const* str){
    while (*str) {
        imx_uart_putc(uart, *str++);
    }
}

char imx_uart_getc(volatile struct imx_uart *uart){
    while(uart->ts == 0b100000);
    return uart->rxd & 0xff;
}
