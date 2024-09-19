#include <uart.h>
#include <imx_uart.h>

volatile struct imx_uart * const uart = (void*)0x30860000;

void uart_init(){
   imx_uart_init(uart);
}

void uart_putc(char c){
   imx_uart_putc(uart, c);
}

char uart_getchar(){
    return imx_uart_getc(uart);
}

void uart_enable_rxirq(){
    /* imx_uart_enable_rxirq(uart); */
}

void uart_clear_rxirq(){
    /* imx_uart_clear_rxirq(uart); */
}
