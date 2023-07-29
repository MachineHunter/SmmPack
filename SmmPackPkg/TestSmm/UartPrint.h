/*
 *
 * This provides UartPrint function which allows printing
 * characters on UP2 Pro board. This is because DEBUG or
 * any other similar functions seems to be not working on my UP2 board.
 *
 */

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/IoLib.h>
#include <Library/PrintLib.h>


#define UART0_BUS 0
#define UART0_DEVICE 24
#define UART0_FUNCTION 0

#define ZERO_OFFSET       0x0
#define COMMAND_OFFSET    0x4
#define BAR_LO_OFFSET     0x10
#define BAR_HI_OFFSET     0x14
#define PMECTRLSTS_OFFSET 0x84

#define EFI_PCI_COMMAND_MEMORY_SPACE 0x2
#define PMESTS_PMEEN      0x100
#define PMESTS_POWERSTATE 0x3

#define CONFIG_ADDRESS 0xCF8
#define CONFIG_DATA 0xCFC

#define UART_RBR 0x00
#define UART_THR 0x00
#define UART_IER 0x04
#define UART_IIR 0x08
#define UART_FCR 0x08
#define UART_LCR 0x0C
#define UART_MCR 0x10
#define UART_LSR 0x14
#define UART_MSR 0x18
#define UART_SCR 0x1C
#define UART_DLL 0x00
#define UART_DLH 0x04
#define UART_USR 0x7C
#define UART_HTX 0xA4
#define UART_CTR 0xFC

#define LCR_DLS    0x0
#define LCR_DLAB   0x7
#define MCR_RTS    0x1
#define MCR_AFCE   0x5
#define FCR_FIFOE  0x0
#define FCR_RFIFOR 0x1
#define FCR_XFIFOR 0x2
#define LSR_THRE   0x5
#define USR_TFNF   0x1
#define HTX_HTX    0x0



typedef union _PciConfAddr {
  UINT32 raw;
  struct __attribute__((packed)) {
    UINT32 offset    : 8;
    UINT32 function  : 3;
    UINT32 device    : 5;
    UINT32 bus       : 8;
    UINT32 reserved2 : 7;
    UINT32 enable    : 1;
  };
} PciConfAddr;


UINT32
PciRead32 (
    IN unsigned char b,
    IN unsigned char d,
    IN unsigned char f,
    IN unsigned char o
);


VOID
PciWrite32 (
    IN unsigned char b,
    IN unsigned char d,
    IN unsigned char f,
    IN unsigned char o,
    IN UINT32 data
);


VOID
InitBaudRate (
);

VOID
SendChar8 (
    IN char c
);


VOID
EFIAPI
UartPrint (
  IN CONST CHAR8  *fmt,
  ...
);


VOID
EnableUartMmio (
);


VOID
InitUart (
);
