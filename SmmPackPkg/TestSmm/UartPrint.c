#include <UartPrint.h>

UINT8  uart_initialized = 0;
UINT64 bar              = 0;



/**
 
 Wrapper functions for inl/outl assembly

**/
inline
UINT32
inl (
    IN UINT16 port
)
{
  UINT32 value;
  asm volatile ("inl %[port],%[value]" : [value]"=a"(value) : [port]"d"(port));
  return value;
}

inline
VOID
outl (
    IN UINT16 port,
    IN UINT32 value
)
{
  asm volatile ("outl %[value],%[port]" :: [value]"a"(value), [port]"d"(port));
}



/**
 
 Read 32bit data from PCI Configuration Space specified by BDFO

**/
UINT32
PciRead32 (
    IN unsigned char b,
    IN unsigned char d,
    IN unsigned char f,
    IN unsigned char o
)
{
  PciConfAddr pciAddress;
  pciAddress.raw      = 0;
  pciAddress.bus      = b;
  pciAddress.device   = d;
  pciAddress.function = f;
  pciAddress.offset   = o & 0xFC;
  pciAddress.enable   = 1;

  outl(CONFIG_ADDRESS, pciAddress.raw);

  return inl(CONFIG_DATA);
}



/**
 
 Write 32bit data to PCI Configuration Space specified by BDFO

**/
VOID
PciWrite32 (
    IN unsigned char b,
    IN unsigned char d,
    IN unsigned char f,
    IN unsigned char o,
    IN UINT32 data
)
{
  PciConfAddr pciAddress;
  pciAddress.raw      = 0;
  pciAddress.bus      = b;
  pciAddress.device   = d;
  pciAddress.function = f;
  pciAddress.offset   = o & 0xFC;
  pciAddress.enable   = 1;

  outl(CONFIG_ADDRESS, pciAddress.raw);

  outl(CONFIG_DATA, data);
}



/**
 
 This function inits baudrate using UART's DLL/DLH register.
 Baudrate will be set to 115200 by setting 1 to DLL/DLH.
 Bit7 (DLAB bit) of LCR register has to be set to access DLL/DLH.

**/
VOID
InitBaudRate (
)
{
  UINT8 lcr =  MmioRead8(bar+UART_LCR);
  if(lcr&(1<<LCR_DLAB))
    lcr &= ~(1<<LCR_DLAB);
  MmioWrite8(bar+UART_LCR, (lcr | (1<<LCR_DLAB)));
  MmioWrite8(bar+UART_DLL, 1);
  MmioWrite8(bar+UART_DLH, 0);
  MmioWrite8(bar+UART_LCR, lcr);
}



/**
 
 This function check/set the memory space bit in PCI Config Space.
 The bit has to be set in order to MMIO the PCI device.

**/
VOID
EnableUartMmio (
)
{
  // set it to D0 function power state
/*
 *  UINT32 pmests = PciRead32(
 *      UART0_BUS,
 *      UART0_DEVICE,
 *      UART0_FUNCTION,
 *      PMECTRLSTS_OFFSET
 *      );
 *  pmests &= ~PMESTS_POWERSTATE;
 *  pmests |= PMESTS_PMEEN;
 *  PciWrite32(
 *      UART0_BUS,
 *      UART0_DEVICE,
 *      UART0_FUNCTION,
 *      PMECTRLSTS_OFFSET,
 *      pmests
 *      );
 *
 */
  UINT32 command = PciRead32(
      UART0_BUS,
      UART0_DEVICE,
      UART0_FUNCTION,
      COMMAND_OFFSET
      );
  if((command&EFI_PCI_COMMAND_MEMORY_SPACE) == 0) {
    command |= EFI_PCI_COMMAND_MEMORY_SPACE;
    PciWrite32(
        UART0_BUS,
        UART0_DEVICE,
        UART0_FUNCTION,
        COMMAND_OFFSET,
        command
        );
  }
}



/**
 
 This function initializes UART by read/writing registers in UART Host Controller.
 It first reads BAR from the PCI Configuration Space and read/write MMIO register
 that are specified in Intel® Pentium® and Celeron® Processor N- and J- Series spec
 which is the spec for SoC UP2 Board uses.

**/
VOID
InitUart (
)
{
  //
  // 0: check Device ID is 0x5ABC (SoC spec v1 p20)
  //
  UINT32 devid = PciRead32(
      UART0_BUS,
      UART0_DEVICE,
      UART0_FUNCTION,
      ZERO_OFFSET
      );
  devid = devid >> 16;


  //
  // 1: get UART device's bar
  // 
  UINT32 bar_lo = PciRead32(
      UART0_BUS,
      UART0_DEVICE,
      UART0_FUNCTION,
      BAR_LO_OFFSET
      );
  UINT64 bar_hi = PciRead32(
      UART0_BUS,
      UART0_DEVICE,
      UART0_FUNCTION,
      BAR_HI_OFFSET
      );
  bar = (bar_lo&0xFFFFFFF0) + ((bar_hi&0xFFFFFFFF) << 32);
  if(bar==0x91524000) return;

  PciWrite32(
      UART0_BUS,
      UART0_DEVICE,
      UART0_FUNCTION,
      BAR_LO_OFFSET,
      0x91524004);
  PciWrite32(
      UART0_BUS,
      UART0_DEVICE,
      UART0_FUNCTION,
      BAR_HI_OFFSET,
      0x0);
  bar = 0x91524000;


  //
  // 2: MMIO UART Initialization
  //
  EnableUartMmio();
  InitBaudRate();
  MmioWrite32(bar+UART_USR, 6);
  MmioWrite8(bar+UART_HTX, 0);
  MmioWrite8(bar+UART_LSR, 96);
  MmioWrite8(bar+UART_LCR, (3<<LCR_DLS));
  MmioWrite8(bar+UART_FCR, (1<<FCR_FIFOE) | (1<<FCR_RFIFOR) | (1<<FCR_XFIFOR));
  MmioWrite8(bar+UART_IER, 0);
  MmioWrite8(bar+UART_MCR, (1<<MCR_RTS));

  uart_initialized = 1;
}



/**
 
 This function sets 1 character to THR register of UART meaning
 it will let UART send 1 character to TX. This will check TFNF bit of
 USR register to see if FIFO in UART is not full.
 
 @param[in]  c  1byte character to send in TX
 
**/
VOID
SendChar8 (
    IN char c
)
{
  while(1) {
    /*UINT8 lsr = MmioRead8(bar + UART_LSR);*/
    UINT8 usr = MmioRead8(bar + UART_USR);
    /*if (((lsr>>LSR_THRE)&1)==0 && (usr&(1<<USR_TFNF))) break;*/
    if (usr&(1<<USR_TFNF)) break;
  }
  MmioWrite8(bar + UART_THR, c);
}



/**
 
 This function takes format string and print the output to UART.
 If UART is not initialized yet, it will call InitUart().
 
 @param[in]  fmt  format string to print by UART
 
**/
VOID
EFIAPI
UartPrint (
  IN CONST CHAR8  *fmt,
  ...
)
{
  if(!uart_initialized)
    InitUart();

  char buf[1000];
  VA_LIST v1;
  VA_START(v1, fmt);
  AsciiVSPrint(buf, 1000, fmt, v1);
  VA_END(v1);

  UINTN i;
  for(i=0; i<AsciiStrLen(buf); i++)
    SendChar8(buf[i]);
}
