ENTRY(_start)
SECTIONS {
  . = 0x80100000;
  .text : { *(.text.start) *(.text*) . = ALIGN(16); }
  .rodata : { *(.rodata*) *(.rdata*) . = ALIGN(8); }
  .data : { *(.data*) . = ALIGN(8); }
  .got : { *(.got) . = ALIGN(8); }
  .bss : { *(.bss*) *(COMMON) . = ALIGN(8); }
  /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment) *(.MIPS.abiflags) *(.reginfo) *(.gnu.attributes) *(.pdr) *(.mdebug*) }
}
