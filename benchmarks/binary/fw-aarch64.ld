MEMORY { FLASH (rx) : ORIGIN = 0x80000, LENGTH = 16M
         RAM (rwx) : ORIGIN = 0x10000000, LENGTH = 16M }
ENTRY(_start)
SECTIONS {
  .text : { *(.text.start) *(.text*) . = ALIGN(4); } > FLASH
  .rodata : { *(.rodata*) . = ALIGN(8); _etext = .; } > FLASH
  .data : AT(_etext) { _sdata = .; *(.data*) . = ALIGN(8); _edata = .; } > RAM
  .bss : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(8); _ebss = .; } > RAM
  _estack = ORIGIN(RAM) + LENGTH(RAM);
  /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment) }
}
