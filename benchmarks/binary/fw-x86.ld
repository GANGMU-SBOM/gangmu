MEMORY { FLASH (rx) : ORIGIN = 0x400000, LENGTH = 64M
         RAM (rwx) : ORIGIN = 0x10000000, LENGTH = 64M }
ENTRY(_start)
SECTIONS {
  .text : { *(.text.start) *(.text*) . = ALIGN(16); } > FLASH
  .rodata : { *(.rodata*) . = ALIGN(16); _etext = .; } > FLASH
  .data : AT(_etext) { _sdata = .; *(.data*) . = ALIGN(16); _edata = .; } > RAM
  .bss : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(16); _ebss = .; } > RAM
  _estack = ORIGIN(RAM) + LENGTH(RAM);
  /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment) }
}
