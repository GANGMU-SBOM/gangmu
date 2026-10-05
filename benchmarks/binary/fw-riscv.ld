MEMORY { FLASH (rx) : ORIGIN = 0x20000000, LENGTH = 16M
         RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 16M }
ENTRY(_start)
SECTIONS {
  .text : { *(.text.start) *(.text*) . = ALIGN(4); } > FLASH
  .rodata : { *(.rodata*) *(.srodata*) . = ALIGN(4); _etext = .; } > FLASH
  .data : AT(_etext) { _sdata = .; *(.data*) *(.sdata*) . = ALIGN(4); _edata = .; } > RAM
  .bss : { _sbss = .; *(.sbss*) *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > RAM
  _estack = ORIGIN(RAM) + LENGTH(RAM);
}
