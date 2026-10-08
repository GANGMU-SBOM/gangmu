/* Addresses are low on purpose: the images are never run, and unresolved calls land on 0, which
   must be in the same 1 GB region as the code or the Xtensa linker refuses the long call. */
MEMORY { FLASH (rx) : ORIGIN = 0x00400000, LENGTH = 3M
         RAM (rwx) : ORIGIN = 0x00800000, LENGTH = 1M }
ENTRY(_start)
SECTIONS {
  .text : { *(.text.start) *(.literal .literal.*) *(.text .text.*) . = ALIGN(4); } > FLASH
  .rodata : { *(.rodata*) . = ALIGN(4); _etext = .; } > FLASH
  .data : AT(_etext) { _sdata = .; *(.data*) *(.literal.*data*) . = ALIGN(4); _edata = .; } > RAM
  .bss : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > RAM
}
