/* Minimal Cortex-M start-up for the corpus builds. The images are never executed; they
   only have to be real Thumb code with a real vector table. */
extern int main(void);
extern unsigned _estack, _sdata, _edata, _etext, _sbss, _ebss;
void Reset_Handler(void) {
  unsigned *s = &_etext, *d = &_sdata;
  while (d < &_edata) *d++ = *s++;
  for (d = &_sbss; d < &_ebss; ) *d++ = 0;
  main();
  for (;;) ;
}
void Default_Handler(void) { for (;;) ; }
__attribute__((section(".isr_vector"), used)) void (*const vectors[16])(void) = {
  (void (*)(void))&_estack, Reset_Handler, Default_Handler, Default_Handler, Default_Handler,
  Default_Handler, Default_Handler, 0, 0, 0, 0, Default_Handler, Default_Handler, 0,
  Default_Handler, Default_Handler };
static char heap[65536]; static unsigned used;
void *_sbrk(int n) { if (used + n > sizeof heap) return (void *)-1; void *p = heap + used; used += n; return p; }
int main(void) { return 0; }
/* No libc: references hold only the library's code. memcpy and friends stay unresolved. */
