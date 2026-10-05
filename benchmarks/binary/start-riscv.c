/* Minimal RV32 start-up for the corpus builds. The images are never executed; they only
   have to be real RISC-V code. */
extern int main(void);
extern unsigned _estack;
__attribute__((section(".text.start"), naked)) void _start(void) {
  __asm__ volatile("la sp, _estack\n call main\n 1: j 1b");
}
void trap_handler(void) { for (;;) ; }
int main(void) { return 0; }
