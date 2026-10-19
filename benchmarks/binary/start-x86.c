/* Minimal x86-64 start-up for the corpus builds. The images are never executed; they only
   have to be real x86-64 code. */
extern int main(void);
__attribute__((section(".text.start"), naked)) void _start(void) {
  __asm__ volatile("call main\n 1: jmp 1b");
}
int main(void) { return 0; }
