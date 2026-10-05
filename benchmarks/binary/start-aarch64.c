/* Minimal AArch64 start-up for the corpus builds. The images are never executed; they only
   have to be real AArch64 code. */
extern int main(void);
__attribute__((section(".text.start"), naked)) void _start(void) {
  __asm__ volatile("ldr x0, =_estack\n mov sp, x0\n bl main\n 1: b 1b");
}
int main(void) { return 0; }
