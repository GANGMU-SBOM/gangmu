/* Minimal Xtensa (ESP32, windowed ABI) start-up for the corpus builds. The images are never
   executed; they only have to be real Xtensa code. */
extern int main(void);
__attribute__((section(".text.start"))) void _start(void) {
  main();
  for (;;) ;
}
int main(void) { return 0; }
