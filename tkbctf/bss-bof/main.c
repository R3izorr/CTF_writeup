// gcc -Wl,-z,now,-z,relro main.c -o bss-bof
#include <stdio.h>
#include <stdint.h>

char buf[8];
int main() {
  uint64_t* dest = 0;
  printf("printf: %p\n", printf);
  
  read(0, &dest, 8);
  read(0, dest, 8);

  gets(buf);
}

__attribute__((constructor)) void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}
