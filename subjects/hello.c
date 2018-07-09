#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void success() {
  printf("done!\n");
  exit(0);
}

int main(int argc, char* argv[0]) {
  assert(argc > 1);
  char* s = argv[1];
  char h = s[0];
  s++;
  assert((h == 'h') || (h == 'H'));
  char e = s[0];
  s++;
  assert((e == 'e') || (e == 'E'));
  char l1 = s[0];
  s++;
  assert((l1 == 'l') || (l1 == 'L'));
  char l2 = s[0];
  s++;
  assert((l2 == 'l') || (l2 == 'L'));
  char o = s[0];
  s++;
  assert((o == 'o') || (o == 'O'));

  success();
  return 0;
}

