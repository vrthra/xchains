#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
/*produces 2^5 hellos*/

void success() {
  printf("done!\n");
  exit(0);
}

int main(int argc, char* argv[0]) {
  assert(argc > 1);
  char* s = argv[1];
  char h = s[0];
  assert((h == 'h') || (h == 'H'));
  s++;
  char e = s[0];
  assert((e == 'e') || (e == 'E'));
  s++;
  char l1 = s[0];
  assert((l1 == 'l') || (l1 == 'L'));
  s++;
  char l2 = s[0];
  assert((l2 == 'l') || (l2 == 'L'));
  s++;
  char o = s[0];
  assert((o == 'o') || (o == 'O'));
  s++;
  char end = s[0];
  assert(end == 0);
  success();
  return 0;
}

