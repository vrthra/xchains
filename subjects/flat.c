#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
void success() {
  printf("success\n");
  exit(0);
}
int main(int argc, char* argv[]) {
  assert(argc > 1);
  if (argv[1][0] > 'a') {
    printf("A\n");
    success();
  }
  return 0;
}
