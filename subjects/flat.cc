#include<stdio.h>
#include<assert.h>
extern "C" void success() {
  printf("success\n");
}
int main(int argc, char* argv[]) {
  assert(argc > 1);
  if (argv[1][0] > 'a') {
    printf("A\n");
    success();
  }
}
