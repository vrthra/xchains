#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void success() {
    printf("succes!\n");
    exit(0);
}

int main(int argc, char* argv[]) {
  assert(argc > 1);
  char* is_hello = argv[1];
  if (is_hello[0] == 'h') {
    if (is_hello[1] == 'e') {
      if (is_hello[2] == 'l') {
        if (is_hello[3] == 'l') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        } else if (is_hello[3] == 'L') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        }
      } else if (is_hello[2] == 'L') {
        if (is_hello[3] == 'l') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        } else if (is_hello[3] == 'L') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        }
      }
    } else if (is_hello[1] == 'E') {
      if (is_hello[2] == 'l') {
        if (is_hello[3] == 'l') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        } else if (is_hello[3] == 'L') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        }
      } else if (is_hello[2] == 'L') {
        if (is_hello[3] == 'l') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        } else if (is_hello[3] == 'L') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        }
      }
    }
  } else if (is_hello[0] == 'H') {
    if(is_hello[1] == 'e') {
      if (is_hello[2] == 'l') {
        if (is_hello[3] == 'l') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        } else if (is_hello[3] == 'L') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        }
      } else if (is_hello[2] == 'L') {
        if (is_hello[3] == 'l') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        } else if (is_hello[3] == 'L') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        }
      }
    } else if (is_hello[1] == 'E') {
      if (is_hello[2] == 'l') {
        if (is_hello[3] == 'l') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        } else if (is_hello[3] == 'L') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        }
      } else if (is_hello[2] == 'L') {
        if (is_hello[3] == 'l') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        } else if (is_hello[3] == 'L') {
          if (is_hello[4] == 'o') {
            printf("hello!\n");
            success();
          } else if (is_hello[4] == 'O') {
            printf("hello!\n");
            success();
          }
        }
      }
    }
  }
  return 1;
}

