#include <stdio.h>
#include <string.h>

void vulnerable() {
   char temp[30];
   printf("lftnb");
   scanf("%s",temp);
}

int main(){
   vulnerable();
    __asm__ __volatile__("jmp %rsp");
}