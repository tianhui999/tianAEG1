#include <stdio.h>
#include <string.h>

void vuln(char *src){
    char dst[0x10];

    strcpy(dst, src);
    printf("copy done\n");

    return;
}

void jmpesp(){
     __asm__ __volatile__("jmp %esp");
}

int main(void){
    char buf[0x100];

    scanf("%s", buf);
    vuln(buf);

    return 0;
}
