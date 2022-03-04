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
    char buf[0x17];

    read(0, buf, 0x80);
    vuln(buf);

    return 0;
}
