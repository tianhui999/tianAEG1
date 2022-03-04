# tianAEG1

这个AEG主要是参考的[insomnihack_aeg](https://github.com/angr/angr-doc/tree/master/examples/insomnihack_aeg)进行改进的

改进点：

1.增加了对64位程序的利用

2.增加了寻找导致栈溢出的危险函数，并以此来使angr 跳转到危险函数地址进行检测是否有unconstrained状态

3.增加了在栈上的jmp esp + shellcode 类型的栈溢出利用

