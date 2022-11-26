# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

from idaapi import *

'''
    第一个寄存器参数为idx0
    寻找r0-r3, 匹配MOV rx, yy模式，把yy返回
'''
def get_argv_from_reg(adr, idx):
    loop_cnt = 10
    while(loop_cnt):
        if(idc.get_operand_type(adr, 0) == 1 and idc.get_operand_value(adr, 0) == idx):  #mov rx, yy
            if(idc.print_insn_mnem(adr) == "MOV"):                  
                asm = idc.print_operand(adr, 1)
                if(asm.startswith("#")):        #判断是否为常量
                    return idc.get_operand_value(adr, 1)
        adr = ida_bytes.prev_not_tail(adr)
        if(adr == BADADDR):
            return BADADDR
        loop_cnt = loop_cnt - 1
        
    return  BADADDR

'''
    栈上第一个参数为idx0
    寻找栈上的参数, 匹配以下模式，将yy返回
    LDR rx, =yy 
    ADD rx, pc
    STR rx, [sp+?]
'''
def get_argv_from_stack(adr, idx):
    caller = adr
    loop_cnt = idx * 3    #平均2.x条指令写一个参数
    idx = idx - 4
    reg = BADADDR
    while(loop_cnt):
        if(idc.get_operand_type(adr, 1) == 4):                        #基址 + 索引 + 位移量, STR rx, [sp+?]
            if(idc.print_insn_mnem(adr) == "STR"):                    #确定操作类型
                asm = idc.print_operand(adr, 1)
                if(asm.startswith("[SP,#")):                         #确定是操作SP
                    if(idc.get_operand_value(adr, 1) == idx * 4):    #确定是指定参数序号
                        reg = idc.get_operand_value(adr, 0)
                        break
        adr = ida_bytes.prev_not_tail(adr)
        if(adr == BADADDR):
            return BADADDR
        loop_cnt = loop_cnt - 1
    
    
    if(reg == BADADDR):    #未找到参数
        print("no reg at %X" % caller)
        return BADADDR
    
    #print("reg:%d" % reg)
    #使用位置无关定位，先找PC偏移
    pc = 0
    loop_cnt = 12
    while(loop_cnt):
        if(idc.get_operand_type(adr, 1) == 1):                    
            if(idc.print_insn_mnem(adr) == "ADD"):                
                if(idc.get_operand_value(adr, 1) == 0xF):    #add Rx, PC
                    pc = adr
                    break
        adr = ida_bytes.prev_not_tail(adr)
        if(adr == BADADDR):
            return BADADDR    
        loop_cnt = loop_cnt - 1  
    
    if(pc == 0):
        print("no pc at %X" % caller)
        return BADADDR
    
    loop_cnt = 10
    while(loop_cnt):
        if(idc.get_operand_type(adr, 1) == 2):                    #内存引用, LDR rx, =yy 
            if(idc.print_insn_mnem(adr) == "LDR"):                #确定操作类型
                if(idc.get_operand_value(adr, 0) == reg):        #确定是指定参数序号
                    return idc.get_wide_dword(idc.get_operand_value(adr, 1)) + pc + 4
        adr = ida_bytes.prev_not_tail(adr)
        if(adr == BADADDR):
            return BADADDR    
        loop_cnt = loop_cnt - 1    
    return BADADDR

'''
    idx从0开始，第一个参数idx为0
    注意：已有常量或者地址的参数才能获取，变量的参数无法获取
    步骤：
    1. 若寻找的参数为r0-r3, 则匹配MOV rx, yy模式，把yy返回
    2. 若寻找的参数在栈上，则匹配以下模式，将yy返回
        LDR rx, =yy 
        ADD rx, pc
        STR rx, [sp+?]
'''
def get_argv(adr, idx):
    if(idx >= 4):
        return get_argv_from_stack(adr, idx-4)
    elif(idx >= 0):
        return get_argv_from_reg(adr, idx)
    else:
        return BADADDR
    
def main():
    # 手动输入或自动获取函数地址
    # target_func = 0x1AC8
    target_func = idc.get_name_ea_simple("")
    print("target_func: 0x%X" % target_func)

    found_count = 0
    next = ida_xref.get_first_fcref_to(target_func)
    while(next != BADADDR): 
        argv = get_argv(next, 2)
        #print("%X" % argv)
        if(argv != BADADDR and argv != 0):
            if(argv == 0x3):
                #idc.get_strlit_contents(func, -1, STRTYPE_C)
                print("%X: %X" % (get_func_attr(next, FUNCATTR_START), next));
                found_count += 1
        next = ida_xref.get_next_fcref_to(target_func, next)
    print("done! found: %d" % found_count)
    
if __name__ == '__main__':
    main()
    