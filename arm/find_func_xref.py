# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

from idaapi import *

def find_bl_arm(func, start, end):
    cur = start
    found = 0
    while(cur < end):
        opcode = 0xEB000000 | (((func - cur - 8) // 4) & 0xFFFFFF)
        if(idc.get_wide_dword(cur) == opcode):
            print("found: %X" % cur)
            found += 1
        cur += 4
    print("done! found: %d" % found)

#x=1:blx or x=0:bl
def calc_thumb_ins(adr, func, x=0):
    off1 = (((func - adr - 4)>>1) >> 11) &0x7FF    #get high 11 bits
    off2 = ((func - adr - 4)>>1) & 0x7FF           #get low 11 bits
    ins1 = 0xF000 + off1
    ins2 = 0
    if(x == 1):
        off2 = (off2+1) & ~1
        ins2 = 0xE800 + off2
    else:
        ins2 = 0xF800 + off2
    return (ins1) | (ins2 << 16)

def find_bl_thumb(func, start, end):
    cur = start
    found = 0
    while(cur < end):
        opcode_bl = calc_thumb_ins(cur, func, 0)
        opcode_blx = calc_thumb_ins(cur, func, 1)
        dword = idc.get_wide_dword(cur)
        # print("%X %X" % (cur, opcode_blx))
        if(dword == opcode_bl or dword == opcode_blx):
            print("found: %X" % cur)
            found += 1
        cur += 2
        # break
    print("done! found: %d" % found)
    
def main():
    find_bl_arm(0x800CF4B8, 0x80000000, 0x80470640)
    # find_bl_thumb(0x8004CB50, 0x80000000, 0x80470640)
    

if __name__ == '__main__':
    main()