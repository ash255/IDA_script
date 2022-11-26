# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

from idaapi import *

def make_struct(struct_name, struct_size):
    print("make struct: name=%s size=%x" % (struct_name, struct_size))

    struc_id = idc.add_struc(-1, struct_name, 0)
    if(struc_id == -1):
        print("add struct failed")
        return False
     
    offset = 0
    while(struct_size > 4):
        member_name = "field_%X" % offset
        idc.add_struc_member(struc_id, member_name, -1, FF_DWORD, -1, 4, -1, 0, 0)
        struct_size -= 4
        offset += 4
        
    while(struct_size > 0):
        member_name = "field_%X" % offset
        idc.add_struc_member(struc_id, member_name, -1, FF_BYTE, -1, 1, -1, 0, 0)
        struct_size -= 1
        offset += 1
        
    return True

def main():
    struct_name = ida_kernwin.ask_text(0, None, "请输入结构体名称")
    if(struct_name == None):
        return
        
    struct_size = ida_kernwin.ask_long(0, "请输入结构体大小")
    if(struct_size == None):
        return

    make_struct(struct_name, struct_size)
    
if __name__ == '__main__':
    main()
    