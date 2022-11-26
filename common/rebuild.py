# !/usr/bin/env python
# -*- coding:utf-8 -*-  

from idaapi import *

def make_align(start, end=None):
    if(end==None):
        end=start+4
    for adr in range(start,end,4):
        idc.create_data(adr,FF_DWORD,4,BADADDR)

def make_quote(start, end=None):
    if(end==None):
        end=start+4
    for adr in range(start,end,4):
        idc.op_plain_offset(adr,0,0)

def make_func_quote(start,end=None):
    if(end==None):
        end=start+4
    for adr in range(start,end,4):
        func_adr = idc.get_wide_dword(adr)
        idc.add_func(func_adr, BADADDR)
        
'''
    rebuild template
'''
def rebuild_task_info(start,end):
    for adr in range(start,end,28):
        make_align(adr)
        make_quote(adr)
        make_func_quote(adr)
        func_name =  b'task_' + get_strlit_contents(adr+16, 8, STRTYPE_C)
        set_name(get_wide_dword(adr), func_name.decode(), SN_CHECK)
        set_cmt(adr,"callback",0)
        
        make_align(adr+4)
        make_align(adr+8)
        make_align(adr+12)
        create_strlit(adr+16, 8, STRTYPE_C)
        make_align(adr+24)
        
        set_cmt(adr+4,"stack",0)
        set_cmt(adr+8,"stack size",0)        
        set_cmt(adr+12,"priority",0)            
        set_cmt(adr+16,"name",0)            
        set_cmt(adr+24,"id",0)

        update_extra_cmt(adr+28, E_PREV, "=========================================")
        
def main():
    pass
    
if __name__ == '__main__':
    main()