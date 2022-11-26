# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

from idaapi import *

def find_and_make(start, end, pat, align):

	func_count = 0
	ea = start
	while(ea < end):
		#find_binary(ea, flag, searchstr, radix=16, from_bc695=False)
		ea = idc.find_binary(ea, SEARCH_DOWN, pat, 16, False)
		if(ea == BADADDR or ea > end):
			break
		
		if((ea % align) != 0): #不是align字节对齐
			ea += 1
			continue
			
		if(get_func_name(ea) != None):	#如果是已定义函数，继续查找
			ea = find_func_end(ea)
			continue
		
		asm_text = generate_disasm_line(ea, GENDSM_FORCE_CODE)
		is_func = False
		if(asm_text.find("STMFD") != -1):
			is_func = True
		elif(asm_text.find("PUSH") != -1):
			is_func = True
			
		if(is_func and add_func(ea)):
			func_count += 1	
		
		ea += 1

def make_arm_bl(start, end, func):
	pass

def calc_thumb_ins(adr, func):
	off1 = (((func - adr - 4)>>1) >> 11) &0x7FF	#get high 11 bits
	off2 = ((func - adr - 4)>>1) & 0x7FF		#get low 11 bits
	ins1 = 0xF000 + off1
	ins2 = 0xF800 + off2
	return (ins1) | (ins2 << 16)
	

def make_thumb_bl(start, end, func):
	while(start < end):
		ins_ex = calc_thumb_ins(start, func)
		if(get_wide_dword(start) == ins_ex):
			print("found at %X" % start)
		start += 2

def main():
	make_thumb_bl(0x0800B000,0x8019168,0x801733C)

if __name__ == '__main__':
	main()