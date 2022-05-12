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

'''
	ARM function format:
	1.  xx xx 2D E9 (STMFD SP!,{Rx-Ry,LR})
'''
def make_arm_func(start, end):
	find_and_make(start, end, "?? ?? 2D E9", 4)

'''
	Thumb function format:
	1.  xx B5 (push{Rx-Ry,LR})
	2.  2D E9 xx xx (PUSH.W {R1-R11,LR})
'''
def make_thumb_func(start, end):
	find_and_make(start, end, "?? B5", 2)
	find_and_make(start, end, "2D E9 ?? ??", 4)

def main():
	make_thumb_func(0x0000,0x6000)
	# make_arm_func(0x44FF000,0x4614614)

if __name__ == '__main__':
	main()