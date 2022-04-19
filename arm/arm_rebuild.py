# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

from idaapi import *

def make_func(start, end, pat_str, align):
	pat = compiled_binpat_vec_t()
	parse_binpat_str(pat, start, pat_str, 16)
	
	func_count = 0
	while(start < end and start != BADADDR):
		start = bin_search(start, end, pat, BIN_SEARCH_NOSHOW|BIN_SEARCH_FORWARD)
		if(start == BADADDR):	#找不到pat就结束
			break
		elif(get_func_name(start) != None):	#如果是已定义函数，继续查找
			start = find_func_end(start)
			continue
		elif((start % 4) != 0):	#不是align字节对齐
			start += 1
			continue
		else:
			asm_text = generate_disasm_line(start,GENDSM_FORCE_CODE)
			is_func = False
			if(asm_text.find("STMFD") != -1):
				is_func = True
			elif(asm_text.find("PUSH") != -1):
				is_func = True
			if(is_func):
				add_func(start)
				# print("rebuild func: %X" % start)
				start += 1
				func_count += 1	
	print("rebuild function total: %d" % func_count)

'''
	ARM function format:
	1.  xx xx 2D E9 (STMFD SP!,{Rx-Ry,LR})
'''
def make_arm_func(start, end):
	make_func(start, end, "2D E9 ?? ??", 4)

'''
	Thumb function format:
	1.  xx B5 (push{Rx-Ry,LR})
'''
def make_thumb_func(start, end):
	make_func(start, end, "?? B5", 2)


def main():
	# make_arm_func(0x80000000,0x80470640)
	make_arm_func(0x458C440,0x4614614)

if __name__ == '__main__':
	main()