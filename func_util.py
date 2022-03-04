# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

from idaapi import *

# 统计函数被外部调用的次数
def get_func_call_count(func_adr):
	call_list = []
	target = get_first_cref_to(func_adr)
	
	while(target != BADADDR):
		call_list.append(target)
		target = get_next_cref_to(func_adr,target)
	
	func_name = get_func_name(func_adr)
	return (func_adr, func_name, len(call_list), call_list)
	
def get_func_call_count_all():
	# min_ea = inf_get_min_ea()
	min_ea = 0
	
	func = get_next_func(min_ea)
	if(func == None):
		print("can't find any function")
		return
	func_list = []
	while(func != None):
		func_tuple = get_func_call_count(func.start_ea)
		func_list.append(func_tuple)
		# print("adr: %X  count: %-4d  name: %s" % (func_tuple[0], func_tuple[2], func_tuple[1]))
		func = get_next_func(func.start_ea)
	
	func_list = sorted(func_list, key=lambda x:x[2], reverse=True)
	# 打印前10项
	print("[+]function call sort:")
	for i in range(0,(len(func_list),10)[len(func_list) >= 10]):
		print("[%d]adr: %X  count: %-4d  name: %s" % (i, func_list[i][0], func_list[i][2], func_list[i][1]))

def test_get_func_call_count():
	get_func_call_count_all()
	
def main():
	test_get_func_call_count()

# if __name__ == '__main__':
	# main()
