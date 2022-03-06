# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

from idaapi import *

def dword_align(start, end=BADADDR, quote=True):
	if(end == BADADDR):
		end = start + 4
		
	for adr in range(start, end, 4):
		create_data(adr,FF_DWORD,4,BADADDR)
		if(quote):
			if(is_loaded(get_wide_dword(adr))):	#issue: IDA7.6 is_loaded fucntion can't not work in heap segment
				op_plain_offset(adr, 0, 0)

def print_struct(struct):
	for struct_name in struct:
		print("%s {" % struct_name)
		for sruct_attr in struct[struct_name]:
			print("\t%s:%s" % (sruct_attr, struct[struct_name][sruct_attr]))
		print("}")

'''
	strcut为二级字典
	一级字典索引为结构体成员名称
	二级字典索引有size、type、comment
		size为结构体成员大小，单位为byte
		type有效值：function、pointer、dword、word、byte、string
'''
def struct_align(start, end, struct):
	struct_size = 0
	for struct_name in struct:
		if("size" not in struct[struct_name] or "type" not in struct[struct_name]):
			print("error struct in struct_align")
			print_struct(struct)
			return
		struct_size += struct[struct_name]["size"]
	
	# print("stuct_size: %d" % struct_size)
	while(start < end):
		for struct_name in struct:
			if(struct[struct_name]["type"] == "function"):
				dword_align(start)
				add_func(get_wide_dword(start), BADADDR)
			elif(struct[struct_name]["type"] == "pointer"):
				create_data(start,FF_DWORD,4,BADADDR)
				op_plain_offset(start, 0, 0)
			elif(struct[struct_name]["type"] == "dword"):
				create_data(start,FF_DWORD,4,BADADDR)
			elif(struct[struct_name]["type"] == "word"):
				create_data(start,FF_WORD,2,BADADDR)
			elif(struct[struct_name]["type"] == "byte"):
				create_data(start,FF_BYTE,1,BADADDR)
			elif(struct[struct_name]["type"] == "string"):
				create_strlit(start, struct[struct_name]["size"], STRTYPE_C)
			else:
				print("%s unknwon type %s" % (struct_name,struct[struct_name]["type"]))
				
			if("comment" in struct[struct_name] and struct[struct_name]["comment"] != ""):
				set_cmt(start,struct[struct_name]["comment"],0)
			start += struct[struct_name]["size"]
		update_extra_cmt(start, E_PREV, "=========================================")
		
def main():
	# test_struct = {
		# "callback":{"size":4,"type":"function","comment":"callback"},
		# "stack":{"size":4,"type":"pointer","comment":"stack"},
		# "stack_size":{"size":4,"type":"dword","comment":"stack_size"},
		# "priority":{"size":4,"type":"dword","comment":"priority"},
		# "name":{"size":8,"type":"string","comment":"name"},
		# "id":{"size":4,"type":"dword","comment":"id"},
	# }

	# struct_align(0x805B5A48,0x805B5A64,test_struct)


if __name__ == '__main__':
	main()