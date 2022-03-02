# !/usr/bin/env python3
# -*- coding:utf-8 -*-  

import configparser
import os
import re
from idaapi import *
from tkinter import *


cf = configparser.ConfigParser()
root = 0
vok = 0

#*******************
#UI code
#*******************
def ok():
	global root
	vok.set(1)
	root.destroy()
def cancel():
	global root
	vok.set(0)
	root.destroy()

def UI(item):
	if(len(item) <= 0):
		return
	global root,vok
	root = Tk()
	root.title("DeJunk")
	
	vok = IntVar()
	vstart = StringVar()
	vlength = StringVar()
	vtype = StringVar()
	vdir = IntVar()
	
	lsta = Label(root,text="start[hex]")
	llen = Label(root,text="length[hex]")
	litem = Label(root,text="type")
	esta = Entry(root,width=10,textvariable=vstart)	
	elen = Entry(root,width=10,textvariable=vlength)	
	cxitem = ttk.Combobox(root,width=7,textvariable=vtype)
	
	esta.insert("end","%X" % get_screen_ea()) #默认为当前光标地址
	elen.insert("end","1000")
	cxitem["values"] = item
	cxitem["state"] = "readonly"
	vtype.set(item[0])
	
	vdir.set(1) #默认选择down
	rup = Radiobutton(root, text="up", variable=vdir, value=0)
	rdown = Radiobutton(root, text="down", variable=vdir, value=1)

	bok = Button(root,text="ok",command=ok,width=8,height=1)
	bcn = Button(root,text="cancel",command=cancel,width=8,height=1)
	
	lsta.grid(row=1,column=1,padx=10, pady=5)
	esta.grid(row=1,column=2,padx=10, pady=5)
	llen.grid(row=2,column=1,padx=10, pady=5)
	elen.grid(row=2,column=2,padx=10, pady=5)
	litem.grid(row=3,column=1,padx=10, pady=5)
	cxitem.grid(row=3,column=2,padx=10, pady=5)
	rup.grid(row=4,column=1)
	rdown.grid(row=4,column=2)
	bok.grid(row=5,column=1,pady=5)
	bcn.grid(row=5,column=2,pady=5)
	
	root.mainloop()
	
	#print("%s %s %d" % (vstart.get(),vlength.get(),vdir.get()))
	rlist = []
	rlist.append(vstart.get())
	rlist.append(vlength.get())
	rlist.append(vtype.get())
	rlist.append(vdir.get())
	rlist.append(vok.get())
	return rlist

#*******************
#ida dejunk code
#*******************
def dejunk(start,length,dir,S,R):
	if(len(S) != len(R)):
		return 0

	found = 0
	S = re.sub(r"(?<=(\w|\?))(?=(?:(\w|\?)(\w|\?))+$)", " ", S)
	R = re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", R)
	R = R.split(" ")	
	pat = compiled_binpat_vec_t()
	parse_binpat_str(pat, start, S, 16)
	if(dir == "0"):#"0"=向上查找,"1"=向下查找
		end = start - length
		if(end < 0):
			end = 0;
		while(1):
			start = bin_search(end,start,pat,BIN_SEARCH_NOSHOW|BIN_SEARCH_CASE|BIN_SEARCH_BACKWARD)
			if(start == BADADDR):
				break
			if(start < end):
				break
			for byte in R:
				patch_byte(start,int(byte,16))
				start += 1
			start -= len(R)
			found += 1			
	else:
		end = start + length
		while(1):
			start = bin_search(start,end,pat,BIN_SEARCH_NOSHOW|BIN_SEARCH_CASE|BIN_SEARCH_FORWARD)
			if(start == BADADDR):
				break
			if(start > end):
				break
			for byte in R:
				patch_byte(start,int(byte,16))
				start += 1
			found += 1	
	return found

def main():
	ini_path = os.path.dirname(__file__) + "/DeJunk.ini"
	
	flist = cf.read(ini_path)
	if(not flist):
		print("file %s not found" % ini_path)
		print(flist)
		return
	
	slist = cf.sections();
	if("OPTION" not in slist):
		print("no OPTION in %s" % ini_path)
		return
	optlist = cf.options("OPTION")
	if("junktype" not in optlist):
		print("no JunkType in OPTION")
		return
	typelist = cf.get("OPTION","JunkType").split(",")
	rlist = UI(typelist)

	if(rlist[3] == "0"):
		print("cancel")
		return;
	
	start = rlist[0]
	length = rlist[1]
	type = rlist[2]
	dir = rlist[3]#"0"=up,"1"=down
	
	start = int(start,16)
	if(not is_loaded(start)):
		print("start address %08X not load" % start)
		return
	length = int(length,16)		
	
	sublist = cf.get("OPTION","PatList_"+type).split(",")
	if(sublist == False):
		print("no %s in OPTION\n" % "PatList_"+type)
		return	
		
	print("start:%08X length:%08X type:%s dir:%s" % (start,length,type,dir))
	
	found = 0
	for sec in sublist:
		sec = "CODE" + sec
		S = cf.get(sec,"S")
		R = cf.get(sec,"R")
		if(S != "" and R != ""):
			found += dejunk(start,length,dir,S,R)

	print("%d junk patched" % found)
	
if __name__ == '__main__':
	main()
	
