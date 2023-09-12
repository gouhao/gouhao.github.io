#!/bin/python
# -*- coding:utf-8 -*-

"""
检查系统调用
./checksyscall.py syscall_64.tbl base_syscall.list
"""

import os, sys

def check_str(buf, str):
	for item in buf:
		if item.find(str) != -1:
			return True
	return False

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("param error!")
		exit(1)

	base_syscall = []
	fp = open(sys.argv[1], "r")
	for line in fp:
		line = line.strip()
		if len(line) == 0 or line.startswith("#"):
			continue
		items = line.split(" ")
		base_syscall.append(line)
	fp.close()

	check = []
	fp = open(sys.argv[2], "r")
	for line in fp:
		line = line.strip()
		if len(line) == 0 or line.startswith("#"):
			continue
		items = line.split(" ")
		check.append(line)
	fp.close()

	for s in base_syscall:
		if not check_str(check, s):
			print("not support %s" % s)



	
