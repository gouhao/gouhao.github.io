#!/bin/python
# -*- coding:utf-8 -*-

"""
检查系统调用
./checksyscall.py syscall_64.tbl base_syscall.list
"""

import os, sys
from tkinter import N
import openpyxl

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("param error!")
		exit(1)

	check_syscall_list = []
	fp = open(sys.argv[1], "r")
	for line in fp:
		line = line.strip()
		if len(line) == 0 or line.startswith("#"):
			continue
		items = line.split(" ")
		check_syscall_list.append(line)
	fp.close()

	wb = openpyxl.load_workbook(sys.argv[2])
	ws = wb.active
	for row in ws.rows:
		if not row[0].value or len(row[0].value) == 0:
			continue
		if row[0].value not in check_syscall_list:
			row[0].value = ""
			row[1].value = "N"

	wb.save(sys.argv[2])


	
