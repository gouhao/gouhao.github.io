#!/bin/python
# -*- coding:utf-8 -*-

"""
excel 操作

用法：
./excel_op.py

"""

import openpyxl
import sys

def insert_new_row(ws, row):
	item = (row[0].value, row[1].value, row[2].value, \
				row[3].value, row[4].value, row[5].value, row[6].value)
	ws.append(item)

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print("Usage: ./merge-patches-info.py "\
			"patches_info.xlsx task-202210.xlsx")
		exit(1)
	excel_path = sys.argv[1]
	commits_path = sys.argv[2]
	t = int(sys.argv[3])

	excel_wb = openpyxl.load_workbook(excel_path)
	excel_ws = excel_wb.active

	if not excel_ws:
		exit(1)
	
	fp = open(commits_path, "r")
	commit_lines = fp.readlines()
	fp.close()


	for row in excel_ws.rows:
		if len(commit_lines) == 0:
			break

		commit = row[2].value.strip()
		if not commit:
			continue
		count = 0
		
		for c in commit_lines:
			val = c[:12]
			if commit == val:
				if t == 1 or t == 2:
					row[0].value = "E"
					if t == 1:
						row[1].value = "我们的代码已合入"
				elif t == 3:
					row[0].value = "NM"
					row[1].value = "我们的代码是最新的"
				commit_lines.remove(c)
				break
	excel_wb.save(excel_path)
