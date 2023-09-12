#!/bin/python
# -*- coding:utf-8 -*-

"""
检查excel表里重复的补丁

用法：
./check_dupli_patch.py -m excel -s sheet_name
注意：表的第0~5列分别是：特性名称, 状态, 负责人, 备注, Commit-Id, Subject, Bug-ID

例如：
./check_dupli_patch.py main.xlsx
"""

import openpyxl
import argparse, sys

def parse_args():
	"""
	解析命令行参数
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument("-m", "--main")
	parser.add_argument("-s","--sheet_name", default=None)

	return parser.parse_args()

def get_sheet(wb, sheed_name):
	try:
		return wb.get_sheet_by_name(name = sheed_name)
	except:
		return None

INDEX_FEATURE_NAME = 0
INDEX_STATUS = 1
INDEX_OWNER = 2
INDEX_COMMENT = 3
INDEX_COMMITID = 4
INDEX_SUBJECT = 5
INDEX_BUGID = 6

def insert_new_row(ws, row):
	item = (row[0].value, row[1].value, row[2].value, \
				row[3].value, row[4].value, row[5].value, row[6].value)
	ws.append(item)

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print("Usage: ./merge-patches-info.py "\
			"patches_info.xlsx task-202210.xlsx")
		exit(1)
	args = parse_args()
	main_xlsx_path = args.main

	main_wb = openpyxl.load_workbook(main_xlsx_path)
	main_ws = main_wb.active
	if args.sheet_name:
		main_ws = get_sheet(main_wb, args.sheet_name)

	if not main_ws:
		exit(1)


	for row in main_ws.rows:
		subj = row[INDEX_SUBJECT].value.strip()
		if not subj:
			continue
		count = 0
		for r2 in main_ws.rows:
			sub2 = r2[INDEX_SUBJECT].value.strip()
			if r2[INDEX_SUBJECT].value == subj:
				count += 1

		if count > 1:
			print("%s %s %s" % (row[INDEX_OWNER].value, row[INDEX_COMMITID].value, subj))
