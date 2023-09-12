#!/bin/python
# -*- coding:utf-8 -*-

"""
用于合并510补丁处理状态

用法：
./merge510task.py 主表 需要合到主表上的任务表
注意：表的第0~5列分别是：特性名称, 状态, 负责人, 备注, Commit-Id, Subject, Bug-ID

例如：
./merge510task.py patches_info.xlsx task-202210.xlsx
"""

import openpyxl
import argparse, sys

def parse_args():
	"""
	解析命令行参数
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument("-m", "--main")
	parser.add_argument("-t","--task")
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
		print("Usage: eg: ./merge-patches-info.py" \
			"patches_info.xlsx task-202210.xlsx")
		exit(1)
	args = parse_args()
	main_xlsx_path = args.main
	task_xlsx_path = args.task

	main_wb = openpyxl.load_workbook(main_xlsx_path)
	main_ws = main_wb.active
	if args.sheet_name:
		main_ws = get_sheet(main_wb, args.sheet_name)

	if not main_ws:
		exit(1)

	task_wb = openpyxl.load_workbook(task_xlsx_path)
	task_ws = task_wb.active

	for row in task_ws.rows:
		commit_id = row[INDEX_COMMITID].value
		if not commit_id:
			continue
		found = False
		for r2 in main_ws.rows:
			if r2[INDEX_COMMITID].value != commit_id:
				continue

			found = True
			for i in range(0, 7):
				r2[i].value = row[i].value
			break
		if not found:
			insert_new_row(main_ws, row)
		
	main_wb.save(main_xlsx_path)
