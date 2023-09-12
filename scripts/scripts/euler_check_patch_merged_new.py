#!/bin/python
# -*- coding:utf-8 -*-

"""
检查欧拉补丁是否已经合入，用来跟踪欧拉补丁的合入情况。

读取一个excel表，补丁记录必须是第0个工作表，表的第1列记录是否已经合入，第2列为补丁名
把要对比的补丁放到一个文件夹下
"""

import argparse
from common import *
import openpyxl
import os

def parse_args():
    """
    解析命令行参数

    -f: excel文件路径，必须。
    -p: 补丁路径，必须。
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file")
    parser.add_argument("-p", "--patches_path")

    return parser.parse_args()

def is_same_patch(name1, name2):
    if len(name1) < len(name2):
        str1 = name1
        str2 = name2
    else:
        str1 = name2
        str2 = name1
    return str2.startswith(str1)

def find_patch_in_list(patch, patch_list):
    """
    之所以用这种方式来判断，是因为有时候同一个补丁生成的名字不一样。
    """
    for p in patch_list:
        if is_same_patch(patch, p):
            return True
    return False

if __name__ == "__main__":
    args = parse_args()
    if not args.file or not args.patches_path:
        log("Need params!")
        exit(1)
    
    patches = []
    
    patches_tmp = os.listdir(args.patches_path)
    patches_tmp.sort(patch_name_cmp)
    for p in patches_tmp:
        patches.append(get_patch_name(p))

    wb = openpyxl.load_workbook(args.file)
    ws = wb.active
    
    
    for row in ws.rows:
        if not row[0].value or row[0].value == "N":
            if find_patch_in_list(get_patch_name(row[1].value), patches):
                row[0].value = "Y"
            else:
                row[0].value = "N"

    wb.save(args.file)
