#!/bin/python
# -*- coding:utf-8 -*-
import openpyxl
import sys

def get_patch_number_str(p):
    """ 
    获取patch序号
    
    p: patch文件名

    return: 解析成功，返回文件序号；否则返回0 
    """ 
    index = p.find("-")
    if index == -1: 
        return ""
    no = p[:index]
    return no

def read_array(f):
    fp = open(f, "r")
    ret = []
    for line in fp:
        ret.append(line.strip())
    return ret

if __name__ == "__main__":

    seq = read_array(sys.argv[1])

    wb = openpyxl.load_workbook(sys.argv[2])
    ws = wb.active
    
    
    for row in ws.rows:
        n = get_patch_number_str(row[8].value)
        if n == "":
            print(str(row[8].value))
            continue
        if n in seq:
            row[0].value = "Y"
        else:
            row[0].value = "N"

    wb.save(sys.argv[2])
