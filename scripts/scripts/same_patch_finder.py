#!/bin/python
# -*- coding:utf-8 -*-

"""
找相同的补丁,并将相同的补丁分别移到名自文件夹

使用方法：
./same_patch_finder.py /home/patches1 /home/patches2
执行完后，会把patches1 和 patches2 中相同的补丁，移动到patches1_tmp, patches2_tmp

作者：苟浩 <gouhao@uniontech.com>
日期：2021年11月18日
"""
import sys, os, glob
import openpyxl
from common import log, get_patch_name, patch_name_cmp

if __name__ == "__main__":
    if len(sys.argv) < 3:
        log("Need two path!")
        exit(1)
    p1 = sys.argv[1]
    p2 = sys.argv[2]

    if p1.endswith("/"):
        p1 = p1[:-1]
    if p2.endswith("/"):
        p2 = p2[:-1]

    # p1_files为patch数量较少的文件夹
    p1_files = os.listdir(p1)
    p2_files = os.listdir(p2)

    if len(p2_files) < len(p1_files):
        p1_files = p2_files
        p2_files = os.listdir(p1)
        p2 = p1
        p1 = sys.argv[2]
    
    p1_files.sort(patch_name_cmp)

    p1_tmp_dir = "%s_tmp" % p1
    p2_tmp_dir = "%s_tmp" % p2

    os.system("rm -rf %s %s" % (p1_tmp_dir, p2_tmp_dir))
    os.mkdir(p1_tmp_dir)
    os.mkdir(p2_tmp_dir)
    
    wb = openpyxl.Workbook()
    ws = wb.worksheets[0]

    same_count = 0
    last_same_name = ""
    for f in p1_files:
        patch_name = get_patch_name(f)
        p1_same_list = glob.glob("%s/*-%s.patch" % (p1, patch_name))
        p2_same_list = glob.glob("%s/*-%s.patch" % (p2, patch_name))
        p1_same_list.sort(patch_name_cmp)
        p2_same_list.sort(patch_name_cmp)

        p1_len = len(p1_same_list)
        p2_len = len(p2_same_list)
        if p2_len == 1:
            same_count += 1
            os.system("mv %s/%s %s/%d-%s.patch" % (p1, f, p1_tmp_dir, same_count, patch_name))
            os.system("mv %s %s/%d-%s.patch" % (p2_same_list[0], p2_tmp_dir, same_count, patch_name))
        elif p2_len > 1:
            if p2_len != p1_len:
                ws.append((str(p1_same_list), str(p2_same_list)))
                i = 0
                for tf in p1_same_list:
                    same_count += 1
                    os.system("mv -f %s %s/%d-%s-%d.patch" % (p1_same_list[i], p1_tmp_dir, same_count, patch_name, i))
            else:
                
                i = 0
                for tf in p1_same_list:
                    same_count += 1
                    os.system("mv -f %s %s/%d-%s-%d.patch" % (p1_same_list[i], p1_tmp_dir, same_count, patch_name, i))
                    os.system("mv -f %s %s/%d-%s-%d.patch" % (p2_same_list[i], p2_tmp_dir, same_count, patch_name, i))


    wb.save("euler_vs_anolis.xlsx")   
        
    log("same patches: %d" % same_count)


    


        