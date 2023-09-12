#!/bin/python
# -*- coding:utf-8 -*-

"""
把补丁处理成方便review的格式

作者：苟浩 <gouhao@uniontech.com>
日期：2021年12月16日
"""

import sys, os

def get_patch_number_str(p):
    """
    获取patch序号
    
    p: patch文件名

    return: 解析成功，返回文件序号；否则返回0
    """
    index = p.find("-")
    if index == -1:
        return None
    no = p[:index]
    return no

def get_patch_number(p):
    no = get_patch_number_str(p)
    if no and no.isdigit():
        return int(no)
    return 0



def patch_name_cmp(p1, p2):
    """
    patch文件名比较器
    p1, p2: 两个patch文件名
    """
    return get_patch_number(os.path.basename(p1)) - get_patch_number(os.path.basename(p2))

def rm_patch_header_footer(patch_dir, p):
        filename = "%s/%s" % (patch_dir, p)
        fp = open(filename, "r")

        tmp = "%s_tmp" % filename
        fp2 = open(tmp, "w")

        lines = fp.readlines()
        start = 5
        while True:
            if lines[start].strip() != "":
                break
            start += 1
            
        fp2.writelines(lines[start:-2])

        fp.close()
        fp2.close()

        os.rename(tmp, filename)

def is_skip_line(line):
    if line.startswith("index"):
        return True
    elif line.startswith("Change-Id:"):
        return True
    elif line.find("Gou Hao") != -1:
	return True
    elif line.find("xuzhenhai") != -1:
        return True
    elif line.find("Donghua Liu") != -1:
        return True
    elif line.find("goutongchen") != -1:
        return True
    elif line.find("jiaofenfang") != -1:
        return True
    elif line.find("Yang Yingliang") != -1:
        return True
    elif line.find("ankun") != -1:
        return True
    elif line.find("CaiNa") != -1:
        return True
    elif line.find("daifan") != -1:
        return True
    elif line.find("meihaipeng") != -1:
        return True
    elif line.find("Wang You") != -1:
        return True
    elif line.find("jiazhenyuan") != -1:
        return True
    elif line.startswith("Cherryfrom:"):
        return True
    elif line.startswith("(cherry picked"):
        return True
    elif line.startswith("This reverts commit"):
        return True
    return False

def rm_patch_flag(dir, patch):
    filename = "%s/%s" % (dir, patch)
    fp = open(filename, "r")

    tmp = "%s_tmp" % filename
    fp2 = open(tmp, "w")
    
    is_cherry_line = False
    for line in fp:
        if is_skip_line(line):
            if line.startswith("Cherryfrom:"):
                is_cherry_line = True
            continue
        
        if is_cherry_line:
            is_cherry_line = False
            continue

        if line.startswith("@@"):
            i = line.find("@@", 2)
            line = line[i:]
        fp2.write(line)
    fp.close()
    fp2.close()

    os.rename(tmp, filename)

def rm_number(dir, patch):
    name = patch[patch.find("-") + 1:]
    new_name = "%s/%s"  % (dir, name)
    i = 1
    while True:
        if not os.path.exists(new_name):
            break
        i += 1
        new_name = "%s_%d" % (new_name, i)
    os.rename("%s/%s" % (dir, patch), new_name)

def process(dir):
    patches = os.listdir(p)
    patches.sort(patch_name_cmp)
    for patch in patches:
        if not os.path.isfile("%s/%s" % (dir, patch)):
            continue
        rm_patch_header_footer(dir, patch)
        rm_patch_flag(dir, patch)
        rm_number(dir, patch)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Need path dirs!")
        exit(1)
    for p in sys.argv[1:]:
        process(p)
