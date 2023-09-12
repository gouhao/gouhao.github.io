# -*- coding:utf-8 -*-

import os

def log(msg):
    print(msg)

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

def get_patch_name(filename):
    start = filename.find("-") + 1
    end = filename.rfind(".patch")
    return filename[start:end]

def get_patch_commit_oneline(path):
    fp = open(path, "r")
    line = fp.readline()
    commit_id = line.split(" ")[1][:12]

    fp.readline()
    fp.readline()

    line = fp.readline()
    sub = line[len("Subject: "):]
    if sub.startswith("["):
        index = sub.find("]")
        if index != -1:
            sub = sub[index+1 : ].strip()

    line = fp.readline().strip()
    if line != "":
        sub = "%s %s" % (sub, line)

    return (commit_id, sub)