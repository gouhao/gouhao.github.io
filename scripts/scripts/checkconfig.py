#!/bin/python
# -*- coding:utf-8 -*-

"""
检查配置文件里的重复项

./checkconfig.py config
"""
from io import SEEK_SET
import os, sys

from matplotlib.pyplot import get

def get_kv(line):
    line = line.strip()
    if line.startswith("# CONFIG"):
        start = line.find("CONFIG")
        end = line.rfind(" is not")
        return (line[start:end], "%s" % line)
    else:
        i = line.find("=")
        return (line[:i], line[i+1:])

def is_skip_line(line):
    return ( line.startswith("#") and not line.startswith("# CONFIG") ) \
            or line.startswith("\n")

if __name__ == "__main__":
    path = sys.argv[1]
    tmp = "%s_tmp" % path
    ftmp = open(tmp, "w")

    fp = open(path, "r")
    config_dict = {}
    for line in fp:
        if is_skip_line(line):
            continue
        (k, v) = get_kv(line)

        if config_dict.has_key(k):
            print("already has %s, old_value: %s; new_value: %s" % (k, config_dict[k], v))
        config_dict[k] = v
    fp.seek(0, SEEK_SET)

    for line in fp:
        if is_skip_line(line):
            ftmp.write(line)
            continue
        (k, v) = get_kv(line)

        if not config_dict.has_key(k):
            continue

        if config_dict[k].startswith("# CONFIG"):
            ftmp.write("%s\n" % config_dict[k])
        else:
            ftmp.write("%s=%s\n" % (k, config_dict[k]))
        del config_dict[k]
    
    fp.close()
    ftmp.close()

    # os.rename(tmp, path)
