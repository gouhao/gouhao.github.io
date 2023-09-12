#!/bin/python
# -*- coding:utf-8 -*-

import sys, os
from common import *
from patch_parser import EulerPatchParser
import requests

if __name__ == "__main__":
    if len(sys.argv) < 2:
        log("Need a path!")
        exit(1)
    
    parser = EulerPatchParser(sys.argv[1])
    parser.start_parse()
    results = parser.get_results()

    fp = open("euler_fix_mainline_list", "w")
    counter = 0

    print("result_count=%d" % len(results))

    for i in range(0, len(results)):
        info = results[i]
        if info.origin.strip().startswith("mainline"):
            fp.write("%s\n" % info.name)
            counter += 1
    fp.close()

    print("counter=%d" % counter)

        
    