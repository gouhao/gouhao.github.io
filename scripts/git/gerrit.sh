#!/bin/bash

## 批量对gerrit进行操作
##
## 1.把下面的账号(ut003637)替换成你的
## 2.start/end: 开始/结束的gerrit号
## 
## 用法：
## review: gerrit.sh "--code-review +2" start end
## abandon: ./gerrit.sh --abandon start end

for i in $(seq $2 $3) 
do
	ssh -p 29418 ut003637@gerrit.uniontech.com gerrit review $1 $i,1
done
