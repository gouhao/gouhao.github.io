# 容器

## 安装docker
sudo yum-config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
yum install docker-ce

## 运行镜像
```sh	
$ docker run -i -t IMAGE /bin/bash

-i -interactive = true | false 默认是false  ：守护进程是否打开标准输入

-t -tty = true | false 默认是false   ： 是否为容器打开-tty终端
```