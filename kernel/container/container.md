# 容器

## 安装docker
sudo yum-config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
yum install docker-ce

## 容器相关命令
### 导入本地镜像
```sh
$ cat cgroup/uniontechos-server-20-1050u1a-amd64-cui-release-20220722-1700.img.tar | docker import - gouhao:1.0
sha256:01331d1b27b1725992d1eb2a29772510ff446f006a1d8d5fd0453f43dbb871ab
$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
gouhao              1.0                 01331d1b27b1        38 seconds ago      317MB

$ docker rmi -f 01331d1b27b1
Untagged: gouhao:1.0
Deleted: sha256:01331d1b27b1725992d1eb2a29772510ff446f006a1d8d5fd0453f43dbb871ab

docker run -it uniontechos-server-20-1050u1a:latest /bin/bash

```
### 启动交互式容器
```sh	
$ docker run -i -t IMAGE /bin/bash

-i -interactive = true | false 默认是false  ：守护进程是否打开标准输入

-t -tty = true | false 默认是false   ： 是否为容器打开-tty终端
```
### 查看容器
```sh
$docker ps [-a] [-l] : -a是指列出所有的容器 ； -l是指列出最新创建的容器

$docker inspect : inspect代表的是容器的名字，既可以是容器的名字也可以是容器的id
```

### 自定义容器名
```sh
$docker run --name=自定义名 -i -t IMAGE /bin/bash
```

### 重新启动停止的容器
```sh
$docker start [-i] 容器名 ：-i是指它可以以交互的方式来重新启动已经停止的容器

删除停止的容器：
$docker rm 容器名
```

## Docker--守护式容器
* 什么是守护式容器：
* 能够长期运行
* 没有交互式会话
* 适合运行应用程序和服务

### 以守护形式运行容器
```sh
$docker run - i -t IMAGE /bin/bash


Ctrl+P   Ctrl+Q :以ctrl+p 加上Ctrl+q的组合键来退出交互式容器的bash，这样容器就会在后台运行

$docker run -d 镜像名 [COMMAND] [ARG...]  :  -d是指以后台的形式运行命令，但是在命令结束后，容器依旧会停止
```

### 附加到运行中的容器
```sh
$docker attach 容器名
```

### 启动守护式容器
```sh
$docker run -d 镜像名 [COMMAND] [ARG...]  :  -d是指以后台的形式运行命令，但是在命令结束后，容器依旧会停止
查看容器日志：
$docker logs [-f] [-t] [-tail] 容器名

-f --follows = true | false 默认为false   ：-f是告诉logs 一直跟踪日志的变化，并返回结果

-t --timestamps=true | false 默认为false  : -t是在返回的结果上加上时间戳

--tail = “all”           ： --tail 是选择返回结尾处多少数量的日志，那么如果不指定，logs返回所有的日志
查看容器内运行中进程:
docker top 容器名 ：来查看运行中容器的进程
```

### 在运行中的容器内启动新进程
```sh
$docker exec [-d] [-i] [-t] 容器名 [COMMAND] [ARG...] 
exec用来在已经运行的容器中启动新进程
如何停止守护式容器：
$docker stop 容器名   stop 发送一个信号给容器，等待容器的停止
$docker kill 容器名   kill 会直接停止容器
```

## Docker--查看和删除镜像
### Docker Image 镜像
* 容器的基石
* 层叠的只读文件系统
* 联合加载（union mount）
* 存储位置： /var/lib/docker

### 查看和删除镜像 -列出镜像
```sh
$docker images [OPTSIONS] [REPOSITORY]
-a --all=false      显示所有镜像，默认不显示中间层的镜像
-f --filter=[]      显示时的过滤条件，
--no-trunc =false  是指定不使用截断的形式来显示数据，默认情况下我们用images命令查到的列表是会截断镜像的唯一id的。

-q, --quiet=false   只显示镜像的唯一id。
```

### 查看和删除镜像-镜像的仓库
REPOSITORY 仓库
REGISTYRY  仓库？
### 查看和删除镜像-镜像标签
TAG : ubuntu:14.04
ubuntu:latest

### 查看和删除镜像-查看镜像
```sh
$docker inspect [OPTIONS] CONTAINER|IMAGE [CONTAINER|IMAGE...]
-f,--format=""
查看和删除镜像-删除镜像
$docker rmi [OPTIONS] IMAGE [IMAGE...]
-f--force=false  Force removal of the image :强制移除图像
-no-prune=false   Do not Delete untagged parents :保留被删除镜像中被打标签的父镜像
```

## Docker-获取和推送镜像
### 获取和推送镜像-查找镜像

几种查找镜像的方式

1.Docker Hub
https://registry.hub.docker.com

2.$docker search [OPTIONS] TERM
--automated=false Only show automated builds :只显示自动构建
--no-trunc=false Dont truncate output  :不截断输出
-s--stars=0 Only displays with at least x stars  :
最多返回25个结果
### 获取和推送镜像-拉取镜像
```sh
shell ￥docker pull [OPTIONS] NAME[:TAG] -a,--all-tags=false Download all tagged images in the repository :下载存储库中所有标记的图像

使用 --registry-mirror选项 1.修改： /etc/default/docker 2.添加： DOCKER_OPTS=“ --registry-mirror=http://MIRROR-ADDR” https://www.daocloud.io ```
```
### 获取和推送镜像-推送镜像
```sh
$docker push NAME[:TAG]
```

## Docker--构建镜像
### docker-构建镜像的好处：
保存对容器的修改，并再次使用
自定义镜像的能力
以软件的形式打包并分发服务及其运行环境
docker构建镜像的方式：
```sh
$docker commit 通过容器构建
$docker build 通过Dockerfile文件构建
docker-使用commit构建镜像
$docker commit [options] container [repository] [:tag]
-a--author=""  Author   
                  e.g.,"chj@qq.com"

-m--message=""  Commit message    : 记录镜像构建的信息

-p --pause=true  Pause container during commit   :指示commit命令可以不暂停正在执行的命令
```

### docker-使用Dockerfile构建镜像
```sh
1.创建Dockerfile
2.使用 $ docker build 命令

创建第一个Dockerfile
  #First Dockerfile
  FROM centos:7
  MAINTEINER dormancypress "chj@qq.com"
  RUN yum update
  RUN yum install -y nginx
  EXPOSE 80

  $docker build [OPTIONS] PATH | URL | -
  --force-rm=false
  --no-cache=false
  --pull=false
  -q,--quiet=false
  -rm=true
  -t,--tag=""  : 为了指定构建处镜像的名字
```