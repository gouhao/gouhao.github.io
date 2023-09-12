# OBS 简单用法

Open Build Service (简称 OBS) 是 openSUSE 开源维护的源码构建系统，可完成常见 Linux 发行版（Debian, Ubuntu, CentOS, Fedora, SUSE等）的安装包构建。此处的安装包指 `Debian` 系的 `.deb` 包和 `Red Hat` 系的 `.rpm` 包。


OBS服务器提供网页端接口及后台命令接口。后台使用是通过osc命令行工具。

OBS后端在编译的时候会创建相互独立的沙盒来编译，沙盒隔离于宿主机。根据描述文件(RPM系统中是.spec文件)和 OBS 工程配置，在编译时会自动下载安装依赖包，构建沙盒环境。普通使用用户无法指定沙盒类型，沙盒类型一般默认为 chroot 环境，也可以配置为KVM或XEN虚拟机环境，需要管理员后台配置。

OBS 根据描述文件(RPM系统中是.spec文件)执行编译，编译成功则将该工程包中的文件存放到OBS后台，可通过OBS的download页面(download repository)查看。

OBS 使用工程(project)管理包(package)，一个工程包含多个包。工程中可以创建其他的工程(子工程)，他们与父工程隔离开，可以进行单独的配置。每个工程的名字通过冒号(:)区分开，作为用户，通常在 home 工程下编译包。OBS中名为 home:xxxx 的工程即为 home 工程。 home 工程作为用户的个人工作区，可以自定义修改。

## osc 安装

OBS 可以在网页操作，但是功能有限，使用命令接口 `osc` 命令操作会比较方便。

~~行业版 OBS 地址：https://10.7.10.150/~~(因为自编译整改,此服务器已弃用)
行业版 1xxx 版本维护 OBS 地址: https://10.7.10.216/
行业版 0xxx 版本开发 OBS 地址： https://10.7.10.160
欧拉版 OBS 地址：https://10.7.10.204/

**使用osc 命令前请先在OBS 网页上完成用户注册,打开网页后,点击右上角 `Sign Up`注册即可**

不同的操作系统安装 osc 会有不同的差异.

### UOS 服务器行业版系统安装 osc

1. 配置repo源

    ```bash
    cat >/tmp/osc.conf <<EOF
    [main]
    keepcache=1
    debuglevel=2
    reposdir=/dev/null
    logfile=/var/log/yum.log
    retries=20
    obsoletes=1
    gpgcheck=0

    [openSUSE:Tools]
    name=openSUSE:Tools
    baseurl=http://download.opensuse.org/repositories/openSUSE:/Tools/CentOS_8/
    priority=1

    [BaseOS]
    name=BaseOS
    baseurl=http://10.7.10.100/internet-server/server-enterprise-c/kongzi/BaseOS/x86_64/
    priority=1

    [AppStream]
    name=AppStream
    baseurl=http://10.7.10.100/internet-server/server-enterprise-c/kongzi/AppStream/x86_64/
    priority=1

    [epel]
    name=epel
    baseurl=http://10.7.10.100/centos/epel-mirror/Everything/x86_64/
    priority=99
    EOF

    ```

2. 执行安装命令

    ```bash
    dnf -c /tmp/osc.conf install wget curl osc obs-build rpm-build -y
    ```

### UOS 服务器欧拉系统安装 osc

1. 配置repo源

    ```bash
    dnf config-manager --add-repo http://10.7.10.204:8080/UOS_20:/Euler:/Tools/standard_aarch64/
    ```

2. 通过dnf 在线安装 osc, 安装之前，请使用期激活或者配置 everything 源， **此处执行需要 root 权限**

    ```
    dnf -c install wget curl osc build rpm-build -y
    ```

### UOS桌面版系统安装 osc

1. 从 opensuse 提供的网站上下载 osc 和 build

    ```bash
    wget --execute robots=off -nc -nd -r -l1 -A 'osc*.deb' https://download.opensuse.org/repositories/openSUSE:/Tools/Debian_10/all/
    wget --execute robots=off -nc -nd -r -l1 -A 'obs-build*.deb' https://download.opensuse.org/repositories/openSUSE:/Tools/Debian_10/all/
    ```

2. 通过apt 安装 下载下来的 osc 和 obs-build deb 包和一些依赖包

    ```bash
    sudo apt install  ./osc*.deb ./obs-build*.deb bsdtar build-essential python3-dev python-dev libssl-dev swig python3-pip curl -y
    sudo pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple  m2crypto
    ```

## OSC 配置

安装 osc 后并不能直接使用,还需要进一步配置一下
* 配置 /etc/hosts

因为 osc 使用时需要域名才能访问 OBS 服务器，所以需要在 /etc/hosts 中增加本地映射.

**此处执行需要 root 权限**
```bash
sudo sed -i "/uos-build/d" /etc/hosts
sudo sed -i "/euleros-obs/d" /etc/hosts
sudo sed -i "/gitlabxa/d" /etc/hosts

##此处使用新的OBS
sudo echo "10.7.10.216 uos-build2.uniontech.com uos-build2" >> /etc/hosts
sudo echo "10.7.10.204 euleros-obs" >> /etc/hosts
## 添加 gitlabxa 主机的映射
sudo echo "10.7.0.61  gitlabxa.uniontech.com" >> /etc/hosts
## 新增 C7版本 OBS
sudo echo "10.7.10.160  c7-obs.uniontech.com c7-obs" >> /etc/hosts
```

* 配置osc用户组中的用户 osc build 免 sudo 编译

**此处执行需要 root 权限**
```bash
## 新建 osc 群组
sudo getent group osc > /dev/null || sudo groupadd osc
```

*  创建sudoers配置文件/etc/sudoers.d/osc
**此处执行需要 root 权限**
```bash
sudo cat >/etc/sudoers.d/osc<<EOF
# sudoers file "/etc/sudoers.d/osc" for the osc group
Cmnd_Alias OSC_CMD = /usr/bin/osc, /usr/bin/build
%osc ALL = (ALL) NOPASSWD:OSC_CMD
EOF

```

* 下载 mock 配置文件到系统中
因为一台 OBS 服务器后台只能支持一种 mock 配置，所以，如果使用不同的 OBS (216 或者 160), osc 客户端也需要同步配置不同的mock 脚本
**此处执行需要 root 权限**
```bash
## 适用与 10.7.10.216 的 mock  配置
sudo curl https://gitlabxa.uniontech.com/ut000913/obs-config/-/raw/master/obs_build/build-recipe-mock-2.sh -o /usr/lib/build/build-recipe-mock

## 适用与 10.7.10.160 的 mock 配置
sudo curl https://gitlabxa.uniontech.com/ut000913/obs-manger/-/raw/master/obs_server/build-recipe-mock-c7.sh -o /usr/lib/build/build-recipe-mock
```

### osc 用户配置
**此小章节配置时用户可以是root用户,也可以是普通用户,建议使用普通用户**

* 下载配置文件到用户目录下

* 配置 osc 用户名密码

如果没有用户名或者密码请先注册

~~行业版 OBS 地址：https://10.7.10.150/~~(因为自编译整改,此服务器已弃用)
行业版 OBS 地址：https://10.7.10.216/

欧拉版 OBS 地址：https://10.7.10.204/

创建 ~/.config/osc/oscrc 文件

```bash
vim  ~/.config/osc/oscrc
```
添加以下内容，用于创建命令别名，只有osc用户组用户才能使用， 文件中的 `username` 和 `password` 需要更改为自己在网页上申请的账号和密码
```bash
[general]
sslcertck=0
apiurl = https://c7-obs
no_verify = 1

[https://c7-obs]
aliases = build2
sslcertck=0
user = username
pass = password

[https://uos-build2]
aliases = build2
sslcertck=0
user = username
pass = password

[https://euleros-obs]
sslcertck=0
## osc 命令可以同时连接不同的 obs服务器，可以用别名区分
aliases = euler
## 欧拉版的 OBS 如果不需要使用可以不用注册，此处的 username 和 password 就可以不用改了
user = username
pass = password
```

* 为不同的服务器配置别名

```bash
echo "alias c7osc='osc -A https://c7-obs'" >> ~/.bashrc
echo "alias eosc='osc -A https://euleros-obs'" >> ~/.bashrc
echo "alias cosc='osc -A https://uos-build2'" >> ~/.bashrc
source ~/.bashrc
```

### 验证 osc

执行如下命令,如果列出了 https://10.7.10.216 服务器上所有的 OBS 工程，说明对于行业版的 osc 配置已完成.

```bash
cosc ls
```
执行如下命令,如果列出了 https://10.7.10.204 服务器上所有的 OBS 工程，说明对于行业版的 osc 配置已完成.

```bash
eosc ls
```

## osc build 使用方式

* 添加用户到 osc 组， 免 sudo 编译


如果是 root 用户 osc build 编译，可以免去如下步骤，如果是普通用户，请让具有 root 权限的用户执行如下命令，添加到 osc 组中，免 sudo 编译。
不推荐使用 root 用户编译。

```bash
sudo getent passwd $USER > /dev/null && sudo usermod -a -G osc $USER
```

此处以行业版上的 kernel 包举例, 欧拉版使用时注意替换 `cosc` 为 `eosc`

* branch 操作
此操作可理解为 gitlab 的 fork 。

登录 OBS , 点击右上角 搜索 kernel，点击 kernel 所在的工程，然后点击包所在的页面上的 `Branch package`
![](https://gitlabxa.uniontech.com/ut000913/docs/uploads/89cce902e24a4c6bb163aefdd4169aff/image.png)
点击确认后，kernel 包就到自己的 home 工程下，例如 `home:guoqinglan:branches:UOS_20:EnterpriseC:BaseOS/kernel`。

* checkout 操作
此操作可理解为 gitlab fork 后 git clone 步骤。

```bash
cosc checkout  home:guoqinglan:branches:UOS_20:EnterpriseC:BaseOS/kernel
```

* 拉取 service 文件


因为 obs 上的包都是 gitlab 管理源码，然后再经过 obs 特性通过 `_service` 文件拉去代码,
更新 `_service` 文件拉去代码到本地后， 需要把 _service 文件删除，并且需要重命名一下，去掉_service* 前缀。

```bash
## 注意进入到 kernel 所在的二级目录
cd home:guoqinglan:branches:UOS_20:EnterpriseC:BaseOS/kernel
## 此操作可理解为 git fetch 步骤。
cosc up -S

rm -f _service && rm -f *obsinfo && rm -f *obscpio && ls |awk -F ":" '{print "mv "$0" "$NF""}' | bash
```

* 修改代码或spec

```bash
# vim ...
# vim kernel.spec
```

* 修改代码完成后推送 obs 编译

```bash
cosc addremove *  # 类似git add -A 步骤
cosc up
cosc commit -m "提交信息，按自己提交信息填写" # 类似 git commit
```

* 也可以再次修改

```bash
cosc up  # 更新网页修改到本地

# vim ***
# vim kernel.spec
```

* 再此修改后，推送 obs 编译

```bash
cosc addremove *  # 类似git add -A 步骤
cosc  commit -m "提交信息，按自己提交信息填写" # 类似 git commit
```
* 也可以本地编译

注意osc 本地编译,不支持交叉编译, 也就是 x86_64 硬件架构只支持编译 x86_64 或者 i686 架构的包, aarch64 硬件架构只支持编译 aarch64 架构的包, x86_64硬件架构不支持编译 aarch64 架构.
```bash
## -j64 用来传递给 make 进行并行编译, 请按自己机器实际CPU情况赋值
## --root 后接本地chroot 目录位置,不指定此参数默认位置在 /var/tmp 下,建议指定
osc build repo_x86_64 x86_64 -j64  --trust-all-projects --root=/home/guoqinglan/kernel_root_1 kernel.spec
```