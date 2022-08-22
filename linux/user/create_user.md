## 简介

本文从用户的创建，使用，删除等一系列操作来分析Linux用户的运行原理，分析的程序基于CentOS7的源码。

如文中有错误，请指正，感谢！

主要通过下面程序来分析用户机制：
+ useradd：用户创建
+ login：用户登录产生一个用户
+ ls：用户权限检测
+ userdel：删除用户

## 创建用户——useradd

useradd的源码在shadow-utils包里。在看源码之前，先来看一下几个需要用到的文件：

### 相关配置文件

#### 1./etc/passwd

这个文件里主要保存用户的基本信息：

`gouhao:x:1000:1000::/home/gouhao:/bin/bash`

passwd中的每条记录以 : 分隔每个字段，每个字段的意义分别为：

`用户名:密码:用户id:用户组id:描述信息:用户主目录:用户shell`

其中密码以加密的形式保存在/etc/shadow文件中

#### 2./etc/shadow

这个文件里主要保存的用户密码相关信息：

`gouhao:$6$P1x3usYC$7d/xdWjNdfK.1YNGUR0x.cFcFJGk8hGJlb8fjW8CVOS7NuwYSg5pZgYg0iWI8qgIF82iPcwI9DGojMzc4WZCX1:18496:0:99999:7:::`

shadow里的每条记录也是以 : 分隔，每个字段意义如下：

`用户名:加密密码:上次修改密码时间:修改密码最小时间间隔:密码有效期:快过期前几天警告:密码过期后宽限时间:失效时间:保留`

其中，如果加密密码为空则表示没有密码；如果为 "!!"两个感叹号，则不能登录；修改密码最小间隔如果为0，表示随时可以修改密码；密码有效期如果为99999，则表示永久有效。

加密密码有三个字段，用 $ 分隔，每个字段意义如下：

`$加密类型$盐值$加密后的字符串`

默认的加密类型为6，表示sha512

#### 3./etc/group
这个文件主要保存组信息

`gouhao:x:1000:`

同样以冒号分隔每个字段，每个字段意义如下

`组名:组密码:组id:组列表`

#### 4./etc/login.def

这个文件里主要保存了一些用户相关的默认常量。

```
# 密码过期时间，长度相关
PASS_MAX_DAYS   99999 
PASS_MIN_DAYS   0
PASS_MIN_LEN    5
PASS_WARN_AGE   7

# 最大／最小各种id
UID_MIN                  1000
UID_MAX                 60000
SYS_UID_MIN               201
SYS_UID_MAX               999
GID_MIN                  1000
GID_MAX                 60000
SYS_GID_MIN               201
SYS_GID_MAX               999

# 创建用户时是否创建home目录
CREATE_HOME     yes

# 默认文件掩码
UMASK           077

USERGROUPS_ENAB yes

＃ 默认加密类型
ENCRYPT_METHOD SHA512

```

#### 5./etc/default/useradd：
这个文件中是一些创建用户时用到的默认常量，比如home路径，shell路径等。
```
# useradd defaults file
GROUP=100
HOME=/home  #默认用户主目录起始路径
INACTIVE=-1
EXPIRE=
SHELL=/bin/bash #默认shell
SKEL=/etc/skel
CREATE_MAIL_SPOOL=yes
```

### 程序分析

useradd的命令参数选项比较多，我们以 `useradd test` 这条命令来看源码，只提供用户名，其它都用默认值。

```c
process_root_flag ("-R", argc, argv);

prefix = process_prefix_flag("-P", argc, argv);
```
在程序一开始会先处理-R, -P，这两个选项。-R表示要进行chroot，切换要目录。－P表示目录前缀，这两个参数都对后面打开passwd, shadow, login.defs等这些文件有影响。

```c
sys_ngroups = sysconf (_SC_NGROUPS_MAX);
user_groups = (char **) xmalloc ((1 + sys_ngroups) * sizeof (char *));
/*
 * Initialize the list to be empty
 */
user_groups[0] = (char *) 0;


is_shadow_pwd = spw_file_present ();

get_defaults ();

process_flags (argc, argv);

```
get_defaults是从/etc/default/useradd中解析useradd命令的一些默认值。
process_flags(argc, argv)用来解析命令行参数，命令行参数有以下：

```c
static struct option long_options[] = {
			{"base-dir",       required_argument, NULL, 'b'},
			{"comment",        required_argument, NULL, 'c'},
			{"home-dir",       required_argument, NULL, 'd'},
			{"defaults",       no_argument,       NULL, 'D'},
			{"expiredate",     required_argument, NULL, 'e'},
			{"inactive",       required_argument, NULL, 'f'},
			{"gid",            required_argument, NULL, 'g'},
			{"groups",         required_argument, NULL, 'G'},
			{"help",           no_argument,       NULL, 'h'},
			{"skel",           required_argument, NULL, 'k'},
			{"key",            required_argument, NULL, 'K'},
			{"no-log-init",    no_argument,       NULL, 'l'},
			{"create-home",    no_argument,       NULL, 'm'},
			{"no-create-home", no_argument,       NULL, 'M'},
			{"no-user-group",  no_argument,       NULL, 'N'},
			{"non-unique",     no_argument,       NULL, 'o'},
			{"password",       required_argument, NULL, 'p'},
			{"system",         no_argument,       NULL, 'r'},
			{"root",           required_argument, NULL, 'R'},
			{"prefix",         required_argument, NULL, 'P'},
			{"shell",          required_argument, NULL, 's'},
			{"uid",            required_argument, NULL, 'u'},
			{"user-group",     no_argument,       NULL, 'U'},
#ifdef WITH_SELINUX
			{"selinux-user",   required_argument, NULL, 'Z'},
#endif				/* WITH_SELINUX */
			{NULL, 0, NULL, '\0'}
		};
```
后面会用到一些flag，这些flag的命令都是以这些参数的简写开头，到后面用到的时候再详细说明。

```c
if (Dflg) {
    if (gflg || bflg || fflg || eflg || sflg) {
        exit ((set_defaults () != 0) ? 1 : 0);
    }

    show_defaults ();
    exit (E_SUCCESS);
}

if (prefix_getpwnam (user_name) != NULL) { 
    fprintf (stderr, _("%s: user '%s' already exists\n"), Prog, user_name);
    fail_exit (E_NAME_IN_USE);
}


if (Uflg) {
    if (prefix_getgrnam (user_name) != NULL) {
        fprintf (stderr,
                    _("%s: group %s exists - if you want to add this user to that group, use -g.\n"),
                    Prog, user_name);
        fail_exit (E_NAME_IN_USE);
    }
}
```
如果有Dflag，则只修改/etc/default/useradd文件中的相关内容。接下来根据用户名获取passwd中的内容，如果用户已经存在，则报错。如果有Uflag则指定了附加组，如果附加组和要新建的用户名相同则报错。

```c
open_files ();

if (!oflg) {
    if (!uflg) {
        if (find_new_uid (rflg, &user_id, NULL) < 0) {
            fprintf (stderr, _("%s: can't create user\n"), Prog);
            fail_exit (E_UID_IN_USE);
        }
    } else {
        if (prefix_getpwuid (user_id) != NULL) {
            fprintf (stderr,
                        _("%s: UID %lu is not unique\n"),
                        Prog, (unsigned long) user_id);
            fail_exit (E_UID_IN_USE);
        }
    }
}
```
在open_files()里，打开了passwd, group两个文件，并且都创建了相应的锁文件，保护并发的情况。

oflag表示id是否唯一， ufl要ag表示用户自定义的uid。如果用户没有指定uid，则通过find_new_uid找一个合适的id。否则，如果用户指定了id，则判断这个id有没有被使用，如果已经使用，则报错。

find_new_uid的函数比较长，就不贴了。find_new_uid有三个参数，第一个表示是否是系统用户，第二个是找到的uid，第三个是想要的uid。find_new_uid会通过/etc/login.defs中定义的最小／最大的用户id值锁定一个范围。然后遍历passwd文件，在这个范围中找一个passwd文件中没有用过的id返回。

```c
open_shadow ();

if (Uflg) {
    if (find_new_gid (rflg, &user_gid, &user_id) < 0) {
        fprintf (stderr,
                    _("%s: can't create group\n"),
                    Prog);
        fail_exit (4);
    }
    grp_add ();
}
```
接下来是打开shadow文件，然后找一个没有用过的组id, 并在group文件中写一条记录。

```c
usr_update ();

close_files ();
```
接下来两行代码，user_update会根据我们刚写找到的用户id，组id和其他默认参数，生成passwd, shadow记录的数据结构。close_files会在关闭passwd, shadow这些文件前把生成的数据结构写到相应文件中。user_update会调用new_pwent, new_spent生成passwd和spwd结构。

```c
static void new_pwent (struct passwd *pwent)
{
	memzero (pwent, sizeof *pwent);
	pwent->pw_name = (char *) user_name;
	if (is_shadow_pwd) {
		pwent->pw_passwd = (char *) SHADOW_PASSWD_STRING;
	} else {
		pwent->pw_passwd = (char *) user_pass;
	}

	pwent->pw_uid = user_id;
	pwent->pw_gid = user_gid;
	pwent->pw_gecos = (char *) user_comment;
	pwent->pw_dir = (char *) user_home;
	pwent->pw_shell = (char *) user_shell;
}
```
new_pwent生成passwd结构，其中user_name, user_id, user_gid是用户名，用户id， 用户组id，在上文中已经定义或生成。pw_passwd是x，因为密码保存在shadow文件中; user_home我们没有指定，所以是默认值/etc/default/useradd文件中的HOME的值加上用户名，在本例中是/home/test；user_shell也是useradd文件中的默认值：/bin/sh。

```c
static void new_spent (struct spwd *spent)
{
	memzero (spent, sizeof *spent);
	spent->sp_namp = (char *) user_name;
	spent->sp_pwdp = (char *) user_pass;
	spent->sp_lstchg = (long) gettime () / SCALE;
	if (0 == spent->sp_lstchg) {
		/* Better disable aging than requiring a password change */
		spent->sp_lstchg = -1;
	}
	if (!rflg) {
		spent->sp_min = scale_age (getdef_num ("PASS_MIN_DAYS", -1));
		spent->sp_max = scale_age (getdef_num ("PASS_MAX_DAYS", -1));
		spent->sp_warn = scale_age (getdef_num ("PASS_WARN_AGE", -1));
		spent->sp_inact = scale_age (def_inactive);
		spent->sp_expire = scale_age (user_expire);
	} else {
		spent->sp_min = -1;
		spent->sp_max = -1;
		spent->sp_warn = -1;
		spent->sp_inact = -1;
		spent->sp_expire = -1;
	}
	spent->sp_flag = SHADOW_SP_FLAG_UNSET;
}
```
new_spent生成spwd结构。根据是否为系统用户设置的值不同。user_pass在没有指定的时候是两个感叹号"!!"，此时用户不能登录。普通用户的其他属性，像修改时间，有效期等都是从/etc/login.defs中获取的默认值。

```c
if (mflg) {
    create_home ();
    if (home_added) {
        copy_tree (def_template, prefix_user_home, false, true,
                    (uid_t)-1, user_id, (gid_t)-1, user_gid);
    } else {
        fprintf (stderr,
                    _("%s: warning: the home directory already exists.\n"
                    "Not copying any file from skel directory into it.\n"),
                    Prog);
    }

}

if (!rflg) {
    create_mail ();
}

```
最后通过create_home创建用户主目录，并将owner改为新用户。如果是普通用户还会创建邮箱目录。

至此，一个新用户创建完成。
