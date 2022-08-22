## 简介
[上文分析了useradd命令](https://blog.csdn.net/jakelylll/article/details/108172871)，了解了一个用户的创建过程。本文通过分析login程序的用户登录的过程，了解一个运行时用户到底是怎么产生的。

login程序位于util-linux包，源码是login-utils/login.c。

从终端进行登录的时候，首先是agettty这个程序会在界面上显示 login: 等待我们输入用户名。输入用户名后，agetty程序会调用login程序并把刚才输入的用户名传到login里。

## 源码分析

```c
struct login_context cxt = {
    .tty_mode = TTY_MODE,		/* tty chmod() */
    .pid = getpid(),		/* PID */
    .conv = { misc_conv, NULL }	/* PAM conversation function */
};

/**  ...省略初始化，参数解析等代码**/

init_loginpam(&cxt);

/* login -f, then the user has already been authenticated */
cxt.noauth = cxt.noauth && getuid() == 0 ? 1 : 0;

if (!cxt.noauth)
    loginpam_auth(&cxt);

loginpam_acct(&cxt);

if (!(cxt.pwd = get_passwd_entry(cxt.username, &pwdbuf, &_pwd))) {
    warnx(_("\nSession setup problem, abort."));
    syslog(LOG_ERR, _("Invalid user name \"%s\" in %s:%d. Abort."),
            cxt.username, __FUNCTION__, __LINE__);
    pam_end(cxt.pamh, PAM_SYSTEM_ERR);
    sleepexit(EXIT_FAILURE);
}
```
首先会调用pam模块进行用户身份认证，关于pam机制可在网上看相关详细资料。在init_loginpam中会根据是远程登录还是本地登录打开不同的pam服务，远程调用是remote，本地是login，这两个配置文件在/etc/pam.d/中。pam的会话函数在ctx这个变量里，用的是misc_conv，这是pam模块自带的一个默认函数，可以给pam传递用户的输入。

pam初始化完之后，调用loginpam_auth开始认证，会提示Password：提示用户输入密码，认证成功后还会调用loginpam_acct检查帐号。

```c
if (!(cxt.pwd = get_passwd_entry(cxt.username, &pwdbuf, &_pwd))) {
    warnx(_("\nSession setup problem, abort."));
    syslog(LOG_ERR, _("Invalid user name \"%s\" in %s:%d. Abort."),
            cxt.username, __FUNCTION__, __LINE__);
    pam_end(cxt.pamh, PAM_SYSTEM_ERR);
    sleepexit(EXIT_FAILURE);
}

pwd = cxt.pwd;
cxt.username = pwd->pw_name;

retcode = pwd->pw_uid ? initgroups(cxt.username, pwd->pw_gid) :	/* user */
                setgroups(0, NULL);			/* root */
/** 省略代码 **/

loginpam_session(&cxt);

/** 省略代码 **/

chown_tty(&cxt);

if (setgid(pwd->pw_gid) < 0 && pwd->pw_gid) {
    syslog(LOG_ALERT, _("setgid() failed"));
    exit(EXIT_FAILURE);
}

if (pwd->pw_shell == NULL || *pwd->pw_shell == '\0')
    pwd->pw_shell = _PATH_BSHELL;

init_environ(&cxt);	

setproctitle("login", cxt.username);

log_syslog(&cxt);

if (!cxt.quiet) {
    motd();

/**  省略代码  **/
fork_session(&cxt);
```
接下来是从/etc/passwd中读取用户配置信息，初始化群组，调用pam打开一个会话，然后将终端属主设为当前用户，设置组id，初始化环境变量，设置HOME, SHELL, PATH等变量，然后开始fork一个新进程。

```c
static void fork_session(struct login_context *cxt)
{
	struct sigaction sa, oldsa_hup, oldsa_term;

	...

	child_pid = fork();

    ...

	if (child_pid) {
		/*
		 * parent - wait for child to finish, then cleanup session
		 */
		close(0);
		close(1);
		close(2);
		sa.sa_handler = SIG_IGN;
		sigaction(SIGQUIT, &sa, NULL);
		sigaction(SIGINT, &sa, NULL);

		/* wait as long as any child is there */
		while (wait(NULL) == -1 && errno == EINTR) ;
		openlog("login", LOG_ODELAY, LOG_AUTHPRIV);

		pam_setcred(cxt->pamh, PAM_DELETE_CRED);
		pam_end(cxt->pamh, pam_close_session(cxt->pamh, 0));
		exit(EXIT_SUCCESS);
	}

	/*
	 * child
	 */

    ...

	/* start new session */
	setsid();

	/* make sure we have a controlling tty */
	open_tty(cxt->tty_path);

    ...
}
```
在fork_session里，fork成功之后，父进程进等待子进程结束，子进程结束之后，调用pam_close_session, pam_end，结束会放。

子进程创建一个新会话，由于是新进程，此进程也会成为会话首进程，组长进程。然后就是打开控制终端。

```c
/* discard permissions last so can't get killed and drop core */
if (setuid(pwd->pw_uid) < 0 && pwd->pw_uid) {
    syslog(LOG_ALERT, _("setuid() failed"));
    exit(EXIT_FAILURE);
}

/* wait until here to change directory! */
if (chdir(pwd->pw_dir) < 0) {
    warn(_("%s: change directory failed"), pwd->pw_dir);

    if (!getlogindefs_bool("DEFAULT_HOME", 1))
        exit(0);
    if (chdir("/"))
        exit(EXIT_FAILURE);
    pwd->pw_dir = "/";
    printf(_("Logging in with home = \"/\".\n"));
}

/* if the shell field has a space: treat it like a shell script */
if (strchr(pwd->pw_shell, ' ')) {
    buff = xmalloc(strlen(pwd->pw_shell) + 6);

    strcpy(buff, "exec ");
    strcat(buff, pwd->pw_shell);
    childArgv[childArgc++] = "/bin/sh";
    childArgv[childArgc++] = "-sh";
    childArgv[childArgc++] = "-c";
    childArgv[childArgc++] = buff;
} else {
    char tbuf[PATH_MAX + 2], *p;

    tbuf[0] = '-';
    xstrncpy(tbuf + 1, ((p = strrchr(pwd->pw_shell, '/')) ?
                p + 1 : pwd->pw_shell), sizeof(tbuf) - 1);

    childArgv[childArgc++] = pwd->pw_shell;
    childArgv[childArgc++] = xstrdup(tbuf);
}

childArgv[childArgc++] = NULL;

execvp(childArgv[0], childArgv + 1);
```
接下来的代码在子进程中执行，也就是新登录用户的进程。首先设置用户id，然后切换工作目录，如果工作目录切换失败，再根据配置文件判断是否要切换到根目录。

然后就开始执行用户的shell。如果shell是一个脚本，就用sh去执行，否则运行shell程序，后面用户的操作就由shell去代替执行。

