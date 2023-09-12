# kobject_uevent
源码基于5.10

## kobject_uevent
```c

struct kobj_uevent_env {
	char *argv[3];
	// UEVENT_NUM_ENVP 64, 表示最大允许64个key-value
	// envp里每个指针都会指向buf里key-value的开头
	char *envp[UEVENT_NUM_ENVP];
	// envp里数据的长度
	int envp_idx;
	// UEVENT_BUFFER_SIZE 2048
	char buf[UEVENT_BUFFER_SIZE];
	// buf里数据的长度
	int buflen;
};

int kobject_uevent(struct kobject *kobj, enum kobject_action action)
{
	return kobject_uevent_env(kobj, action, NULL);
}

int kobject_uevent_env(struct kobject *kobj, enum kobject_action action,
		       char *envp_ext[])
{
	struct kobj_uevent_env *env;
	// 动作
	const char *action_string = kobject_actions[action];
	const char *devpath = NULL;
	const char *subsystem;
	struct kobject *top_kobj;
	struct kset *kset;
	const struct kset_uevent_ops *uevent_ops;
	int i = 0;
	int retval = 0;

	// 标志remove完成, 不管它的结果是否完成, 对有些子系统来说不希望重新触发event的自动清理
	if (action == KOBJ_REMOVE)
		kobj->state_remove_uevent_sent = 1;

	pr_debug("kobject: '%s' (%p): %s\n",
		 kobject_name(kobj), kobj, __func__);

	// 找到顶层的kset
	top_kobj = kobj;
	while (!top_kobj->kset && top_kobj->parent)
		top_kobj = top_kobj->parent;

	// 没有kset的不能发uevent
	if (!top_kobj->kset) {
		pr_debug("kobject: '%s' (%p): %s: attempted to send uevent "
			 "without kset!\n", kobject_name(kobj), kobj,
			 __func__);
		return -EINVAL;
	}

	// 顶层对象及操作表
	kset = top_kobj->kset;
	uevent_ops = kset->uevent_ops;

	// uevent_suppress: 禁止uevent
	if (kobj->uevent_suppress) {
		pr_debug("kobject: '%s' (%p): %s: uevent_suppress "
				 "caused the event to drop!\n",
				 kobject_name(kobj), kobj, __func__);
		return 0;
	}
	// 调用过滤器, 判断是否要过滤
	if (uevent_ops && uevent_ops->filter)
		if (!uevent_ops->filter(kset, kobj)) {
			pr_debug("kobject: '%s' (%p): %s: filter function "
				 "caused the event to drop!\n",
				 kobject_name(kobj), kobj, __func__);
			return 0;
		}

	// 子系统名称
	if (uevent_ops && uevent_ops->name)
		subsystem = uevent_ops->name(kset, kobj);
	else
		subsystem = kobject_name(&kset->kobj);
	// 丢弃没有子系统名称的uevent
	if (!subsystem) {
		pr_debug("kobject: '%s' (%p): %s: unset subsystem caused the "
			 "event to drop!\n", kobject_name(kobj), kobj,
			 __func__);
		return 0;
	}

	// 环境信息
	env = kzalloc(sizeof(struct kobj_uevent_env), GFP_KERNEL);
	if (!env)
		return -ENOMEM;

	// 获取kobj的绝对路径
	devpath = kobject_get_path(kobj, GFP_KERNEL);
	if (!devpath) {
		retval = -ENOENT;
		goto exit;
	}

	// 添加通用的3个键值
	retval = add_uevent_var(env, "ACTION=%s", action_string);
	if (retval)
		goto exit;
	retval = add_uevent_var(env, "DEVPATH=%s", devpath);
	if (retval)
		goto exit;
	retval = add_uevent_var(env, "SUBSYSTEM=%s", subsystem);
	if (retval)
		goto exit;

	// 有扩展的key, 则加之
	if (envp_ext) {
		for (i = 0; envp_ext[i]; i++) {
			retval = add_uevent_var(env, "%s", envp_ext[i]);
			if (retval)
				goto exit;
		}
	}

	// 有自定义的uevent, 则调用之
	if (uevent_ops && uevent_ops->uevent) {
		retval = uevent_ops->uevent(kset, kobj, env);
		if (retval) {
			pr_debug("kobject: '%s' (%p): %s: uevent() returned "
				 "%d\n", kobject_name(kobj), kobj,
				 __func__, retval);
			goto exit;
		}
	}

	switch (action) {
	case KOBJ_ADD:
		// 标记添加已经发送
		kobj->state_add_uevent_sent = 1;
		break;

	case KOBJ_UNBIND:
		zap_modalias_env(env);
		break;

	default:
		break;
	}

	mutex_lock(&uevent_sock_mutex);
	// 添加序号
	retval = add_uevent_var(env, "SEQNUM=%llu", ++uevent_seqnum);
	if (retval) {
		mutex_unlock(&uevent_sock_mutex);
		goto exit;
	}
	// 广播事件
	retval = kobject_uevent_net_broadcast(kobj, env, action_string,
					      devpath);
	mutex_unlock(&uevent_sock_mutex);

#ifdef CONFIG_UEVENT_HELPER
	/* call uevent_helper, usually only enabled during early boot */
	if (uevent_helper[0] && !kobj_usermode_filter(kobj)) {
		struct subprocess_info *info;

		retval = add_uevent_var(env, "HOME=/");
		if (retval)
			goto exit;
		retval = add_uevent_var(env,
					"PATH=/sbin:/bin:/usr/sbin:/usr/bin");
		if (retval)
			goto exit;
		retval = init_uevent_argv(env, subsystem);
		if (retval)
			goto exit;

		retval = -ENOMEM;
		info = call_usermodehelper_setup(env->argv[0], env->argv,
						 env->envp, GFP_KERNEL,
						 NULL, cleanup_uevent_env, env);
		if (info) {
			retval = call_usermodehelper_exec(info, UMH_NO_WAIT);
			env = NULL;	/* freed by cleanup_uevent_env */
		}
	}
#endif

exit:
	kfree(devpath);
	kfree(env);
	return retval;
}

int add_uevent_var(struct kobj_uevent_env *env, const char *format, ...)
{
	va_list args;
	int len;

	// env超过了边界
	if (env->envp_idx >= ARRAY_SIZE(env->envp)) {
		WARN(1, KERN_ERR "add_uevent_var: too many keys\n");
		return -ENOMEM;
	}

	// 把key-value到buflen开始的地方
	va_start(args, format);
	len = vsnprintf(&env->buf[env->buflen],
			sizeof(env->buf) - env->buflen,
			format, args);
	va_end(args);


	// 返回值大于长度,表示空间不够, 值会被截断
	if (len >= (sizeof(env->buf) - env->buflen)) {
		WARN(1, KERN_ERR "add_uevent_var: buffer size too small\n");
		return -ENOMEM;
	}

	// evnp指向kv的开头
	env->envp[env->envp_idx++] = &env->buf[env->buflen];
	// 长度 + 1, 是因为kv后面有/0
	env->buflen += len + 1;
	return 0;
}

static int kobject_uevent_net_broadcast(struct kobject *kobj,
					struct kobj_uevent_env *env,
					const char *action_string,
					const char *devpath)
{
	int ret = 0;

#ifdef CONFIG_NET
	const struct kobj_ns_type_operations *ops;
	const struct net *net = NULL;

	// 获取ops
	ops = kobj_ns_ops(kobj);
	if (!ops && kobj->kset) {
		struct kobject *ksobj = &kobj->kset->kobj;

		if (ksobj->parent != NULL)
			ops = kobj_ns_ops(ksobj->parent);
	}

	// 获取net ops
	if (ops && ops->netlink_ns && kobj->ktype->namespace)
		if (ops->type == KOBJ_NS_TYPE_NET)
			net = kobj->ktype->namespace(kobj);

	// 广播事件, 这2个函数差不多
	if (!net)
		ret = uevent_net_broadcast_untagged(env, action_string,
						    devpath);
	else
		ret = uevent_net_broadcast_tagged(net->uevent_sock->sk, env,
						  action_string, devpath);
#endif

	return ret;
}

const struct kobj_ns_type_operations *kobj_ns_ops(struct kobject *kobj)
{
	return kobj_child_ns_ops(kobj->parent);
}

const struct kobj_ns_type_operations *kobj_child_ns_ops(struct kobject *parent)
{
	const struct kobj_ns_type_operations *ops = NULL;

	// 有子节点则获取ops
	if (parent && parent->ktype && parent->ktype->child_ns_type)
		ops = parent->ktype->child_ns_type(parent);

	return ops;
}

static int uevent_net_broadcast_tagged(struct sock *usk,
				       struct kobj_uevent_env *env,
				       const char *action_string,
				       const char *devpath)
{
	struct user_namespace *owning_user_ns = sock_net(usk)->user_ns;
	struct sk_buff *skb = NULL;
	int ret = 0;

	// 分配skb, 并且把env的数据填充进去
	skb = alloc_uevent_skb(env, action_string, devpath);
	if (!skb)
		return -ENOMEM;

	// 用户证书相关修复
	if (owning_user_ns != &init_user_ns) {
		struct netlink_skb_parms *parms = &NETLINK_CB(skb);
		kuid_t root_uid;
		kgid_t root_gid;

		/* fix uid */
		root_uid = make_kuid(owning_user_ns, 0);
		if (uid_valid(root_uid))
			parms->creds.uid = root_uid;

		/* fix gid */
		root_gid = make_kgid(owning_user_ns, 0);
		if (gid_valid(root_gid))
			parms->creds.gid = root_gid;
	}

	// 通过netlink广播事件
	ret = netlink_broadcast(usk, skb, 0, 1, GFP_KERNEL);

	if (ret == -ENOBUFS || ret == -ESRCH)
		ret = 0;

	return ret;
}
```