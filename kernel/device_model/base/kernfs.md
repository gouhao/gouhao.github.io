# kernfs

## 结构体
```c
/* type-specific structures for kernfs_node union members */
struct kernfs_elem_dir {
	unsigned long		subdirs;
	/* children rbtree starts here and goes through kn->rb */
	struct rb_root		children;

	/*
	 * The kernfs hierarchy this directory belongs to.  This fits
	 * better directly in kernfs_node but is here to save space.
	 */
	struct kernfs_root	*root;
};

struct kernfs_elem_symlink {
	struct kernfs_node	*target_kn;
};

struct kernfs_elem_attr {
	const struct kernfs_ops	*ops;
	struct kernfs_open_node	*open;
	loff_t			size;
	struct kernfs_node	*notify_next;	/* for kernfs_notify() */
};

struct kernfs_node {
	atomic_t		count; // 引用计数
	atomic_t		active; // 活跃计数
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
#endif
	/*
	 * Use kernfs_get_parent() and kernfs_name/path() instead of
	 * accessing the following two fields directly.  If the node is
	 * never moved to a different parent, it is safe to access the
	 * parent directly.
	 */
	struct kernfs_node	*parent;
	const char		*name;

	struct rb_node		rb;

	const void		*ns;	/* namespace tag */
	unsigned int		hash;	/* ns + name hash */
	union {
		struct kernfs_elem_dir		dir;
		struct kernfs_elem_symlink	symlink;
		struct kernfs_elem_attr		attr;
	};

	void			*priv;

	/*
	 * 64bit unique ID.  On 64bit ino setups, id is the ino.  On 32bit,
	 * the low 32bits are ino and upper generation.
	 */
	u64			id;

	unsigned short		flags;
	umode_t			mode;
	struct kernfs_iattrs	*iattr;
};
```

## kernfs_create_dir_ns
```c
struct kernfs_node *kernfs_create_dir_ns(struct kernfs_node *parent,
					 const char *name, umode_t mode,
					 kuid_t uid, kgid_t gid,
					 void *priv, const void *ns)
{
	struct kernfs_node *kn;
	int rc;

	// 分配一个node
	kn = kernfs_new_node(parent, name, mode | S_IFDIR,
			     uid, gid, KERNFS_DIR);
	if (!kn)
		return ERR_PTR(-ENOMEM);

	// 根结点就是父目录的根结点
	kn->dir.root = parent->dir.root;
	kn->ns = ns;
	kn->priv = priv;

	// 添加到父结点
	rc = kernfs_add_one(kn);
	if (!rc)
		return kn;

	kernfs_put(kn);
	return ERR_PTR(rc);
}

struct kernfs_node *kernfs_new_node(struct kernfs_node *parent,
				    const char *name, umode_t mode,
				    kuid_t uid, kgid_t gid,
				    unsigned flags)
{
	struct kernfs_node *kn;

	// 分配一个node对象
	kn = __kernfs_new_node(kernfs_root(parent), parent,
			       name, mode, uid, gid, flags);
	if (kn) {
		// 增加父结点引用计数
		kernfs_get(parent);
		kn->parent = parent;
	}
	return kn;
}

static struct kernfs_node *__kernfs_new_node(struct kernfs_root *root,
					     struct kernfs_node *parent,
					     const char *name, umode_t mode,
					     kuid_t uid, kgid_t gid,
					     unsigned flags)
{
	struct kernfs_node *kn;
	u32 id_highbits;
	int ret;

	// 复制字符串
	name = kstrdup_const(name, GFP_KERNEL);
	if (!name)
		return NULL;

	// 分配对象
	kn = kmem_cache_zalloc(kernfs_node_cache, GFP_KERNEL);
	if (!kn)
		goto err_out1;

	// 分配，初始化ino_idr
	idr_preload(GFP_KERNEL);
	spin_lock(&kernfs_idr_lock);
	
	ret = idr_alloc_cyclic(&root->ino_idr, kn, 1, 0, GFP_ATOMIC);
	// todo: 这个low, hight范围是干嘛的
	if (ret >= 0 && ret < root->last_id_lowbits)
		root->id_highbits++;
	id_highbits = root->id_highbits;
	root->last_id_lowbits = ret;
	spin_unlock(&kernfs_idr_lock);
	idr_preload_end();
	if (ret < 0)
		goto err_out2;

	// todo: id为什么这么存储
	kn->id = (u64)id_highbits << 32 | ret;

	// 引用为1
	atomic_set(&kn->count, 1);
	// 设置不活跃状态
	atomic_set(&kn->active, KN_DEACTIVATED_BIAS);
	// 重置node
	RB_CLEAR_NODE(&kn->rb);

	kn->name = name;
	kn->mode = mode;
	kn->flags = flags;

	// 如果uid, gid不是根id，则重新设置相关属性
	if (!uid_eq(uid, GLOBAL_ROOT_UID) || !gid_eq(gid, GLOBAL_ROOT_GID)) {
		struct iattr iattr = {
			.ia_valid = ATTR_UID | ATTR_GID,
			.ia_uid = uid,
			.ia_gid = gid,
		};

		// 设置kn里的attr对象，如果没有则分配
		ret = __kernfs_setattr(kn, &iattr);
		if (ret < 0)
			goto err_out3;
	}

	// 调用kernfs_init_security hook
	if (parent) {
		ret = security_kernfs_init_security(parent, kn);
		if (ret)
			goto err_out3;
	}

	return kn;

 err_out3:
	idr_remove(&root->ino_idr, (u32)kernfs_ino(kn));
 err_out2:
	kmem_cache_free(kernfs_node_cache, kn);
 err_out1:
	kfree_const(name);
	return NULL;
}

int kernfs_add_one(struct kernfs_node *kn)
{
	struct kernfs_node *parent = kn->parent;
	struct kernfs_iattrs *ps_iattr;
	bool has_ns;
	int ret;

	mutex_lock(&kernfs_mutex);

	ret = -EINVAL;
	// 判断有无KERNFS_NS标志
	has_ns = kernfs_ns_enabled(parent);
	if (WARN(has_ns != (bool)kn->ns, KERN_WARNING "kernfs: ns %s in '%s' for '%s'\n",
		 has_ns ? "required" : "invalid", parent->name, kn->name))
		goto out_unlock;

	// 父结点不是目录，直接退出
	if (kernfs_type(parent) != KERNFS_DIR)
		goto out_unlock;

	ret = -ENOENT;
	// 父结点是空目录，退出
	if (parent->flags & KERNFS_EMPTY_DIR)
		goto out_unlock;

	// 父结点不活跃，退出
	if ((parent->flags & KERNFS_ACTIVATED) && !kernfs_active(parent))
		goto out_unlock;

	// 计算文件名哈希值
	kn->hash = kernfs_name_hash(kn->name, kn->ns);

	// 插入到父结点的红黑树里
	ret = kernfs_link_sibling(kn);
	if (ret)
		goto out_unlock;

	// 更新父结点相关时间戳
	ps_iattr = parent->iattr;
	if (ps_iattr) {
		ktime_get_real_ts64(&ps_iattr->ia_ctime);
		ps_iattr->ia_mtime = ps_iattr->ia_ctime;
	}

	mutex_unlock(&kernfs_mutex);

	// 如果父结点没有不活跃标志，则激活kn
	if (!(kernfs_root(kn)->flags & KERNFS_ROOT_CREATE_DEACTIVATED))
		// 设置 KERNFS_ACTIVATED 标志，并递增active计数
		kernfs_activate(kn);
	return 0;

out_unlock:
	mutex_unlock(&kernfs_mutex);
	return ret;
}
```

## __kernfs_create_file
```c
struct kernfs_node *__kernfs_create_file(struct kernfs_node *parent,
					 const char *name,
					 umode_t mode, kuid_t uid, kgid_t gid,
					 loff_t size,
					 const struct kernfs_ops *ops,
					 void *priv, const void *ns,
					 struct lock_class_key *key)
{
	struct kernfs_node *kn;
	unsigned flags;
	int rc;

	flags = KERNFS_FILE;

	// 分配一个kn
	kn = kernfs_new_node(parent, name, (mode & S_IALLUGO) | S_IFREG,
			     uid, gid, flags);
	if (!kn)
		return ERR_PTR(-ENOMEM);

	// 设置各种属性
	kn->attr.ops = ops;
	kn->attr.size = size;
	kn->ns = ns;
	kn->priv = priv;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	if (key) {
		lockdep_init_map(&kn->dep_map, "kn->active", key, 0);
		kn->flags |= KERNFS_LOCKDEP;
	}
#endif

	// 根据ops设置不同属性
	if (ops->seq_show)
		kn->flags |= KERNFS_HAS_SEQ_SHOW;
	if (ops->mmap)
		kn->flags |= KERNFS_HAS_MMAP;
	if (ops->release)
		kn->flags |= KERNFS_HAS_RELEASE;

	// 添加到父结点
	rc = kernfs_add_one(kn);
	if (rc) {
		kernfs_put(kn);
		return ERR_PTR(rc);
	}
	return kn;
}
```

## kernfs_remove_by_name
```c
static inline int kernfs_remove_by_name(struct kernfs_node *parent,
					const char *name)
{
	return kernfs_remove_by_name_ns(parent, name, NULL);
}

int kernfs_remove_by_name_ns(struct kernfs_node *parent, const char *name,
			     const void *ns)
{
	struct kernfs_node *kn;

	// 必须要有父目录
	if (!parent) {
		WARN(1, KERN_WARNING "kernfs: can not remove '%s', no directory\n",
			name);
		return -ENOENT;
	}

	mutex_lock(&kernfs_mutex);

	// 找到名字对应的kn
	kn = kernfs_find_ns(parent, name, ns);

	// 如果找到了就移除之
	if (kn)
		__kernfs_remove(kn);

	mutex_unlock(&kernfs_mutex);

	if (kn)
		return 0;
	else
		return -ENOENT;
}

static struct kernfs_node *kernfs_find_ns(struct kernfs_node *parent,
					  const unsigned char *name,
					  const void *ns)
{
	struct rb_node *node = parent->dir.children.rb_node;
	bool has_ns = kernfs_ns_enabled(parent);
	unsigned int hash;

	lockdep_assert_held(&kernfs_mutex);

	if (has_ns != (bool)ns) {
		WARN(1, KERN_WARNING "kernfs: ns %s in '%s' for '%s'\n",
		     has_ns ? "required" : "invalid", parent->name, name);
		return NULL;
	}


	// 名字的哈希值
	hash = kernfs_name_hash(name, ns);
	while (node) {
		struct kernfs_node *kn;
		int result;

		kn = rb_to_kn(node);

		// 这个函数会对比kn的哈希值，ns，name，这3个都一致才返回0
		result = kernfs_name_compare(hash, name, ns, kn);
		if (result < 0)
			// 向左走
			node = node->rb_left;
		else if (result > 0)
			// 向右走
			node = node->rb_right;
		else
			// 找到了
			return kn;
	}
	return NULL;
}


static void __kernfs_remove(struct kernfs_node *kn)
{
	struct kernfs_node *pos;

	lockdep_assert_held(&kernfs_mutex);

	if (!kn || (kn->parent && RB_EMPTY_NODE(&kn->rb)))
		return;

	pr_debug("kernfs %s: removing\n", kn->name);

	// 递规的增加非活跃的计数
	pos = NULL;
	while ((pos = kernfs_next_descendant_post(pos, kn)))
		if (kernfs_active(pos))
			atomic_add(KN_DEACTIVATED_BIAS, &pos->active);

	/* deactivate and unlink the subtree node-by-node */
	do {
		// 找到kn的第一个孩子
		pos = kernfs_leftmost_descendant(kn);

		kernfs_get(pos);

		if (kn->flags & KERNFS_ACTIVATED)
			kernfs_drain(pos);
		else
			WARN_ON_ONCE(atomic_read(&kn->active) != KN_DEACTIVATED_BIAS);

		// 把pos从目录解链
		if (!pos->parent || kernfs_unlink_sibling(pos)) {
			struct kernfs_iattrs *ps_iattr =
				pos->parent ? pos->parent->iattr : NULL;

			// 更新父目录时间戳
			if (ps_iattr) {
				ktime_get_real_ts64(&ps_iattr->ia_ctime);
				ps_iattr->ia_mtime = ps_iattr->ia_ctime;
			}

			kernfs_put(pos);
		}

		kernfs_put(pos);
	} while (pos != kn);
}
```