#ifndef DEBUGFS_DEMO_H
#define DEBUGFS_DEMO_H

#define EXT_DEF_FLAG(name) extern bool dd_##name

EXT_DEF_FLAG(f1);
EXT_DEF_FLAG(f2);
EXT_DEF_FLAG(f3);
EXT_DEF_FLAG(f4);
EXT_DEF_FLAG(f5);
EXT_DEF_FLAG(f6);

#endif