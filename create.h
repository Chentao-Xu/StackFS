#ifndef __CREATE_H__
#define __CREATE_H__

#define _GNU_SOURCE

#include <fuse_lowlevel.h>

#include "ebpf.h"

int ebpf_create_entry(ebpf_context_t *ctxt, void *args, size_t args_sz);

#endif