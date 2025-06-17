#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>

#include <fuse.h>
#include <linux/fuse.h>
#include <fuse_lowlevel.h>

#include "ebpf.h"
#include "ebpf_lookup.h"


void init_read_stat_map(ebpf_context_t *ctxt);
int data_insert(ebpf_context_t *ctxt, uint64_t file_handle,
    uint64_t offset, uint64_t size, const char *data);