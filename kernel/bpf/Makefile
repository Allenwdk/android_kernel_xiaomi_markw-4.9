obj-y := core.o
CFLAGS_core.o += $(call cc-disable-warning, override-init)

<<<<<<< HEAD
obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o helpers.o
obj-$(CONFIG_BPF_SYSCALL) += hashtab.o arraymap.o percpu_freelist.o
=======
obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o helpers.o tnum.o
obj-$(CONFIG_BPF_SYSCALL) += hashtab.o arraymap.o percpu_freelist.o bpf_lru_list.o lpm_trie.o map_in_map.o
obj-$(CONFIG_BPF_SYSCALL) += local_storage.o
obj-$(CONFIG_BPF_SYSCALL) += btf.o
obj-$(CONFIG_BPF_SYSCALL) += disasm.o
ifeq ($(CONFIG_NET),y)
obj-$(CONFIG_BPF_SYSCALL) += devmap.o
obj-$(CONFIG_BPF_SYSCALL) += cpumap.o
obj-$(CONFIG_BPF_SYSCALL) += offload.o
ifeq ($(CONFIG_STREAM_PARSER),y)
obj-$(CONFIG_BPF_SYSCALL) += sockmap.o
endif
endif
>>>>>>> 8480b85ba5fb (bpf: introduce new bpf cpu map type BPF_MAP_TYPE_CPUMAP)
ifeq ($(CONFIG_PERF_EVENTS),y)
obj-$(CONFIG_BPF_SYSCALL) += stackmap.o
endif
obj-$(CONFIG_CGROUP_BPF) += cgroup.o
