/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _LINUX_BPF_VERIFIER_H
#define _LINUX_BPF_VERIFIER_H 1

#include <linux/bpf.h> /* for enum bpf_reg_type */
#include <linux/filter.h> /* for MAX_BPF_STACK */

 /* Just some arbitrary values so we can safely do math without overflowing and
  * are obviously wrong for any sort of memory access.
  */
#define BPF_REGISTER_MAX_RANGE (1024 * 1024 * 1024)
#define BPF_REGISTER_MIN_RANGE -1

struct bpf_reg_state {
	enum bpf_reg_type type;
	union {
		/* valid when type == CONST_IMM | PTR_TO_STACK | UNKNOWN_VALUE */
		s64 imm;

		/* valid when type == PTR_TO_PACKET* */
		struct {
			u16 off;
			u16 range;
		};

		/* valid when type == CONST_PTR_TO_MAP | PTR_TO_MAP_VALUE |
		 *   PTR_TO_MAP_VALUE_OR_NULL
		 */
		struct bpf_map *map_ptr;
	};
<<<<<<< HEAD
=======
	/* Fixed part of pointer offset, pointer types only */
	s32 off;
	/* For PTR_TO_PACKET, used to find other pointers with the same variable
	 * offset, so they can share range knowledge.
	 * For PTR_TO_MAP_VALUE_OR_NULL this is used to share which map value we
	 * came from, when one is tested for != NULL.
	 * For PTR_TO_SOCKET this is used to share which pointers retain the
	 * same reference to the socket, to determine proper reference freeing.
	 */
>>>>>>> 8fd51c1c0823 (bpf: Add PTR_TO_SOCKET verifier type)
	u32 id;
	/* Used to determine if any memory access using this register will
	 * result in a bad access. These two fields must be last.
	 * See states_equal()
	 */
<<<<<<< HEAD
	s64 min_value;
	u64 max_value;
	bool value_from_signed;
=======
	s64 smin_value; /* minimum possible (s64)value */
	s64 smax_value; /* maximum possible (s64)value */
	u64 umin_value; /* minimum possible (u64)value */
	u64 umax_value; /* maximum possible (u64)value */
	/* Inside the callee two registers can be both PTR_TO_STACK like
	 * R1=fp-8 and R2=fp-8, but one of them points to this function stack
	 * while another to the caller's stack. To differentiate them 'frameno'
	 * is used which is an index in bpf_verifier_state->frame[] array
	 * pointing to bpf_func_state.
	 * This field must be second to last, for states_equal() reasons.
	 */
	u32 frameno;
	/* This field must be last, for states_equal() reasons. */
	enum bpf_reg_liveness live;
>>>>>>> 10423c35d702 (bpf: introduce function calls (verification))
};

enum bpf_stack_slot_type {
	STACK_INVALID,    /* nothing was stored in this stack slot */
	STACK_SPILL,      /* register spilled into stack */
	STACK_MISC	  /* BPF program wrote some data into this slot */
};

#define BPF_REG_SIZE 8	/* size of eBPF register in bytes */

<<<<<<< HEAD
=======
struct bpf_stack_state {
	struct bpf_reg_state spilled_ptr;
	u8 slot_type[BPF_REG_SIZE];
};
struct bpf_reference_state {
	/* Track each reference created with a unique id, even if the same
	 * instruction creates the reference multiple times (eg, via CALL).
	 */
	int id;
	/* Instruction where the allocation of this reference occurred. This
	 * is used purely to inform the user of a reference leak.
	 */
	int insn_idx;
};

>>>>>>> a91bf4d10f2c (bpf: Add reference tracking to verifier)
/* state of the program:
 * type of all registers and stack info
 */
struct bpf_func_state {
	struct bpf_reg_state regs[MAX_BPF_REG];
<<<<<<< HEAD
	u8 stack_slot_type[MAX_BPF_STACK];
	struct bpf_reg_state spilled_regs[MAX_BPF_STACK / BPF_REG_SIZE];
=======
	struct bpf_verifier_state *parent;
	/* index of call instruction that called into this func */
	int callsite;
	/* stack frame number of this function state from pov of
	 * enclosing bpf_verifier_state.
	 * 0 = main function, 1 = first callee.
	 */
	u32 frameno;
	/* subprog number == index within subprog_stack_depth
	 * zero == main subprog
	 */
	u32 subprogno;
	/* The following fields should be last. See copy_func_state() */
	int acquired_refs;
	struct bpf_reference_state *refs;
	int allocated_stack;
	struct bpf_stack_state *stack;
};

#define MAX_CALL_FRAMES 8
struct bpf_verifier_state {
	/* call stack tracking */
	struct bpf_func_state *frame[MAX_CALL_FRAMES];
	struct bpf_verifier_state *parent;
	u32 curframe;
<<<<<<< HEAD
>>>>>>> 10423c35d702 (bpf: introduce function calls (verification))
=======
	u32 active_spin_lock;
	bool speculative;
>>>>>>> b4eac9a69945 (bpf: introduce bpf_spin_lock)
};

#define bpf_get_spilled_reg(slot, frame)				\
	(((slot < frame->allocated_stack / BPF_REG_SIZE) &&		\
	  (frame->stack[slot].slot_type[0] == STACK_SPILL))		\
	 ? &frame->stack[slot].spilled_ptr : NULL)

/* Iterate over 'frame', setting 'reg' to either NULL or a spilled register. */
#define bpf_for_each_spilled_reg(iter, frame, reg)			\
	for (iter = 0, reg = bpf_get_spilled_reg(iter, frame);		\
	     iter < frame->allocated_stack / BPF_REG_SIZE;		\
	     iter++, reg = bpf_get_spilled_reg(iter, frame))

/* linked list of verifier states used to prune search */
struct bpf_verifier_state_list {
	struct bpf_verifier_state state;
	struct bpf_verifier_state_list *next;
};

struct bpf_insn_aux_data {
	union {
<<<<<<< HEAD
		enum bpf_reg_type ptr_type;     /* pointer type for load/store insns */
		struct bpf_map *map_ptr;        /* pointer for call insn into lookup_elem */
=======
		enum bpf_reg_type ptr_type;	/* pointer type for load/store insns */
		unsigned long map_state;	/* pointer/poison value for maps */
		s32 call_imm;			/* saved imm field of call insn */
<<<<<<< HEAD
>>>>>>> 87b159cb4a05 (bpf: x64: add JIT support for multi-function programs)
=======
		u32 alu_limit;			/* limit for add/sub register with pointer */
		struct {
			u32 map_index;		/* index into used_maps[] */
			u32 map_off;		/* offset from value base address */
		};
>>>>>>> 9c10dc89bf41 (bpf: implement lookup-free direct value access for maps)
	};
	int sanitize_stack_off; /* stack slot to be cleared */
	bool seen; /* this insn was processed by the verifier */
};

#define MAX_USED_MAPS 64 /* max number of maps accessed by one eBPF program */

<<<<<<< HEAD
struct bpf_verifier_env;
struct bpf_ext_analyzer_ops {
	int (*insn_hook)(struct bpf_verifier_env *env,
			 int insn_idx, int prev_insn_idx);
};

=======
#define BPF_VERIFIER_TMP_LOG_SIZE	1024

struct bpf_verifier_log {
	u32 level;
	char *kbuf;
	char __user *ubuf;
	u32 len_used;
	u32 len_total;
};

static inline bool bpf_verifier_log_full(const struct bpf_verifier_log *log)
{
	return log->len_used >= log->len_total - 1;
}

static inline bool bpf_verifier_log_needed(const struct bpf_verifier_log *log)
{
	return log->level && log->ubuf && !bpf_verifier_log_full(log);
}

__printf(2, 3) void bpf_verifier_log_write(struct bpf_verifier_env *env,
					   const char *fmt, ...);

void bpf_verifier_vlog(struct bpf_verifier_log *log, const char *fmt,
		       va_list args);

<<<<<<< HEAD
>>>>>>> 9faa02816919 (bpf: offload: allow netdev to disappear while verifier is running)
=======
#define BPF_MAX_SUBPROGS 256

<<<<<<< HEAD
>>>>>>> 79362c5a0fad (bpf: squash of log related commits)
=======
struct bpf_subprog_info {
	u32 start; /* insn idx of function entry point */
	u32 linfo_idx; /* The idx to the main_prog->aux->linfo */
	u16 stack_depth; /* max. stack depth used by this function */
};

>>>>>>> 43db0b2ddbf3 (bpf: centre subprog information fields)
/* single container for all structs
 * one verifier_env per bpf_check() call
 */
struct bpf_verifier_env {
	struct bpf_prog *prog;		/* eBPF program being verified */
	const struct bpf_verifier_ops *ops;
	struct bpf_verifier_stack_elem *head; /* stack of verifier states to be processed */
	int stack_size;			/* number of states to be processed */
	struct bpf_verifier_state cur_state; /* current verifier state */
	struct bpf_verifier_state_list **explored_states; /* search pruning optimization */
	const struct bpf_ext_analyzer_ops *analyzer_ops; /* external analyzer ops */
	void *analyzer_priv; /* pointer to external analyzer's private data */
	struct bpf_map *used_maps[MAX_USED_MAPS]; /* array of map's used by eBPF program */
	u32 used_map_cnt;		/* number of used maps */
	u32 id_gen;			/* used to generate unique reg IDs */
	bool allow_ptr_leaks;
	bool seen_direct_write;
	bool varlen_map_value_access;
	struct bpf_insn_aux_data *insn_aux_data; /* array of per-insn state */

	struct bpf_verifier_log log;
	struct bpf_subprog_info subprog_info[BPF_MAX_SUBPROGS + 1];
	u32 subprog_cnt;
};

<<<<<<< HEAD
<<<<<<< HEAD
=======
static inline struct bpf_reg_state *cur_regs(struct bpf_verifier_env *env)
=======
static inline struct bpf_func_state *cur_func(struct bpf_verifier_env *env)
>>>>>>> a91bf4d10f2c (bpf: Add reference tracking to verifier)
{
	struct bpf_verifier_state *cur = env->cur_state;

	return cur->frame[cur->curframe];
}

static inline struct bpf_reg_state *cur_regs(struct bpf_verifier_env *env)
{
	return cur_func(env)->regs;
}

int bpf_prog_offload_verifier_prep(struct bpf_verifier_env *env);
int bpf_prog_offload_verify_insn(struct bpf_verifier_env *env,
				 int insn_idx, int prev_insn_idx);

>>>>>>> 9faa02816919 (bpf: offload: allow netdev to disappear while verifier is running)
int bpf_analyzer(struct bpf_prog *prog, const struct bpf_ext_analyzer_ops *ops,
		 void *priv);

#include <linux/vmalloc.h>
#include <linux/mm.h>
static inline void *__compat_kvcalloc(size_t n, size_t size, gfp_t flags)
{
        return kvmalloc_array(n, size, flags | __GFP_ZERO);
}
#define kvcalloc __compat_kvcalloc

#endif /* _LINUX_BPF_VERIFIER_H */
