#include "../include/utils.hh"
#include "../include/bblock.hh"

static Disass d;
static bool is_last_branch(__u64 i, std::list<__u64>& list);

Generic(T) void iter(ElfPtr elf, __u64 virt, T fn) {
	__u64 off = elf->vtof(virt);
	// if (in.IsDatamov()) {
	// 	switch (in[0]->Type()) {
	// 		case OperType::REG:
	// 	}
	// }

	d.iter(elf->off(off), bblock::size(elf->map, off), [&](__u64 i, insn_t& in) {
		fn(i, in);
		/* Cflow */
		if (in.IsCall() || in.IsJump()) {
			__u64 dest = in.PtrAddr(virt + i);
			if (dest != -1) {
				iter(elf, elf->vtof(dest), fn);
			}
		}
	});
}

namespace bblock {
	void get(struct bb_ret_insn *ret, void *mem, __u64 off, __u64 offset, __u64 size) {
		std::list<__u64> blist;
		bool ok{false};

		d.iter(mem + offset, size, [&](__u64 i, insn_t& in) {
			ret->in = in;
			if (in.IsNull())
				goto is_cflow_end;

			if (in.IsJump() && in.size() == 2)// || (in.IsBranch() && in.PtrAddr(0) < 0xffffu))
				blist.push_back(in.PtrAddr(i));

			is_cflow_end:
			if (	is_last_branch(i, blist) && ((in.IsNull())
				||	((in.IsQuit() || in.Mnemo()
				 &&	 (in.IsJmp()  || in.IsRet() || in.IsHlt())))))
			{
				*ret = {
					.off = offset+off,
					.size = i+in.size()-off,
					.in = in,
				};
				ok = true;
				throw DisassQuit;
			}
		});
		if (!ok) {
			ret->off = offset+off;
			ret->size = size + ret->in.size() - off;
		}
		d.iter(mem + ret->off + ret->size, -1, [&](__u64 i, insn_t& in) {
			if (!in.IsNull() && in.IsNop()) ret->size+=in.size();
			else throw DisassQuit;
		});
	}

	__u64 size(void *mem, __u64 offset) {
		bb_ret_insn r;
		bblock::get(&r, mem, 0, offset, -1);
		return r.size;
	}

	__u64 size(void *mem, __u64 offset, __u64 max) {
		bb_ret_insn r;
		bblock::get(&r, mem, 0, offset, max-offset);
		return r.size;
	}
};

static bool is_last_branch(__u64 i, std::list<__u64>& list) {
	for (__s64 e : list) if (e > (__s64)i) return false;
	return true;
}