#include <linux/types.h>
#include <x86disass/disass.hpp>


#ifndef BBLOCK_HH
#define BBLOCK_HH
struct bb_ret_insn {
	__u64	off;
	__u64	size;
	insn_t	in;
};

namespace bblock {
	__u64 size(void *mem, __u64 offset);
	__u64 size(void *mem, __u64 offset, __u64 max);
	void get(struct bb_ret_insn *ret, void *mem, __u64 off, __u64 offset, __u64 size);
};



#define for_bblocks(map, _off_, _sz_, _offset_, _size_)										\
		for (__u64 _off_ = (_offset_), _sz_=bblock::size((map), _off_, (_offset_)+(_size_));\
			_off_ < (_offset_) + (_size_);													\
			_off_+=_sz_ + !_sz_, _sz_=bblock::size((map), _off_, (_offset_)+(_size_))) if (!!_sz_)

#define for_phdr_bblocks(map, off, sz, ph)	for_bblocks(map, off, sz, (ph)->p_offset, (ph)->p_filesz)
#endif
