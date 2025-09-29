#include "../include/shellcode.hh"

mm_t *Shellcode::compile() {
	if (!!mm.mem) mm.deallocate(mm.mem, mm.sz);
	mm = mm_t(get_sc_size());
	
	__u64 i = 0;
	for (auto& e : specs) {
		__u64 sz = std::get<1>(e);
		memcpy(mem+i, e.get(), sz);
		i += sz;
	}
	return &mm;
}
__u64 Shellcode::get_sc_size() {
	__u64 sz{};
	for (auto& e : specs) sz += std::get<1>(e);
	return sz;
}
