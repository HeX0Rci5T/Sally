#include <x86disass/disass.hpp>
#include <regex>
#include "../include/utils.hh"

void *map_anon(void *addr, __u64 sz) {
	if (!addr) return map_anon(sz);
    return mmap(addr, sz, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE|MAP_ANON, -1, 0);
}

void *map_anon(__u64 sz) {
    return mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
}

void *util::mmap_file(int fd, __u64 size) {
	return mmap(0, size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
}

void ds(void *mem, __u64 sz) {
	Disass().iter(mem, sz, [](__u64 i, insn_t& in) {
		if (!in.IsNull()) in.Print();
	});
}

namespace util {
	std::vector<std::string> regexp(std::string rx, std::string& exp) {
		std::vector<std::string> ret;
	    std::shared_ptr<std::smatch> m{new std::smatch};
	    try {
	        if (!!std::regex_search(exp, *m, (const std::regex)("^"+rx+"$"))) {
				__u64 i = 0;
		        for (auto& x : *m.get()) {
		        	if (!i++) continue;
			        ret.push_back(x);
		        }
		        if (!ret.size()) ret.push_back(rx);
		        return std::move(ret);
	        }
	    } catch (...) {}
	    return std::move(ret);
	}

	bool is_hex(std::string& str) {
	    return !strncmp("0x", str.c_str(), 2);
	}

	__u64 strtoull(std::string& str) {
	    __u64 s = (is_hex(str) ? 2     : 0);
	    __u64 n = (is_hex(str) ? 0x10  : 10);
	    return std::strtoull(&str.c_str()[s], NULL, n);
	}
	int _mprot(void *p, __u64 size, int prot) {
		__u64 ret;
		asm("syscall" : "=r"(ret) : "a"(SYS_MPROTECT), "D"(((__u64)p) & ~0xfffllu), "S"(size), "d"(prot));
		return ret;
	}
};




static char *hexdump_char_color(__u8 c) {
	char *clr = CRST;
	if (isprint(c)) {
		clr = BLUE;
	} else if (isspace(c) || !c) {
		clr = RED;
	} else if (c == 0xff) {
		clr = GRN;
	}
	return clr;
}

void hexdump(void *addr, __u64 sz) {
	__u8 *ptr = (__u8*)addr;

	for (__u64 i = 0; i <= sz; i++) {
		__u8 ch = ptr[i];

		if ( ( !(i % 0x10) && i) || i >= sz) {
			__u8 n = 0x10;

			if (i >= sz) {
				n = !(sz % 0x10) ? 0x10 : (sz % 0x10);
				for (int x = n; x < 0x10; x++) {
					if (!(i % 4)) prf("  ");
					prf("   ");
				}
			}

			prf("\t|\t");

			for (__u8 l = 0; l < n; l++) {
				__u8 c = ptr[ (i-n)+l ];
				char *clr = hexdump_char_color(c);
				prf("%s%c" CRST, clr, isprint(c) ? c : '.');
			}

			pr("");
			if (i >= sz) return;
		}

		if (!i || !(i % 0x10))
			prf(CRST "0x%06x :\t", i);

		if ( !(i % 4) && i && (i % 0x10))
			prf("| ");

		char *clr = hexdump_char_color(ptr[i]);
		prf("%s%02x " CRST, clr, ch);
	}
}