#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <elflib/elf.hpp>
#include <x86disass/disass.hpp>
#include <elfcore/elfcore.hh>
#include <vector>
#include <memory>

#ifndef SALLY_HH
#define SALLY_HH
#include "./mem.hh"
#include "./utils.hh"
#include "./bblock.hh"

namespace Sally {
#pragma pack(1)
struct mm_area_t : mm_t {
	mmsz_t		e_mmsz;
	union {
		struct {
			__u8 x:1;
			__u8 w:1;
			__u8 r:1;
		} perm;
		int prot{};
	};

	mm_area_t() = default;
	mm_area_t(int p, mmsz_t& mm);
	mm_area_t(mmsz_t *mm, int p);
	mm_area_t(int p, __u64 size);
	mm_area_t(void *addr, int p, __u64 size);
	
	bool write_on() {
		return !util::_mprot(mem, sz, PROT_READ|PROT_WRITE);
	}
	bool write_off() {
		return !util::_mprot(mem, sz, get());
	}
	int cpy(__u64 off, void *src, __u64 size);
private:
	bool chng_prot();
	int get() {
		int r{};
		r |= (prot&PF_R) ? PROT_READ	: 0;
		r |= (prot&PF_W) ? PROT_WRITE	: 0; 
		r |= (prot&PF_X) ? PROT_EXEC	: 0;
		return r;
	}
};
#pragma pack()



struct elfobj_t : Elf {
	std::list<struct bblock_st>	bb;

	elfobj_t() = delete;
	Generic(T) elfobj_t(T *f) : Elf(const_cast<char*>(f)) {
		foreach_phdr(this, _p) {
			if (_p->IsX())
				for_bblocks(map, off, sz, _p->p_offset, _p->p_filesz) {
					bb.push_back((struct bblock_st){BBEnumT::None, off, sz});
				}
		}
	}
};


typedef std::shared_ptr<Sally::elfobj_t> selfobj_t;
struct vm_area_t {
	selfobj_t 			elf;
	struct mm_area_t	mma;
	struct mm_area_t	shadow;
	__u64				addr;
};

class Instr;
struct vmmap_t : std::list<struct vm_area_t> {
	std::list<Instr> rels;
	void *off(selfobj_t elf, __u64 off);
	void *virt(selfobj_t elf, __u64 virt);
	vm_area_t *get(selfobj_t elf, __u64 virt);
	void *base(selfobj_t elf);

private:
	std::list<struct vm_area_t> *raw() {
		return dynamic_cast<std::list<struct vm_area_t>*>(this);
	}
};

class Stack {
	void	*mem;
	__u64	size;
public:
	__u64 rsp, rbp;
	Stack() = default;
	Stack(mm_t&& m) : mem{m.mem}, size{m.sz} { rbp=rsp=m.sz; }
	void *ptr() { return mem + rsp; }
	template<typename T> void push(T  b) {
		*(reinterpret_cast<T *>(&((char*)mem)[(rsp -= sizeof(T))])) = (T)b;
	}
	void push_str(std::string& str) {
		push_str(str.c_str());
	}
	template<typename T> void push_str(T *str) {
		for (__u64 i = strlen(str); !!(i+1); i--)
			push(((char*)str)[i]);
	}
};
};
#define X86_GNU_LIB std::string{"/lib/x86_64-linux-gnu/"}

namespace Sally {
enum class HookHandlerT : __u8
{
	PreHook, PostHook, OffHook,
};

enum class HookT : __u8
{
	Inline,		// ; stick shellcode before/after bblock
	ASM,		// ; link to asm without <struct regs_t>
	Fun,		// ; link to function with <struct regs_t>
};

enum class err_t : __u8 {};
class ctx {
public:
	ctx() = default;
};
typedef err_t (*hook_fn_t)();
struct hook_fn_st {
	hook_fn_t 	fn{};
	mm_t 		mm{};
	
	hook_fn_st() = default;
	hook_fn_st(hook_fn_t fun) : fn{fun} {}
	hook_fn_st(void *mem, __u64 size) : mm{mm_t(mem, size)} {}
};

struct hook_key_t {
	char		*lib{};
	char		*sym{};
	__u64		off{-1ULL};

	hook_key_t() = default;
	hook_key_t(__u64 offset) : off{offset} {}
	hook_key_t(char *l, char *s)
		: lib{new char[strlen(l)+1]}, sym{new char[strlen(s)+1]}
	{
		memcpy(lib, reinterpret_cast<void*>(l), strlen(l)+1);
		memcpy(sym, reinterpret_cast<void*>(s), strlen(s)+1);
	}
	hook_key_t(char *l, __u64 offset)
		: lib{new char[strlen(l)+1]}, off{offset}
	{
		memcpy(lib, reinterpret_cast<void*>(l), strlen(l)+1);
	}
	hook_key_t(char *s)
		: sym{new char[strlen(s)+1]}
	{
		memcpy(sym, reinterpret_cast<void*>(s), strlen(s)+1);
	}
	bool operator<(const hook_key_t& k) const {
		return (__u64)lib < (__u64)k.lib;
	}
	~hook_key_t() {
		delete[] lib;//if (!!lib) { free(lib); lib=NULL; };
		delete[] sym;//if (!!sym) { free(sym); sym=NULL; };
	}
};

enum class InsElf : bool
{
	Instr=true, NoInstr=false
};
using IE = InsElf;
}

class Instr;
class AddrHolder {
	__u64 addr{0};
public:
	Generic(T) AddrHolder(T *n)
		: AddrHolder(reinterpret_cast<__u64>(n)) {}
	AddrHolder(__u64 n) : addr{PAGE_ALIGN(n)} {}
	void *add(__u64 size) {
		return (void*)(addr += PAGE_ALIGN(size));
	}
	void *get() { return (void*)(addr); }
};

extern "C" __attribute__((sysv_abi)) void *ASM_entry(__u64 rdx, void *stack, void *entry);

#define GRPLUS 	BGBLACK "["BGRN"+"CRST BGBLACK"]"CRST
#define PLUS 	BGBLACK "["BCYAN"+"CRST BGBLACK"]"CRST

#define VM_BASE_ADDR	(void*)0x666666660000
#define STACK_SIZE		0x21000ull
namespace Sally {
class Sally {
	x_t_c								xtc;
	AddrHolder							last_addr;
	Stack								stack;
	selfobj_t							elf;
	selfobj_t							interp;
	vmmap_t								vmmap;
	std::list<selfobj_t>				ll_elf;
	std::map<hook_key_t*, hook_fn_st>	hooks;

public:
	Generic(T) Sally(T *file)
		:	elf{std::make_shared<elfobj_t>(file)},
			stack(mm_area_t(PF_R|PF_W, STACK_SIZE)),
			xtc(), last_addr(VM_BASE_ADDR)
	{
		ins_elf(IE::Instr, elf);
	}

	using Fn = hook_fn_st;
	void hook(__u64 off, void *mem, __u64 size);
	void hook(__u64 off, Fn fn);
	Generics(L, T) void hook(L *l, T *s, void *mem, __u64 size);
	Generics(L, T) void hook(L *l, T *s, Fn fn);
	Generic(L) void hook(L *l, __u64 off, void *mem, __u64 size);
	Generic(L) void hook(L *l, __u64 off, Fn fn);
	Generic(T) void hook(T *s, void *mem, __u64 size);
	Generic(T) void hook(T *s, Fn fn);

	void run(int argc, char *argv[], char *envp[]) {
		p("------+~-=*~ ~+~ [" BGRN"Loading the Interpreter"CRST "] ~+~ ~*=-~+------");
		foreach_phdr(elf, _p) if (_p->p_type == PT_INTERP) {
			char *f = (char*)elf->off(_p->p_offset);
			pf(PLUS " Loading interpreter %s\n", f);
			interp = ins_elf(IE::Instr, f);
		}
		p("------+~-=*[" BGRN"Load libraries PT_LOADs into memory"CRST "]*=-~+------");
		load_library(elf);
		p("------+~-~=*=~-~+ +~-~=*=~-~+  +~-~=*=~-~+ +~-~=*=~-~+------");
		p("");
		p("------+~-=*- ~+~ ~=[" BGRN"Relocating binaries"CRST "]=~ ~+~ -=*=-~+------");
		reloc();
		p("------+~-~=*=~-~+ +~-~=*=~-~+  +~-~=*=~-~+ +~-~=*=~-~+------");
		p("");
		p(GRPLUS " Fixing PHDRs of loaded binaries");
		fix_phdr();
		p("");
		p("------+~-=*=- ~+~=[" BGRN"Initializing the Stack"CRST "]=~+~ -=*=-~+------");
		build_stack(argc, argv, envp);
		p(PLUS " " BGBLACK BGRN"Done"CRST);
		p("-----+~-=*=- ~=" BGBLACK BRED"[" BGBLACK BCYAN"Transfering CFlow to  linker" BGBLACK BRED "]" CRST"=~ -=*=-~+-----");
		pf(PLUS " to 0x%lx\n", vmmap.virt(interp, interp->ehdr->e_entry));
		px(ASM_entry(0x7ffff7e88110, stack.ptr(), vmmap.virt(interp, interp->ehdr->e_entry)));
	}

	friend class Instr;

private:
	Generic(T) selfobj_t elf_get(T *f);
	__u64 reloc_relr_fix(selfobj_t elf, __u64 v);
	void reloc_fix_relr(selfobj_t elf);
	void reloc_stick_ya(void *ptr, selfobj_t elf, Elf_Sym *dynsym, Elf_Rela *r);
	void reloc();

	selfobj_t& ins_elf(IE f, char *file);
	selfobj_t& ins_elf(IE f, selfobj_t elf);
	mm_area_t mma_cpy(selfobj_t elf, ElfX_Phdr *ph);
	void load_library(selfobj_t elf);
	bool has_lib(std::string& str);
	mm_area_t instrument(vm_area_t& vma, ElfX_Phdr *_p);
	void build_stack(int argc, char *argv[], char *envp[]);
	void fix_phdr();
};
};

namespace Sally {
class SallyRel : public RelBase {
	std::function<hook_ctx(struct rel_patch_t *rx, insn_t& in, __u64 imm)> fn;
public: 
	Generic(Fn) SallyRel(Fn fun) : fn{fun} {}
    hook_ctx hook_fn(struct rel_patch_t *rx, insn_t& in, __u64 imm) {
    	return fn(rx, in, imm);
    }
};

class Instr : public RelBase {
	Disass				d;
	vm_area_t&			vma;
	__u64				off;
	__u64				virt;
	__u64				memsz;
	__u64				filesz;
	struct rel_patch_t *base_rx;
	Sally&				s;
public:
	RelInstr			r;
	void				*base;

	Instr() = delete;
	Instr(Sally& _s, vm_area_t& vmarea, ElfX_Phdr *_p)
		:	virt{_p->p_vaddr}, off{ _p->p_offset}, filesz{_p->p_filesz},
			memsz{ALIGN(_p->p_memsz,_p->p_align)}, s{_s}, vma{vmarea},
			r(this, (__u64)_s.last_addr.get(), vma.elf->off(_p->p_offset), memsz)
	{
		base	= s.vmmap.base(vma.elf);
		base_rx = &r._rel_(RelT::InsRel, vma.elf->off(off), (__u64)_s.last_addr.get(), filesz);
		instrument(base_rx);
	}
	void instrument(struct rel_patch_t *rx);
	void relink(__u64 src, __u64 dst) {
		if (!!base_rx) r.hook(*base_rx, src, vma.elf.get(), dst);
	}
	mmsz_t *dump() {
		return r.init();
	}
	struct rel_patch_t& ins(__u64 dst, void *mem, __u64 size) {
		return r._rel_(RelT::InsInsert, mem, dst, size);
	}

	friend class vmmap_t;

protected:
	hook_ctx hook_fn(struct rel_patch_t *rx, __u64 i, insn_t& in, __u64 imm) {
		if (imm == -1) return {};
		// __u64 v = (__u64)base - (__u64)s.last_addr.get() + (__s64)(vmmap_get(imm)->addr - vmmap_off(imm) - (virt - (__u64)base));
		// in.Print();
		// pf(BGRN);
		// for (auto& v : s.vmmap) if (v.elf.get() == vma.elf.get())
		// 	pf("%lx %lx %c\n", v.mma.mem, v.mma.sz, (!!v.mma.perm.x ? 'Y' : '-'));
		// pf(CRST);
		// pf("0x%-8lx 0x%-8lx\n", s.last_addr.get(), vmmap_addr(imm));
		// px(i);
		// p("");
		// if (i&0xffff == 0xbe7d || imm == (__u64)base + 0x1e6ea8) {
			// in.Print();
		// if (!!s.vmmap.virt(vma.elf, imm)) {
		// 	assert(!memcmp(s.vmmap.virt(vma.elf, imm), vma.elf->virt(imm), 0x10));
		// }
		// }
		// if (vma.addr + i == 0xa6967) {
		// 	return {false};
		// 	px(s.vmmap.virt(vma.elf, vma.addr + imm));
		// 	px(vma.addr + imm);
		// 	p("");
		// }
		__u64 v = reinterpret_cast<__u64>(s.vmmap.virt(vma.elf, vma.addr + imm));
		// if (vma.addr + imm == 0x36da0) pf("%lx %lx\n", s.vmmap.virt(vma.elf, vma.addr + imm), vma.addr + imm);
		if (!v) return {};
		return { true, v };
	}
};
};
#endif
