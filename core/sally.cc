#include <unistd.h>
#include <sys/auxv.h>
#include <type_traits>
#include <bits/stdc++.h>
#include <elfcore/elfcore.hh>
#include "../include/sally.hh"
#include "../include/shellcode.hh"

namespace Sally {
mm_area_t::mm_area_t(int p, mmsz_t& mm)
	: prot{p}
{
	if (mm.t==PackPtrT::MMAP) t=mm_type_t::MMAP;
	if (mm.t==PackPtrT::HEAP) t=mm_type_t::HEAP;
	mem	= mm.mem;
	sz	= mm.sz;

	chng_prot();
}
mm_area_t::mm_area_t(int p, __u64 size)
	: prot{p}, mm_t(mm_type_t::MMAP, size)
{ chng_prot(); }
mm_area_t::mm_area_t(void *addr, int p, __u64 size)
	: prot{p}, mm_t(addr, mm_type_t::MMAP, size)
{ chng_prot(); }

bool mm_area_t::chng_prot() { return !mprotect(mem, sz, get()); }
int mm_area_t::cpy(__u64 off, void *src, __u64 size) {
	if (off + size > sz)
		return -1;
	
	write_on();
	memcpy(mem + off, src, size);
	write_off();
	
	return 0;
}
};

namespace Sally {
	void *vmmap_t::off(selfobj_t elf, __u64 off) {
		return virt(elf, elf->ftov(off));
	}
	void *vmmap_t::virt(selfobj_t elf, __u64 virt) {
		for (auto& v : *raw()) if (v.elf.get() == elf.get() && !v.mma.perm.x) {
			if (!!_contain_(v.addr, v.mma.sz, virt)) return v.mma.mem + virt - v.addr;
		}
		for (auto& v : *raw()) if (v.elf.get() == elf.get() && !!v.mma.perm.x) {
			if (!!_contain_(v.addr, v.mma.sz, virt)) {
				auto val = v.mma.mem + virt - v.addr;
				for (auto& r : rels) if (r.vma.elf.get() == elf.get()) {
					__s64 align = r.r.off_align((__u64)val);
					if (!!align) return (void*)((__u64)val + align);
				}
				return val;
			}
		}

		return NULL;
	}
	vm_area_t *vmmap_t::get(selfobj_t elf, __u64 virt) {
		for (auto& v : *raw()) if (v.elf.get() == elf.get()) {
			if (_contain_(v.addr, v.mma.sz, virt)) return &v;
		}
		return nullptr;
	}
	void *vmmap_t::base(selfobj_t elf) {
		vm_area_t *vm_base{};
		for (auto& v : *raw()) if (v.elf.get() == elf.get()) {
			if (!vm_base || v.addr < vm_base->addr) vm_base = &v;
		}
		return vm_base->mma.mem;
	}
};

/**
 * Recursively load libraries
 **/
namespace Sally {	
void Sally::load_library(selfobj_t elf) {

	foreach_dynamic(elf.get(), dyn) {
		if (dyn->d_tag != DT_NEEDED) continue;

		std::string lib = X86_GNU_LIB + (char*)&elf->strtab[dyn->d_un.d_ptr];
		if (!has_lib(lib)) {
			pf(BGBLACK "["BCYAN"+"CRST BGBLACK"]"CRST " Loading library %s\n", lib.c_str());
			load_library(ins_elf(InsElf::NoInstr, const_cast<char*>(lib.c_str())));
		}
	}
}
bool Sally::has_lib(std::string& str) {
	if (!ll_elf.size()) return false;

	for (auto& elf : ll_elf) {
		if (!!elf->file && !strncmp(str.c_str(), elf->file, strlen(elf->file)+1))
			return true;
	}
	return false;
}
};

namespace Sally {
selfobj_t& Sally::ins_elf(InsElf f, char *file) {
	return ins_elf(f, std::make_shared<elfobj_t>(file));
}
selfobj_t& Sally::ins_elf(InsElf f, selfobj_t _elf) {
	selfobj_t& self = ll_elf.emplace_back(_elf);
	foreach_phdr(self, _p)	/* PT_LOADs with non Exec */
		if (	_p->p_type == PT_LOAD
			&&	((f == InsElf::Instr && !_p->IsX())
			||	( f == InsElf::NoInstr)))
		{
			vm_area_t& vma = vmmap.emplace_back(vm_area_t{
				.elf	= self,
				.mma 	= mma_cpy(self, _p),
				.addr	= _p->p_vaddr,
			});
		}

	foreach_phdr(self, _p)	/* PT_LOADs with Exec */
		if (	_p->p_type == PT_LOAD
			&&	(f == InsElf::Instr && _p->IsX()))
		{
			vm_area_t& vma = vmmap.emplace_back(vm_area_t{});
			vma.elf		= self;
			vma.addr	= _p->p_vaddr;	// this one shall b e before .mma
			vma.mma 	= instrument(vma, _p);
			vma.shadow	= mma_cpy(self, _p);
		}
	return self;
}


Generics(T, L) bool revstrcmp(T *a, L *b) {
	if (!a || !b) return false;
	char *a1=reinterpret_cast<char*>(const_cast<rawT(T)*>(a));
	char *b1=reinterpret_cast<char*>(const_cast<rawT(L)*>(b));
	
	// __u64 max_a = PAGE_ALIGN_UP((__u64)a);
	// __u64 max_b = PAGE_ALIGN_UP((__u64)b);

	while (!!*a1 && !!*(++a1));	// && (__u64)a1 < max_a);
	while (!!*b1 && !!*(++b1));	// && (__u64)b1 < max_b);

	while (a1 != (char*)a && b1 != (char*)b) if (*(a1--) != *(b1--)) return false;
	return true;
}

__u64 Sally::reloc_relr_fix(selfobj_t elf, __u64 v) {
	return *(__u64*)vmmap.virt(elf, v) = (__u64)vmmap.virt(elf, *(__u64*)vmmap.virt(elf, v));
}
void Sally::reloc_fix_relr(selfobj_t elf) {
	for (auto& relr : elf->relrtab) {
		void *curr{};
		foreach_relr(&relr, r) {
			if (!(*r & 1)) {
				curr = (void*)*r;
				reloc_relr_fix(elf, *r);
			} else {
				assert(!!curr);
				__u64 e = *r >> 1;
				for (__u64 i = 0; i < 63; i++) {
					if (!!(e & (1ull << i))) {
						__u64 v = (__u64)((curr+(i+1)*sizeof(void*)));
						reloc_relr_fix(elf, v);
					}
				}
				curr += 63 * sizeof(void*);
			}
		}
	}
}

struct ifunc_entry_t {
	void 		*ptr;
	selfobj_t 	elf;
	Elf_Sym 	*sym;
	Elf_Rela 	*r;
};

void Sally::reloc() {
	std::list<ifunc_entry_t> ifunc_list;
	for (auto& ielf : ll_elf) {
		pf(BGBLACK "["BCYAN"+"CRST BGBLACK"]"CRST " %-47s ... ", ielf->file);
		reloc_fix_relr(ielf);
		
		elf_symtab_t *dyntab = ielf->dyntab();
		assert(!!dyntab);

		foreach_rela_tab(ielf, rtab, r) {
			selfobj_t target;
			void *ptr 		= vmmap.virt(ielf, r->r_offset);
			Elf_Sym *dynsym = &dyntab->tab[ELF64_R_SYM(r->r_info)];
			__u16 versym 	= ielf->gnu.versym.tab[ELF64_R_SYM(r->r_info)];
			char *s_name 	= (char*)&dyntab->str[dynsym->st_name];

			foreach_verneed(ielf, vn) {
				foreach_vernaux(vn, vna) if (versym == vna->vna_other) {
					target = elf_get(&ielf->strtab[vn->vn_file]);
					break;
				}
			}
			if (!!dynsym->st_value)
			{	/* Reloc self */
				reloc_stick_ya(ptr, ielf, dynsym, r);
			}
			else if (!!target)
			{	/* Reloc library */
				elf_symtab_t *t_dyntab = target->dyntab();
				Elf_Sym *t_sym = target->sym_by_name(s_name);

				__u64 v = t_sym->st_value;
				if (ELF64_ST_TYPE(t_sym->st_info) == STT_GNU_IFUNC) {
					ifunc_list.push_back(ifunc_entry_t{
						.ptr=ptr, .elf=target, .sym=t_sym, .r=r
					});
				} else {
					reloc_stick_ya(ptr, target, t_sym, r);
				}
			}
		}
		p(BGRN BGBLACK "Done" CRST);
	}
	for (auto& i : ifunc_list) {
		auto ifunc = (void*(*)())(vmmap.virt(i.elf, i.sym->st_value));
		*(void**)i.ptr = (void*)ifunc();
		assert(!!*(void**)i.ptr);
	}

}

void Sally::reloc_stick_ya(void *ptr, selfobj_t elf, Elf_Sym *dynsym, Elf_Rela *r) {
	__u64 t = ELF64_R_TYPE(r->r_info);
	__u64 _B_ = (__u64)vmmap.base(elf);
	__u64 _S_ = dynsym->st_value;
	__u64 _A_ = r->r_addend;
	switch (t) {
		case R_X86_64_JUMP_SLOT:
		case R_X86_64_GLOB_DAT:
			*(void**)ptr = vmmap.virt(elf, _S_);
			break;
		case R_X86_64_64:
			*(void**)ptr = vmmap.virt(elf, _S_+_A_);
			break;
		case R_X86_64_IRELATIVE:	// Base + st_value
			*(void**)ptr = vmmap.virt(elf, _S_);
			break;
		default:
			*(void**)ptr = (void*)(0xdeadull << 32);
			return;
	}
	// assert(!!*(void**)ptr);
}

void Sally::fix_phdr() {
	for (auto& ielf : ll_elf) {
		void *addr		= vmmap.base(ielf);
		vm_area_t *vma	= vmmap.get(ielf, 0);
		Elf_Ehdr *ehdr	= (Elf_Ehdr*)addr;
		Elf_Phdr *phdr	= (Elf_Phdr*)((__u64)addr + ehdr->e_phoff);
		vma->mma.write_on();
		for (__u16 i = 0; i < ehdr->e_phnum; i++) {
			auto _p		= &phdr[i];
			auto _p_vma = vmmap.get(ielf, _p->p_offset);
			_p->p_offset	= ((__u64)vmmap.off(ielf, _p->p_offset) - (__u64)addr);
			_p->p_vaddr 	= ((__u64)vmmap.virt(ielf, _p->p_vaddr) - (__u64)addr);
			_p->p_filesz 	= _p_vma->mma.sz;
			_p->p_memsz		= _p_vma->mma.sz;
			// for (__u16 l = 0; l < ehdr->e_phnum; l++) {
			// 	if (!!_contain_(_p->p_offset, _p->p_filesz, phdr[l].p_offset)) {
			// 		_p->p_filesz = phdr[l].p_offset - _p->p_offset; break;
			// 	}
			// }
		}
		// for (__u16 i = 0; i < ehdr->e_phnum; i++) if (phdr[i].p_type == PT_DYNAMIC) {
		// 	if (phdr[i].p_type == PT_DYNAMIC) phdr[i].p_type = PT_NULL;
		// 	*(Elf_Dyn*)((__u64)addr + phdr[i].p_offset) = {0};
		// }
		// for (__u16 i = 0; i < ehdr->e_phnum; i++) pf("%lx %lx %i\n", phdr[i].p_offset, phdr[i].p_filesz, phdr[i].p_flags);
		vma->mma.write_off();
	}
}

Generic(T) selfobj_t Sally::elf_get(T *f) {
	for (auto& i : ll_elf)
		if (revstrcmp(i->file, f)) return i;
	return nullptr;
}

template selfobj_t Sally::elf_get<char>(char *f);
template selfobj_t Sally::elf_get<__u8>(__u8 *f);
template selfobj_t Sally::elf_get<const char>(const char *f);

using sc_ptr_list = std::list<std::unique_ptr<Shellcode>>;
class SClist : public sc_ptr_list {
public:
	SClist() = default;

	std::unique_ptr<Shellcode>& operator<<(Shellcode *sc) {
		return emplace_back(sc);
	}
	std::unique_ptr<Shellcode>& operator<<(Shellcode&& sc) {
		return emplace_back(new Shellcode{std::move(sc)});
	}
};

#define reviter(i, max) for (__u64 i=(max); !!(i+1); i--)

void Sally::build_stack(int argc, char *argv[], char *envp[]) {
	__u64 auxv_platform=0, auxv_execfn=0;
	
	__u64 env_len=0, arg_len=0;
	std::map<__u64, void *> map_argv, map_envp;
	while (!!argv[++arg_len]); arg_len--;
	while (!!envp[++env_len]); env_len--;
	stack.push(0ull);

	stack.push_str("x86_64");
	auxv_platform = (__u64)stack.ptr();
	stack.push_str(realpath(elf->file, NULL));
	auxv_execfn = (__u64)stack.ptr();
	
	stack.push(0ull);
	
	reviter(i, env_len) {	/* Envp/*/
		stack.push_str(envp[i]);
		map_envp[i] = stack.ptr();
	}
	reviter(i, arg_len) {	/* Argv */
		stack.push_str(argv[i]);
		map_argv[i] = stack.ptr();
	}
	
	stack.push(0ull);
	while (!!(stack.rsp % 0x10)) stack.push((char)0);
	while (!!((stack.rsp - 8*(map_envp.size()+map_argv.size()+23+2)) % 0x10))
		stack.push((char)0);
	{	// wrong order - shall be reverse
		using Auxv = Elf64_auxv_t;
		std::vector<Auxv> s;
		s.push_back(Auxv{ AT_SYSINFO_EHDR,	getauxval(AT_SYSINFO_EHDR) });	// Share the [vdso]
		s.push_back(Auxv{ AT_MINSIGSTKSZ, 	getauxval(AT_MINSIGSTKSZ) });
		s.push_back(Auxv{ AT_HWCAP, 		getauxval(AT_HWCAP) });
		s.push_back(Auxv{ AT_PAGESZ, 	PAGE_SZ });
		s.push_back(Auxv{ AT_CLKTCK, 	100 });
		s.push_back(Auxv{ AT_PHDR,		(__u64)vmmap.virt(elf, elf->ehdr->e_phoff) });
		s.push_back(Auxv{ AT_PHENT, 	sizeof(Elf64_Phdr) });
		s.push_back(Auxv{ AT_PHNUM, 	elf->ehdr->e_phnum });
		s.push_back(Auxv{ AT_BASE, 		(__u64)vmmap.base(interp) });
		s.push_back(Auxv{ AT_FLAGS, 	0 });
		s.push_back(Auxv{ AT_ENTRY, 	(__u64)vmmap.virt(elf, elf->ehdr->e_entry) });
		s.push_back(Auxv{ AT_UID,	getuid()	});
		s.push_back(Auxv{ AT_EUID,	geteuid()	});
		s.push_back(Auxv{ AT_GID,	getgid()	});
		s.push_back(Auxv{ AT_EGID,	getegid()	});
		s.push_back(Auxv{ AT_SECURE, 0 });
		s.push_back(Auxv{ AT_RANDOM, 0xdeadbeef });
		s.push_back(Auxv{ AT_HWCAP2, getauxval(AT_HWCAP2) });
		s.push_back(Auxv{ AT_EXECFN,	auxv_execfn });
		s.push_back(Auxv{ AT_PLATFORM,	auxv_platform });
		s.push_back(Auxv{ AT_RSEQ_FEATURE_SIZE,	getauxval(AT_RSEQ_FEATURE_SIZE)});
		s.push_back(Auxv{ AT_RSEQ_ALIGN, 	 	getauxval(AT_RSEQ_ALIGN)});
		s.push_back(Auxv{ AT_NULL, 0 });

		reviter(i, s.size()) stack.push(s[i]);
		hexdump(stack.ptr(), sizeof(Auxv)*s.size());
	};

	stack.push(0ull);
	reviter(i, env_len) stack.push(map_envp[i]);

	stack.push(0ull);
	reviter(i, arg_len) stack.push(map_argv[i]);
	
	stack.push((__u64)argc);
	px(stack.ptr());
	// assert(!((__u64)stack.ptr() % 0x10));
}

mm_area_t Sally::instrument(vm_area_t& vma, ElfX_Phdr *_p) {
	vma.addr 	= _p->p_vaddr;
	vma.mma.prot= _p->p_flags;
	vma.mma.mem = last_addr.get();
	vma.mma.sz 	= ALIGN(_p->p_memsz, _p->p_align);

	Instr& i = vmmap.rels.emplace_back(*this, vma, _p);
	#if 0
	for (auto& b : vma.elf->bb) {
		__u64 off = b.off - _p->p_offset;
		for (auto& [k, hook] : hooks) {
			Elf_Sym *sym = !k->sym ? nullptr : vma.elf->sym_by_name(k->sym);
			if (	!k->lib && vma.elf.get() == elf.get()
				||	revstrcmp(vma.elf->file, k->lib))
			{	// Same binary
				if (	(!!sym 		&& !!_contain_(b.off, b.size, vma.elf->vtof(sym->st_value)))
					||	(k->off!=-1 && !!_contain_(b.off, b.size, k->off)))
				{	// Same basic block
					if (!!hook.mm.mem) {	// insert sc
						ir.ins(off, hook.mm.mem, hook.mm.sz);
					}
					if (!!hook.fn) {		// insert trampoline; how do we return
						auto& sc = sc_list << Shellcode({
							{ "\xff\x25\x00\x00\x00\x00", 6 },				/* jmp QWORD [ rip+0 ]			*/
							{ p64(reinterpret_cast<void*>(hook.fn)), 8 },	/* hook.fn address				*/
							{ "\x90\x90", 2 }								/* NOP; NOP - to align at 0x10	*/
						});
						ir.ins(off, sc->mm.mem, sc->mm.sz);
					}
					break;
				}
			}
		}
	}
	#endif
	auto mm  = i.dump();

	auto mma = mm_area_t(last_addr.get(), _p->p_flags, mm->sz);
	mma.cpy(0, mm->mem, mm->sz);
	last_addr.add(mm->sz);

	return std::move(mma);
}

namespace InstrBits {
	bool HasReg(Operand *op, const char *reg) {
		Regs r(reg);
		return (	r.val() == op->Reg().val()
				||	r.val() == op->IndexReg().val()
				||	r.val() == op->BaseReg().val());
	}
};

void Instr::instrument(struct rel_patch_t *rx) {
	d.iter(vma.elf->off(off), filesz, [&](__u64 i, insn_t& in){
		if (in.IsNull()) return;
		/* Indirect /QWORD/ [...] */
		if ((in.IsPtr()) && in.PtrAddr() == -1) {
			bool pick = false;
			for (__u8 i=0; i<in.OperCount(); i++) {
				if (in[i]->IsType(OperType::PTR)){
					if (!(	!in[i]->sib.on
						||	InstrBits::HasReg(in[i], "RSP")
						||	InstrBits::HasReg(in[i], "RBP")))
					{ pick = true; }
				}
			}
			/* Skip $RSP & $RBP operations */
			if (!!pick) {
				// in.Print();
				r._rel_(base_rx->ll, RelT::InsInsert, (void*)"\xcc\xcc\xcc\xcc", (__u64)s.last_addr.get()+i, 4);
			}
		}
	});
}

mm_area_t Sally::mma_cpy(selfobj_t elf, ElfX_Phdr *ph) {
	__u64 sz = ALIGN(ph->p_memsz, ph->p_align);
	mm_area_t mma = mm_area_t(last_addr.get(), ph->p_flags, sz);
	mma.cpy(0, elf->off(ph->p_offset), ph->p_filesz);
	last_addr.add(mma.sz);
	return std::move(mma);
}
};

namespace Sally {
using Fn = hook_fn_st;
void Sally::hook(__u64 off, void *mem, __u64 size) {
	auto key = new hook_key_t(off);
	hooks[key] = { mem, size };
}
void Sally::hook(__u64 off, Fn fn) {
	auto key = new hook_key_t(off);
	hooks[key] = fn;
}
Generics(L, T) void Sally::hook(L *l, T *s, void *mem, __u64 size) {
	auto key = new hook_key_t(const_cast<rawT(L)*>(l), const_cast<rawT(T)*>(s));
	hooks[key] = { mem, size };
}
Generics(L, T) void Sally::hook(L *l, T *s, Fn fn) {
	auto key = new hook_key_t(const_cast<rawT(L)*>(l), const_cast<rawT(T)*>(s));
	hooks[key] = fn;
}
Generic(L) void Sally::hook(L *l, __u64 off, void *mem, __u64 size) {
	auto key = new hook_key_t(const_cast<rawT(L)*>(l), off);
	hooks[key] = { mem, size };
}
Generic(L) void Sally::hook(L *l, __u64 off, Fn fn) {
	auto key = new hook_key_t(const_cast<rawT(L)*>(l), off);
	hooks[key] = fn;
}
Generic(T) void Sally::hook(T *s, void *mem, __u64 size) {
	auto key = new hook_key_t(const_cast<rawT(T)*>(s));
	hooks[key] = { mem, size };
}
Generic(T) void Sally::hook(T *s, Fn fn) {
	auto key = new hook_key_t(const_cast<rawT(T)*>(s));
	hooks[key] = fn;
}
};

namespace Sally {
using Fn = hook_fn_st;
template void Sally::hook<char, const char>(char *l, const char *s, void *mem, __u64 size);
template void Sally::hook<const char, char>(const char *l, char *s, Fn fn);
// template void Sally::hook<char, __u8>(char *l, __u8 *s, void *mem, __u64 size);
// template void Sally::hook<__u8, char>(__u8 *l, char *s, Fn fn);
// template void Sally::hook<const char, __u8>(const char *l, __u8 *s, void *mem, __u64 size);
// template void Sally::hook<__u8, const char>(__u8 *l, const char *s, Fn fn);

template void Sally::hook<char, char>(char *l, char *s, void *mem, __u64 size);
template void Sally::hook<char, char>(char *l, char *s, Fn fn);
template void Sally::hook<char>(char *l, __u64 off, void *mem, __u64 size);
template void Sally::hook<char>(char *l, __u64 off, Fn fn);
template void Sally::hook<char>(char *s, void *mem, __u64 size);
template void Sally::hook<char>(char *s, Fn fn);

template void Sally::hook<const char, const char>(const char *l, const char *s, void *mem, __u64 size);
template void Sally::hook<const char, const char>(const char *l, const char *s, Fn fn);
template void Sally::hook<const char>(const char *l, __u64 off, void *mem, __u64 size);
template void Sally::hook<const char>(const char *l, __u64 off, Fn fn);
template void Sally::hook<const char>(const char *s, void *mem, __u64 size);
template void Sally::hook<const char>(const char *s, Fn fn);

// template void Sally::hook<__u8, __u8>(__u8 *l, __u8 *s, void *mem, __u64 size);
// template void Sally::hook<__u8, __u8>(__u8 *l, __u8 *s, Fn fn);
// template void Sally::hook<__u8>(__u8 *l, __u64 off, void *mem, __u64 size);
// template void Sally::hook<__u8>(__u8 *l, __u64 off, Fn fn);
// template void Sally::hook<__u8>(__u8 *s, void *mem, __u64 size);
// template void Sally::hook<__u8>(__u8 *s, Fn fn);
};