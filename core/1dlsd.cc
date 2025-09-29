#include <linux/types.h>
#include <stdarg.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <list>
#include <x86disass/disass.hpp>
#include <elflib/elf.hpp>
#include <elfcore/elfcore.hh>
#include "../include/1dlsd.hh"

namespace lsd = _1Dlsd;
namespace _1Dlsd
{
__s8 _1Dlsd::load(char *f) {
	auto& file = elf.file;

	file.name = f;
	file.fd = open(file.name.c_str(), O_RDONLY);
	if (file.fd == -1) return -1;

	struct stat st;
	if (fstat(file.fd, &st) == -1) return -1;
	
	file.size = st.st_size;
	elf.map = util::mmap_file(file.fd, file.size);	
	return 0;
}

lsd::err_t _1Dlsd::ChopElf() {
	auto& ehdr = elf.ehdr;
	if (!!elf.is_overflow(ehdr->e_phoff))
		return lsd::err_t(lsd::Error::NoPhdr);

	cpy_phdr(elf.off(ehdr->e_phoff), ehdr->e_phnum);
	cpy_shdr(elf.off(ehdr->e_shoff), ehdr->e_shnum);
	ElfParser::parse(this);
	
	return lsd::err_t{};
}

void _1Dlsd::cpy_phdr(void *mem, __u16 n) {
	elf.phdr.mm  = mm_t(N_PHDR(n));
	elf.phdr.off = elf.ehdr->e_phoff;
	memcpy(elf.phdr.tab, mem, elf.phdr.mm.sz);
}
void _1Dlsd::cpy_shdr(void *mem, __u16 n) {
	elf.sec.mm 	= mm_t(N_SHDR(n));
	elf.sec.off = elf.ehdr->e_shoff;
	memcpy(elf.sec.tab, mem, elf.sec.mm.sz);
}


void _1Dlsd::hdr_align(__u64 off, __u64 sz) {
	for (auto& [k, emm] : h.map) {
		if (_contain_(*k, emm.mm->sz, off)) {
			h.map[k].mm->sz += sz;
		} else if (*k >= off) {
			*k+=sz;
		}
	}
	for (auto& [k, emm] : h.seg) {
		if (_contain_(k, emm.mm_raw.sz, off)) {
			h.seg[k].mm_raw.sz += sz;
		} else if (k >= off) {
			h.seg.erase(k);
			h.seg[k+sz] = emm;
		}
	}
}

void _1Dlsd::elf_align(__u64 off, __u64 sz) {
	auto& ehdr = elf.ehdr;
	if (ehdr->e_shoff > off) ehdr->e_shoff += sz;
	if (ehdr->e_phoff > off) ehdr->e_phoff += sz;


	h.feach(Phdr, [&](ElfX_Phdr *_p) {
		if (_contain_(_p->p_offset, _p->p_filesz, off)) {
			_p->p_memsz		+= sz;
			_p->p_filesz	+= sz;
		} else if (_p->p_offset >= off) {
			_p->p_offset	+= sz;
			_p->p_paddr		+= sz;
			_p->p_vaddr		+= sz;
		}
	});
	h.feach(Shdr, [&](ElfX_Shdr *sec) {
		if (_contain_(sec->sh_offset, sec->sh_size, off)) {
			sec->sh_size	+= sz;
		} else if (sec->sh_offset >= off) {
			sec->sh_addr	+= sz;
			sec->sh_offset	+= sz;
		}
	});
	// patch_each(pack, SYM, Elf64_Sym, sym)
	// 	if (sym->st_value >= pack_ftov(pack, off))
	// 		sym->st_value += ptx_align(pack, off, sz, sym->st_value);
}

void *_1Dlsd::insert_phdr(Elf_PhdrTabl *tab, __u64 nth, void *e, __u16 num=1) {
	elf.ehdr->e_phnum += num;
	return elf.phdr.mm.ins(N_PHDR(nth), static_cast<Elf64_Phdr*>(e), N_PHDR(num));
}
void *_1Dlsd::insert_shdr(Elf_ShdrTabl *tab, __u64 nth, void *e, __u16 num) {
	elf.ehdr->e_shnum += num;
	return elf.sec.mm.ins(N_SHDR(nth), static_cast<Elf64_Shdr*>(e), N_SHDR(num));
}
void *_1Dlsd::insert_rela(Elf_RelaTabl *tab, __u64 nth, void *e, __u16 num) {
	return tab->mm.ins(nth*sizeof(Elf64_Rela), static_cast<Elf64_Rela*>(e), num*sizeof(Elf64_Rela));
}
void *_1Dlsd::insert_rel(Elf_RelTabl *tab, __u64 nth, void *e, __u16 num) {
	return tab->mm.ins(nth*sizeof(Elf64_Rel), static_cast<Elf64_Rel*>(e), num*sizeof(Elf64_Rel));
}
void *_1Dlsd::insert_sym(Elf_SymTabl *tab, __u64 nth, void *e, __u16 num) {
	return tab->mm.ins(nth*sizeof(Elf64_Sym), static_cast<Elf64_Sym*>(e), num*sizeof(Elf64_Sym));
}
void *_1Dlsd::insert_dyn(Elf_DynTabl *tab, __u64 nth, void *e, __u16 num) {
	return tab->mm.ins(nth*sizeof(Elf64_Dyn), static_cast<Elf64_Dyn*>(e), num*sizeof(Elf64_Dyn));
}



void _1Dlsd::iter_bblocks(__u64 offset, __u64 size) {
	for_bblocks(elf.map, off, sz, offset, size) {
		pass->for_bblock((void*)(elf.map + off), off, sz);
	}
}


__s8 _1Dlsd::output(char *f) {
    int fd = open(f, O_CREAT|O_RDWR, 0755);
    if (fd == -1) return -1;

    patch_elf();
    pwrite(fd, elf.ehdr, sizeof(*elf.ehdr), 0);
    for (auto& [off, e] : h.map) {
    	if (!!off) pwrite(fd, e.mm->mem, e.mm->sz, *off);
    }
    for (auto& [off, e] : h.seg) {
    	pwrite(fd, e.mm_raw.mem, e.mm_raw.sz, off);
    }
    close(fd);
    return 0;
}

/**
 * Fix the fucking relocation / dynamic entries
**/
void _1Dlsd::patch_elf() {
	return;
	// make ehdr into struct not a fucking ptr to mmap
	elf.ehdr->e_entry = h.orig_vtov(&elf, elf.ehdr->e_entry);
	h.feach(Dyn, [&](Elf64_Dyn *dyn) {
		if (ParseElf::dyn_is_ptr(dyn))
			dyn->d_un.d_ptr = h.orig_vtov(&elf, dyn->d_un.d_ptr);
	});
		
	/* Patch Rela */
	elf_mm_t iter;
	h.feach(Rela, &iter, [&](Elf64_Rela *r) {
		elfobj_t *s_elf = iter.src.elf;
		__u64 orig_off	= s_elf->vtof(r->r_offset);
		__u64 r_virt	= h.orig_ftov(s_elf, orig_off);
		// __u64 r_off		= orig_ftof(s_elf, orig_off);

// 		__u64 rA = pack_get_addr(p, elf, ELF_VIRT, r->r_addend);
// 		__u64 rS = pack_get_addr(p, elf, ELF_VIRT, *(__u64*)(elf->map + orig_off));
// 		void *dst = NULL;

// 		r->r_offset = r_virt;

// 		ptx_patch_tup ptup = {0};
// 		pack_get_patch(p, &ptup, r_off);
// 		ptx_patch_t *px = ptup.list_elem->dat;
// 		if (!!px) {
// 			if (r_off - px->off > px->mm.size) goto fail;
// 			dst = px->mm.mem + (r_off - px->off);
// 		}

// 		switch (ELF64_R_TYPE(r->r_info)) {
// 			case R_X86_64_RELATIVE:
// 				r->r_addend = rA;
// 				break;
// 			case R_X86_64_GLOB_DAT:
// 			case R_X86_64_JUMP_SLOT: if(!dst) goto fail;
// 				*(__u64*)dst = rS;
// 				break;
// 			case R_X86_64_64:		if (!dst) goto fail;
// 				*(__u64*)dst = rS + rA;
// 				break;
// 			case R_X86_64_COPY:
// 				r->r_offset = r_off;
// 		}
	});
// 	return;
// 	fail:
// 		xprf(ERR, "%s - fuck!\n", __FUNCTION__);
}
};

namespace _1Dlsd {
void HeaderArray::segments(elfobj_t *src_elf) {
	using T = off_sz_t;

	std::list<T> lst, chunks;
	for (auto& [off_ptr, e] : map) {
		if (!!off_ptr) lst.emplace_back(*off_ptr, e.mm->sz);
	}
	lst.emplace_back(elf.file.size, 0);

	lst.sort([](T& a, T& b) { return a.off < b.off; });

	T *prev{nullptr};
	for (auto& e : lst) {
		__u64 p = (!!prev ? prev->off + prev->sz : 0);
		if (p < e.off) {
			seg[p].is_raw = true;
			seg[p].mm_raw = mm_t(elf.map + p, e.off-p);
			seg[p].src = {
				.elf= src_elf, .off=p, .sz=e.off-p,
			};
		}
		prev = &e;
	}
}

using M = MemT;
__u64 HeaderArray::orig_vtov(elfobj_t *e, __u64 v) { return base_mem(e, M::Virt, v, M::Virt);	} // e->vtof(v) 
__u64 HeaderArray::orig_ftof(elfobj_t *e, __u64 v) { return base_mem(e, M::Off, v, M::Off);	}
__u64 HeaderArray::orig_vtof(elfobj_t *e, __u64 v) { return base_mem(e, M::Virt, v, M::Off);	}
__u64 HeaderArray::orig_ftov(elfobj_t *e, __u64 v) { return base_mem(e, M::Off, v, M::Virt);	}

__u64 HeaderArray::mem_vtov(elfobj_t *e, __u64 v) { return memconv(e, M::Virt, v, M::Virt);}
__u64 HeaderArray::mem_ftof(elfobj_t *e, __u64 v) { return memconv(e, M::Off, v, M::Off);	 }
__u64 HeaderArray::mem_vtof(elfobj_t *e, __u64 v) { return memconv(e, M::Virt, v, M::Off); }
__u64 HeaderArray::mem_ftov(elfobj_t *e, __u64 v) { return memconv(e, M::Off, v, M::Virt); }

__u64 HeaderArray::memconv(elfobj_t *s_elf, MemT st, __u64 v, MemT dt) {
	__u64 ret = -1;
	feach(Phdr, [&](ElfX_Phdr *_p) {
		__u64 base = ((dt==MemT::Virt) ? _p->p_vaddr : _p->p_offset);
		
		if (st == MemT::Virt)
			if (_contain_(_p->p_vaddr, ALIGN(_p->p_memsz, _p->p_align), v)) {
				ret=base + v - _p->p_vaddr;	throw 0;
			}
		if (st == MemT::Off)
			if (_contain_(_p->p_offset, _p->p_filesz+1, v)) {
				ret=base + v - _p->p_offset; throw 0;
			}
	});
	retn:
	return ret;
}

__u64 HeaderArray::base_mem(elfobj_t *e, MemT st, __u64 v, MemT dt) {
	__u64 offset = (st==MemT::Virt ? e->vtof(v) : v);

	for (auto& [off_ptr, v] : map)
		if (v.src.elf==e && !!off_ptr)
			if (_contain_(v.src.off, v.src.sz, offset)) {
				__u64 ret = *off_ptr + (offset - v.src.off);
				return (dt == MemT::Virt ? mem_ftov(e, ret) : ret);
			}

	for (auto& [off, v] : seg)
		if (v.src.elf==e)
			if (_contain_(v.src.off, v.src.sz, offset)) {
				__u64 ret = off + (offset - v.src.off);
				return (dt == MemT::Virt ? mem_ftov(e, ret) : ret);
			}
	return -1;
}
};

namespace _1Dlsd {
void ElfParser::parse(_1Dlsd *l) {
	ElfParser::dynamic(l);
	ElfParser::dyntab(l);
	ElfParser::sections(l);
}

void ElfParser::dynamic(_1Dlsd *l) {
	for_phdr(&l->elf, p)
		if (p->p_type == PT_DYNAMIC) {
			auto ptr = l->elf.off<Elf64_Dyn*>(p->p_offset);
			l->elf.dynamic.mm = mm_alloc_t(ptr, p->p_filesz),
			l->elf.dynamic.off= p->p_offset;
		}
}

void ElfParser::dyntab(_1Dlsd *l) {
	for_dynamic(&l->elf, dyn)
		if (dyn->d_tag == DT_SYMTAB) {
			__u64 i = 0; 
			__u64 off = l->elf.vtof(dyn->d_un.d_ptr);
			Elf64_Sym *dyntab = l->elf.off<Elf64_Sym*>(off);
			while (!util::is_zero(&dyntab[i++], sizeof(*dyntab)));

			Elf_Sym_dyn e = {
				.mm	 = mm_alloc_t(dyntab, i*sizeof(Elf64_Sym)),
				.off = off,
			};
			l->elf.dyn_tabl.ins(e);
		}
}

struct mm_off_t {
	mm_t 	mm;
	__u64 	off;
};
void ElfParser::sections(_1Dlsd *l) {
	for_shdr(&l->elf, sec) {
		mm_off_t m = {
			.mm 	= mm_alloc_t(l->elf.off(sec->sh_offset), sec->sh_size),
			.off 	= sec->sh_offset
		};
		switch (sec->sh_type) {
			case SHT_SYMTAB:
				l->elf.sym_tabl.ins(*((Elf_SymTabl*)&m));
				break;
			case SHT_RELA:
				l->elf.rela_tabl.ins(*((Elf_RelaTabl*)&m));
				break;
			case SHT_REL:
				l->elf.rel_tabl.ins(*((Elf_RelTabl*)&m));
				break;
			// case SHT_NOTE:
		}
	}
}
};

namespace _1Dlsd {
	__u64 elfobj_t::vtof(__u64 virt) {
		for_phdr(this, p) if (p->hasVirt(virt)) return p->p_offset + virt - p->p_vaddr;
		return 0;
	}
	__u64 elfobj_t::ftov(__u64 off) {
		for_phdr(this, p) if (p->hasOff(off)) return p->p_vaddr + off - p->p_offset;
		return 0;
	}
};

namespace _1Dlsd {
__u64 lsd_insn_t::set_dst(__u64 off) {
	__u64 virt = in->PtrAddr(elf.ftov(off));
	if (virt != -1) return -1;

	dst.virt 	= virt;
	dst.off 	= elf.vtof(virt);
	for_phdr(&elf, _p) if (_p->hasVirt(virt)) {
		dst.phdr = _p;
		*(char*)&dst.perm = _p->p_flags;
	}
	for_shdr(&elf, _s) if (_s->hasVirt(virt)) dst.sec =_s;

	dst.is_str	= util::is_string(elf.off(dst.off));

	return virt;
}
};


Generic(Str) void lsd_die(lsd_ctx *ctx, Str str, ...) {
	va_list va;
	va_start(va, str);
	pf("~*~" BCYAN " Goodbye " CRST "~*~\07\n  ~->\t");
	pf(typeid(Str) == typeid(std::string) ? ((std::string)str).c_str() : str, va);
	p("");
	va_end(va);

	exit(-1);
}