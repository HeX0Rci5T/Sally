#include <linux/types.h>
#include <elf.h>
#include <sys/stat.h>
#include <x86disass/disass.hpp>
#include <elfcore/elfcore.hh>
#include <string>
#include <functional>
#include <memory>
#include <regex>

#ifndef _1DLSD_H
#include "./mem.hh"
#include "./utils.hh"
#include "./bblock.hh"
#endif

#define for_phdr(elf, p)													\
		for (ElfX_Phdr *p = (ElfX_Phdr *)((elf)->phdr.tab);					\
			!!p && (Elf_Phdr*)p < &(elf)->phdr.tab[(elf)->ehdr->e_phnum]; p++)

#define for_shdr(elf, s)													\
		for (ElfX_Shdr *s = (ElfX_Shdr *)((elf)->sec.tab);					\
			!!s && (Elf_Shdr*)s < &(elf)->sec.tab[(elf)->ehdr->e_shnum]; s++)

#define for_dynamic(elf, d)													\
		for (Elf64_Dyn *d = (Elf64_Dyn *)((elf)->dynamic.tab); !!d->d_tag; d++)

#ifndef _1DLSD_H
#define _1DLSD_H
namespace _1Dlsd
{
	enum class Error : __u8
	{ None, NoPhdr, NoShdr, BadOption };

	class err_t {
		std::string str;
	public:
		Error		t;
		err_t() = default;
		err_t(Error err) : t{err} {}
		char *what() { return const_cast<char*>(str.c_str()); }
	};
};

namespace lsd = _1Dlsd;
namespace _1Dlsd
{
class _1Dlsd;
class err_t;

class pass_t : public RelBase {
protected:
	_1Dlsd	*lsd{nullptr};
public:
	pass_t() = default;

	virtual err_t _init_() { return err_t{}; }
	virtual void for_bblock(void *mem, __u64 off, __u64 size) {}

	friend class _1Dlsd;
};
};


namespace _1Dlsd
{
enum elfhdr_t : __u8
{ Section=1, Shdr=1, Phdr, Rela, Rel, Sym, Dyn };

typedef ElfX_Union(Phdr) 		Elf_PhdrTabl;
typedef ElfX_Union(Shdr) 		Elf_ShdrTabl;
typedef Elf_Union(Dyn)			Elf_DynTabl;
typedef Elf_tabl(Rel, rel)		Elf_RtabTabl;
typedef Elf_Rel_rel				Elf_RelTabl;
typedef Elf_tabl(Rela, rela)	Elf_RaTabTabl;
typedef Elf_Rela_rela			Elf_RelaTabl;
typedef Elf_tabl(Sym, sym)		Elf_StabTabl;
typedef Elf_Sym_sym				Elf_SymTabl;
typedef Elf_tabl(Sym, dyn)		Elf_DStabTabl;
typedef Elf_Sym_dyn				Elf_DynSymTabl;


class _1Dlsd;
struct elfobj_t {
	_1Dlsd			*l;
	struct {
		int 		fd;
		std::string name;
		__u64		size;
	} file;

	union {
		Elf64_Ehdr	*ehdr;
		void		*map;
	};
	ElfX_Union(Phdr)		phdr;
	ElfX_Union(Shdr)		sec;
	Elf_Union(Dyn)			dynamic;

	Elf_tabl(Rel, rel)		rel_tabl;
	Elf_tabl(Rela, rela)	rela_tabl;
	Elf_tabl(Sym, sym)		sym_tabl;
	Elf_tabl(Sym, dyn)		dyn_tabl;

	elfobj_t(_1Dlsd *lsd) : l{lsd} {}
	bool is_overflow(__u64 off) {
		return file.size < off;
	}

	Generic(T=void*) T off(__u64 v) {
		return static_cast<T>(map + static_cast<__u64>(v));
	}
	Generic(T=void*) T virt(__u64 v) {
		return static_cast<T>(map + static_cast<__u64>(vtof(v)));
	}
	__u64 vtof(__u64 virt);
	__u64 ftov(__u64 off);

};

Generic(T) struct lambda_traits;
template<typename C, typename Ret, typename Arg, typename ...Args>
struct lambda_traits<Ret(C::*)(Arg, Args...) const> {
	using first = Arg;
};
Generic(Fn) using lambda_arg = typename lambda_traits<decltype(&Fn::operator())>::first;

typedef struct {
	elfhdr_t 	t;
	bool		is_raw;
	union {
		mm_t 	mm_raw;
		mm_t 	*mm;
	};
	struct {
		elfobj_t	*elf;
		__u64		off;
		__u64		sz;
	} src;
} elf_mm_t;

struct off_sz_t {
	__u64 off;
	__u64 sz;
	off_sz_t(__u64 f, __u64 s)
		: off{f}, sz{s} {}
};

__attribute__((section(".rodata")))
static elfobj_t	__elf(nullptr);

#define is_elfhdr_type(T)					\
	!!(	typeid(T)==typeid(__elf.phdr)		\
	||	typeid(T)==typeid(__elf.sec)		\
	||	typeid(T)==typeid(__elf.sym_tabl)	\
	||	typeid(T)==typeid(__elf.dyn_tabl)	\
	||	typeid(T)==typeid(__elf.rela_tabl)	\
	||	typeid(T)==typeid(__elf.rel_tabl))	\

class HeaderArray {
	_1Dlsd						*lsd;
	elfobj_t&					elf;	// base elf
public:
	std::map<__u64*, elf_mm_t>	map;	// pointing to elf structs
	std::map<__u64, elf_mm_t>	seg;	// 'segments' in between the headers
	
	HeaderArray(_1Dlsd *l, elfobj_t& _elf) : lsd{l}, elf{_elf} {
		push(&elf, Phdr, elf.phdr);
		push(&elf, Shdr, elf.sec);
	}

	Generic(T) void push(elfobj_t *self, elfhdr_t t, T& v) {
		assert(is_elfhdr_type(T)); // "Shall be a type within elfobj_t");
		map[&v.off] = { .t=t, .mm=&v.mm, .src={ self, v.off, v.mm.sz } };
	}
	Generic(Fn) int feach(elfhdr_t t, Fn fn) { return feach(t, nullptr, fn); }
	Generic(Fn) int feach(elfhdr_t t, elf_mm_t *v, Fn fn) {
		int i = 0;
		try {
		for (auto& [_, e] : map)
			if (e.t == t && ++i && !!e.mm) {
				if (!!v) *v = e;
				for (__u64 off=0, sz=get_size(t); off < e.mm->sz; off+=sz)
					fn(static_cast<lambda_arg<decltype(fn)>>(e.mm->mem + off));
			}
		} catch (...) {}
		return i;
	}
	std::map<__u64*, elf_mm_t>& operator()() {
		return map;
	}
	__u64 get_size(elfhdr_t t) {
		__u64 v = 0;
		switch (t) {
			case Phdr:	v=sizeof(Elf_Phdr);	break;
			case Shdr:	v=sizeof(Elf_Shdr);	break;
			case Rela:	v=sizeof(Elf_Rela);	break;
			case Rel:	v=sizeof(Elf_Rel);	break;
			case Sym:	v=sizeof(Elf_Sym);	break;
			case Dyn:	v=sizeof(Elf_Dyn);	break;
		}
		return v;
	}
	
	void segments(elfobj_t *s_elf);
	__u64 orig_vtov(elfobj_t *e, __u64 v);
	__u64 orig_ftof(elfobj_t *e, __u64 v);
	__u64 orig_vtof(elfobj_t *e, __u64 v);
	__u64 orig_ftov(elfobj_t *e, __u64 v);

private:
	__u64 mem_vtov(elfobj_t *e, __u64 v);
	__u64 mem_ftof(elfobj_t *e, __u64 v);
	__u64 mem_vtof(elfobj_t *e, __u64 v);
	__u64 mem_ftov(elfobj_t *e, __u64 v);

	__u64 base_mem(elfobj_t *s_elf, MemT st, __u64 offset, MemT dt);
	__u64 memconv(elfobj_t *s_elf, MemT st, __u64 v, MemT dt);
	
};

// template<typename Fn>
// class Rel : public RelBase {
// 	Fn fn;
// public:
// 	Rel(Fn f) : fn{f} {}
// 	struct hook_ctx hook_fn(struct rel_patch_t *rx, insn_t& in, __u64 imm) {
// 		return fn(rx, in, imm);
// 	}
// };

struct lsd_fix_t {
	elfhdr_t 	t;
	__u64		off;
	__u64		size;
	lsd_fix_t(elfhdr_t 	_t, __u64 offset, __u64 sz)
		: t{_t}, off{offset}, size{sz} {}
};

class _1Dlsd {
public:
	Disass 		d;
	elfobj_t	elf;
private:
	HeaderArray				h;
	std::list<lsd_fix_t>	fixes;
	pass_t					*pass;
public:

	_1Dlsd() = default;
	Generics(P,C) _1Dlsd(P *ps, C f);
	Generics(T, E) void insert(elfhdr_t t, __u64 nth, T *tab, E* e, __u16 num=1);

	__s8 output(char *file);
private:
	__s8 load(char *f);
	err_t ChopElf();
	void cpy_phdr(void *mem, __u16 n);
	void cpy_shdr(void *mem, __u16 n);

	void elf_align(__u64 off, __u64 size);
	void hdr_align(__u64 off, __u64 sz);

	void *insert_phdr(Elf_PhdrTabl *tab, __u64 nth, void *e, __u16 num);
	void *insert_shdr(Elf_ShdrTabl *tab, __u64 nth, void *e, __u16 num);
	void *insert_rela(Elf_RelaTabl *tab, __u64 nth, void *e, __u16 num);
	void *insert_rel(Elf_RelTabl *tab, __u64 nth, void *e, __u16 num);
	void *insert_sym(Elf_SymTabl *tab, __u64 nth, void *e, __u16 num);
	void *insert_dyn(Elf_DynTabl *tab, __u64 nth, void *e, __u16 num);
	
	void iter_bblocks(__u64 offset, __u64 size);
	void patch_elf();
	friend class pass_t;
};
};

namespace _1Dlsd {
Generics(P,C) _1Dlsd::_1Dlsd(P *ps, C f)
	: elf(this), h(this, elf), pass{dynamic_cast<pass_t*>(ps)}//, x86_insn(pass)
{
	pass->lsd = this;
	load(const_cast<char*>(f));

	auto err = ChopElf();
	if (err.t != Error::None)
		p(err.what());
	
	h.segments(&elf);
	if ((err = pass->_init_()).t != Error::None)
		p(err.what());

	for_phdr(&elf, p) {
		if (p->IsX()) iter_bblocks(p->p_offset, p->p_filesz);
	}
}

Generics(T, E) void _1Dlsd::insert(elfhdr_t t, __u64 nth, T *tab, E* e, __u16 num) {
	assert(!!tab);
	switch (t) {
		/* Because of unnamed structs */
		case lsd::Phdr: insert_phdr(reinterpret_cast<Elf_PhdrTabl*>(tab), nth, (void*)e, num);	break;
		case lsd::Shdr: insert_shdr(reinterpret_cast<Elf_ShdrTabl*>(tab), nth, (void*)e, num);	break;
		case lsd::Rela: insert_rela(reinterpret_cast<Elf_RelaTabl*>(tab), nth, (void*)e, num);	break;
		case lsd::Rel:	insert_rel(reinterpret_cast<Elf_RelTabl*>(tab), nth, (void*)e, num);	break;
		case lsd::Sym:	insert_sym(reinterpret_cast<Elf_SymTabl*>(tab), nth, (void*)e, num);	break;
		case lsd::Dyn:	insert_dyn(reinterpret_cast<Elf_DynTabl*>(tab), nth, (void*)e, num);	break;

	}
	auto fix = fixes.emplace_back(t, tab->off, sizeof(e)*num);
	// px(tab->off);
	hdr_align(fix.off, fix.size);
	elf_align(fix.off, fix.size);
}
};

namespace _1Dlsd::ElfParser {
	void parse(_1Dlsd *l);
	void dynamic(_1Dlsd *l);
	void dyntab(_1Dlsd *l);
	void sections(_1Dlsd *l);
};

namespace _1Dlsd {
class lsd_insn_t : public insn_t {
	elfobj_t&	elf;
	__u64		offset;
	insn_t		*in{dynamic_cast<insn_t*>(this)};
	struct {
		struct {
			__u8	r:1;
			__u8	w:1;
			__u8	x:1;
		} perm;

		ElfX_Phdr	*phdr;
		ElfX_Shdr	*sec;
		Elf64_Sym	*sym;
		__u64	virt;
		__u64	off;
		bool	is_str;
	} dst;

public:
	lsd_insn_t() = delete;
	lsd_insn_t(elfobj_t& _elf, __u64 off, insn_t& ln)
		: elf{_elf}, offset{off}
	{
		if (ln.IsPtr() || ln.IsRip()) set_dst(off);
	}

private:
	__u64 set_dst(__u64 off);
};
};

extern "C" typedef struct {
	Elf 						elf;
	std::vector<std::string>	args;
} lsd_ctx;
Generic(Str) void lsd_die(lsd_ctx *ctx, Str str, ...);

#define assertln(cond, str)		if (!(cond)) lsd_die(NULL, str);
#define assertf(cond, str, ...)	if (!(cond)) lsd_die(NULL, str, __VA_ARGS__);
#endif