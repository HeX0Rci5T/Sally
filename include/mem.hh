#include <linux/types.h>
#include <sys/mman.h>
#include <string.h>
#include <list>
#include "./utils.hh"

#ifndef MEM_HH
#define MEM_HH

#define PAGE_SZ			0x1000
#define PAGE_MASK		(~(PAGE_SZ-1))
#define PAGE_ALIGN_UP(x)(((x)+PAGE_SZ) & PAGE_MASK)
#define PAGE_ALIGN(x)	(((x)+PAGE_SZ -1) & PAGE_MASK)

#define BIT_MASK(n)		((1ull << (n) ) -1)
#define ALIGN(_v_, align)	(((_v_) + ((align)-1)) & ~((align)-1))

enum class MemT : __u8
{ Virt, Off };

enum class mm_type_t : __u8
{ NONE, HEAP, MMAP };

// void xrealloc(mm_type_t t, void *mem, __u64 size, __u64 new_size) {
// 	void *ptr{NULL};
// 	switch (t) 
// 		case T::MMAP: mem = map_anon(sz);	break;
// 		case T::HEAP: ptr = malloc(size+new_size);
// 	memcpy(ptr, mem, size);
// 	free(mem);
// 	return ptr;
// }


using T = mm_type_t;
struct mm_t {
	void		*mem;
	__u64		sz;
	mm_type_t	t;
	mm_t() = default;
	Generic(T)
	mm_t(T *ptr, __u64 size) : mem{ptr}, sz{size} {}
	mm_t(__u64 size)
		: sz{size}
	{
		mem = allocate(NULL, t = mm_type(size));
	}
	mm_t(mm_type_t type, __u64 size)
		: sz{size}, t{type}
	{
		mem = allocate(NULL, t);
	}
	mm_t(void *addr, mm_type_t type, __u64 size)
		: sz{size}, t{type}
	{
		mem = allocate(addr, t);
	}
	void *allocate(void *addr, mm_type_t t) { return allocate(addr, t, sz); }
	void *allocate(mm_type_t t) { return allocate(NULL, t, sz); }
	void *allocate(void *addr, mm_type_t t, __u64 size) {
		void *ptr{NULL};
		switch (t) {
			case T::MMAP: ptr = map_anon(addr, size);	break;
			case T::HEAP: ptr = malloc(size);			break;
		}
		return ptr;
	}

	void deallocate(void *ptr, __u64 size) {
		if (t == T::MMAP) munmap(ptr, PAGE_ALIGN_UP(size));
		if (t == T::HEAP) free(ptr);
	}

	void *ins(__u64 off, void *ptr, __u64 size) {
		void *orig_mem	= mem;
		mem = allocate(NULL, mm_type(sz+size), sz+size);

		memcpy(mem, orig_mem, off);
		memcpy(mem+off, ptr, size);
		memcpy(mem+off+size, orig_mem+off, sz-off);

		// memcpy(mem, orig_mem, sz);
		// memcpy(mem+sz, ptr, size);

		deallocate(orig_mem, sz);
		t = mm_type(sz+=size);
		
		return static_cast<void*>(mem + sz-size);
	}
private:
	mm_type_t mm_type(__u64 size) {
		return (!!(size > PAGE_SZ)) ? T::MMAP : T::HEAP;
	}
};

struct mm_alloc_t : public mm_t {
	Generic(T) mm_alloc_t(T *ptr, __u64 size) : mm_t(size) {
		memcpy(mem, ptr, size);
	}
	mm_alloc_t(__u64 size) : mm_t(size) {}
};

#define _elf_mm_pst(T, name)	\
	mm_t 		mm_##name;		\
	Elf64_##T	*name;			\

#define _Elf_Union(X, T)		\
	struct {					\
		union {					\
			mm_t 		 mm;	\
			Elf##X##_##T *tab;	\
		};						\
		__u64		off;		\
	}

#define __Elf_Struct(X, T, name)	\
	struct Elf_##T##_##name {		\
		union {						\
			mm_t			mm;		\
			Elf##X##_##T	*name;	\
			Elf##X##_##T 	*tab;	\
		};							\
		__u64 			off;		\
	}
#define Elf_Union(T)	_Elf_Union(64, T)
#define ElfX_Union(T)	_Elf_Union(X, T)

#define _Elf_Struct(T, name)	__Elf_Struct(64, T, name)
#define ElfX_Struct(T, name)	__Elf_Struct(X, T, name)

_Elf_Struct(Rela, rela);
_Elf_Struct(Rel, rel);
_Elf_Struct(Sym, sym);
_Elf_Struct(Sym, dyn);

#define Elf_tabl(T, entry)			util::list<Elf_##T##_##entry>
// #define Elf_tables(T, entry, tab)	_Elf_Struct(T, entry)
#endif
