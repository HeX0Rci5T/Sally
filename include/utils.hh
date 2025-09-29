#include <elf.h>
#include <elflib/elf.hpp>
#include <elfcore/elfcore.hh>
#include <sys/mman.h>
#include <regex>
#include <memory>

#ifndef UTILS_H
#define UTILS_H

#define BRED	"\e[1;31m"
#define RED		"\e[0;31m"
#define BGRN	"\e[1;32m"
#define GRN		"\e[0;32m"
#define BBLUE	"\e[1;34m"
#define BLUE	"\e[0;34m"
#define YLW		"\e[0;33m"
#define BYLW	"\e[1;33m"
#define CYAN	"\e[0;36m"
#define BCYAN	"\e[1;36m"
#define WHT		"\e[0;37m"
#define BWHT	"\e[1;37m"
#define CRST	"\e[0m"

#define BGBLACK		"\e[40m"
#define BGRED		"\e[41m"
#define BGGREEN		"\e[42m"
#define BGYELLOW	"\e[43m"
#define BGBLUE		"\e[44m"
#define BGPURPLE	"\e[45m"
#define BGCYAN		"\e[46m"
#define BGWHITE		"\e[47m"

#define BGBBLACK	"\e[0;100m"
#define BGBRED		"\e[0;101m"
#define BGBGREEN	"\e[0;102m"
#define BGBYELLOW	"\e[0;103m"
#define BGBBLUE		"\e[0;104m"
#define BGBPURPLE	"\e[0;105m"
#define BGBCYAN		"\e[0;106m"
#define BGBWHITE	"\e[0;107m"

#define PLUS BGBLACK"["BGRN "+"CRST BGBLACK"]"CRST

#define SYS_MPROTECT 10

#define Generic(x)		template<typename x>
#define Generics(x, y)	template<typename x, typename y>

#define p 		puts
#define pf 		printf
#define px(x)	pf("-> 0x%lx\n", (x));


typedef std::shared_ptr<Elf> ElfPtr;
typedef std::shared_ptr<mmsz_t> mmsz_ptr_t;
#define rawT(T) typename std::remove_const<T>::type

void *map_anon(__u64 sz);
void *map_anon(void *addr, __u64 sz);
void hexdump(void *addr, __u64 sz=0x10);
void MD5_hash(__u8 hash[16], __u8 *msg, __u64 len);

#ifndef UTILS_HH
#define UTILS_HH
namespace util {
	Generic(T)class list : public std::list<T> {
	public:
		void ins(T& e) { dynamic_cast<std::list<T>*>(this)->push_back(e); }
	};

	Generic(T) bool is_zero(T *ptr, __u64 size) {
		for (__u64 i = 0; i < size; i++)
			if (!!((char*)ptr)[i]) return false;
		return true;
	}
	Generic(T) bool is_string(T ptr) {
		while (!!*(char*)ptr) if (!isprint(*(char*)ptr++)) return false;
		return true;
	}
	int _mprot(void *p, __u64 size, int prot);
	void *mmap_file(int fd, __u64 size);
	std::vector<std::string> regexp(std::string rx, std::string& exp);
	bool is_hex(std::string& str);
	__u64 strtoull(std::string& str);
};
#endif

void ds(void *mem, __u64 sz);

#endif