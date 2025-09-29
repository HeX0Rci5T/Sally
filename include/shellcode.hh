#include <linux/types.h>
#include <variant>
#include <tuple>
#include <vector>
#include <memory>
#include <type_traits>
#include "./utils.hh"
#include "./mem.hh"

#ifndef SHELLCODE_HH
#define SHELLCODE_HH
typedef std::variant<void*, __u64, __u8*, char*, const char*> sc_raw_var_t;
typedef std::tuple<sc_raw_var_t, __u64> sc_tuple_t;
struct sc_var_t : sc_tuple_t
{
	sc_tuple_t	*tuple{dynamic_cast<sc_tuple_t*>(this)};
	sc_var_t(sc_raw_var_t sc, __u64 sz) {
		*tuple = sc_tuple_t{sc, sz};
	};
	Generic(T=void*) T get() {
		sc_raw_var_t& t = std::get<0>(*tuple);
		if (is<void*>(t)) 		return (T)(std::get<void*>(t));
		if (is<char*>(t)) 		return (T)(std::get<char*>(t));
		if (is<__u8*>(t)) 		return (T)(std::get<__u8*>(t));
		if (is<const char*>(t)) return (T)(std::get<const char*>(t));
	}
	Generic(T) bool is(sc_raw_var_t& v) {
		return std::holds_alternative<T>(v);
	}
};

class Shellcode {
	std::vector<sc_var_t>	specs;
public:
	union {
		mm_t	mm;
		__u8	*mem;
	};
	Shellcode(std::initializer_list<sc_var_t> v) : specs{v} {
		compile();
	}
	mm_t& sc() { return mm; }
private:
	mm_t *compile();
	__u64 get_sc_size();
};

#define p64(ptr)({ __u8 _n_[8]; *(__u64*)_n_ = (__u64)(ptr); _n_; })
#define p32(ptr)({ __u8 _n_[4]; *(__u32*)_n_ = (__u32)(ptr); _n_; })
#define p16(ptr)({ __u8 _n_[2]; *(__u16*)_n_ = (__u16)(ptr); _n_; })
#define p8(ptr)	({ __u8 _n_[1]; *(__u8*)_n_ = (__u8)(ptr); _n_; })
#endif
