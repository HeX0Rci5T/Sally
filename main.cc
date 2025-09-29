#include <linux/types.h>
#include <typeinfo>
#include "./include/1dlsd.hh"
#include "./include/sally.hh"
#include "./include/shellcode.hh"
#include <x86disass/disass.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <regex>

static void test() {
	mm_t mm;
	static_assert((void*)&mm.mem == (void*)&mm, "fuck");
}

__attribute__((constructor)) void _init_() {
	struct rlimit x = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_AS, &x);
	test();
}

namespace lsd = _1Dlsd;
class _x_ : public _1Dlsd::pass_t {
public:
	_x_() = default;

	void x(ElfX_Phdr *ph) { puts("!"); }

	lsd::err_t _init_() {
		lsd->insert(lsd::Phdr, 10, &lsd->elf.phdr, &lsd->elf.phdr.tab[1]);
		lsd->insert(lsd::Phdr, 11, &lsd->elf.phdr, &lsd->elf.phdr.tab[7], 3);
		for (auto& tab : lsd->elf.sym_tabl)
			lsd->insert(lsd::Sym, 0, &tab, tab.tab, 1);
		lsd->output("./oi.fuck.off.cunt");
		return lsd::err_t{};
	}
	void for_bblock(void *mem, __u64 off, __u64 size);
};

void _x_::for_bblock(void *mem, __u64 off, __u64 size) {
	// hexdump(mem, size);
	// pf(GRN " -~+~=*=~+~-- " BGBLACK BRED" ["BCYAN"0x%06lx" BRED"] " CRST BYLW"  ~>  " BGRN"0x%04lx" GRN  " --~+~=*=~+~- " CRST"\n", off, size);
	// lsd->d.iter(mem, size, [](__u64 i, insn_t& in) {
	// 	in.Print();
	// });
}

lsd::err_t fn1(lsd_ctx& ctx) {
	__u64 i = 0, l = 0;
	p(CRST"------  -~=+-=" BGRN" Offset " CRST"=-+=~- ++ -~=+-=" BGRN" Memory " CRST"=-+=~-  ------"CRST);
	foreach_phdr(&ctx.elf, _p) {
		pf(	" [" BGRN"%02lu"CRST "]  %c%c"BRED"%c" CRST" - "  BGBLACK  "0x%08lx" CRST" / " BGBLACK "0x%06lx"CRST"  |  "
			BGBLACK  "0x%08lx" CRST" / " BGBLACK "0x%06lx" CRST "\n", 

			i++,
			(_p->p_flags & PF_R) ? 'R' : '-',
			(_p->p_flags & PF_W) ? 'W' : '-', 
			(_p->p_flags & PF_X) ? 'X' : '-',
			_p->p_offset, _p->p_filesz,
			_p->p_vaddr, _p->p_memsz);
	}
	p("   ----+~-~=*=~-~+ +~-~=*=~-~+ +~-~=*=~-~+ +~-~=*=~-~+----");
	foreach_phdr(&ctx.elf, _p) {
		pf(" [" BGRN"%02lu"CRST "] - ", l++);
		foreach_shdr(&ctx.elf, sec) if (_p->hasOff(sec->sh_offset)) {
			__u8 *name = &ctx.elf.sec.str[sec->sh_name];
			if (!!l) pf(" ; ");
			pf(BGBLACK"%s(%s%s%s)"CRST, (!name || !*name ? (__u8*)"[???]" : name),
				(sec->sh_flags & SHF_EXECINSTR) ? BWHT"E"CRST BGBLACK : "-",
				(sec->sh_flags & SHF_WRITE) ? BWHT"W"CRST BGBLACK : "-",
				(sec->sh_flags & SHF_ALLOC) ? BWHT"A"CRST BGBLACK : "-");
		}
		p("");
	}
	p("------+~-~=*=~-~+ +~-~=*=~-~+ +~-~=*=~-~+ +~-~=*=~-~+------");
	return lsd::err_t{};
}

typedef lsd::err_t(*cmd_fn_t)(lsd_ctx& ctx);

lsd::err_t fn_disass(lsd_ctx& ctx) {
	for (auto& x : ctx.args) std::cout << x << std::endl;
	return lsd::err_t{};
}

lsd::err_t fn_exit(lsd_ctx& ctx) {
	exit(0);
	// return lsd::err_t{};
};

lsd::err_t fn_dixiland(lsd_ctx& ctx) {
    __u8 sz     = 0;
    bool in     = false;
    __u64 num   = (!!ctx.args[0].size()) ? util::strtoull(ctx.args[0]) : 1;
    void *addr  = (void*)(util::strtoull(ctx.args[2]));
    switch (*ctx.args[1].c_str()) {
        case 'b': sz = 1;       break;
        case 'd': sz = 2;       break;
        case 'x':
        case 'w': sz = 4;       break;
        case 'q': sz = 8;       break;
        case 'i': in = true;    break;
        default:
            return lsd::err_t{lsd::Error::BadOption};
    }

    if (!!in && ctx.elf.size > (__u64)(addr+num)) {
        Disass().iter(ctx.elf.off(addr), -1, [&](__u64 i, insn_t& in) {
        	if (!num--) throw DisassQuit;
        	if (in.IsNull() || !in.Mnemo()) {
        		p("  ------- ");
        		return;
        	}
    		pf(BGBLACK" %s "CRST"   ", in.Mnemo());
        	for (__u64 i = 0; i < in.OperCount(); i++) {
        		if (!!i) pf(", ");
        		pf("%s", in[i]->Str());
        	}
        	p("");
        });
    } else {
        hexdump(ctx.elf.off(addr), num * sz);
    }
    for (auto& x : ctx.args) std::cout << x << std::endl;
    return lsd::err_t{};
}

// using R = std::regex;
static std::vector<std::tuple<std::vector<const char*>, cmd_fn_t>> commands = {
	{{"phdr", "l"},	fn1},
	{{"x/([0-9]{0,8})([ibwdqx]{1}) ([x0-9a-fA-F]{1,18})(([\w\s\t ]*([+-]{0,1})[\w\s\t ]*([x0-9a-fA-F]{1,18}))*)"},	fn_dixiland},
	{{"q", "quit", "exit"}, fn_exit}
};

Sally::err_t fn() {
	p("FUCK YOU BITCH !");
	return Sally::err_t{};
}

int main(int argc, char *argv[], char *envp[]) {
	if (argc != 2) return -1;
	// p(BGBLACK BCYAN " _1Dlsd " BCYAN CRST " / " BGBLACK BGRN " Sally " BCYAN CRST);
	pf(BGRN "                ███    ███          \n" CRST);
	pf(BGRN "   ▓███▒          █      █          \n" CRST);
	pf(BGRN "  █▓  ░█          █      █          \n" CRST);
	pf(BGRN "  █      ░███░    █      █    █░  █ \n" CRST);
	pf(BGRN "  █▓░    █▒ ▒█    █      █    ▓▒ ▒▓ \n" CRST);
	pf(BGRN "   ▓██▓      █    █      █    ▒█ █▒ \n" CRST);
	pf(BGRN "      ▓█ ▒████    █      █     █ █  \n" CRST);
	pf(BGRN "       █ █▒  █    █      █     █▓▓  \n" CRST);
	pf(BGRN "  █░  ▓█ █░ ▓█    █░     █░    ▓█▒  \n" CRST);
	pf(BGRN "  ▒████░ ▒██▒█    ▒██    ▒██   ▒█   \n" CRST);
	pf(BGRN "                               ▒█   \n" CRST);
	pf(BGRN "                               █▒   \n" CRST);
	p("  -~=+=["BGRN "A DynBinInstr kit     ██" CRST"  ]=+=~------");
	p("    ~+=["BGRN "Made by " BCYAN BGBLACK "~HeX0Rci5T~"CRST BGRN CRST"       ]=+~ ----");
	p("     ~=["BGRN "Welcome to the mindfuck " CRST"  ]=~ ---");
	p("");
	std::string cmd;
    using_history();
    lsd_ctx ctx = {
    	.elf = Elf(argv[1]),
    };
    while(!!((cmd = std::string{readline(BGRN" > "CRST)}).c_str())) {
        add_history(cmd.c_str());
        for (auto& [rx_arr, fn] : commands) {
        	for (auto& rx : rx_arr) {
	        	ctx.args = util::regexp(rx, cmd);
	    		if (!!ctx.args.size()) {
		    		fn(ctx);
		    		goto next;
	    		}
        	}
        }
    	next:
    }
	char *args[] = {argv[1], NULL};
	auto q = Sally::Sally(argv[1]);
	mm_t& sc = Shellcode({
		{ "\xcc", 1 },
		{ p64(0xdeadbeefcafedead), 8 }
	}).sc();
	q.hook("libc.so.6", "__libc_start_main", fn);
	q.hook("_start", sc.mem, sc.sz);
	q.run(2, args, envp);
	// _x_ x;
	// _1Dlsd::_1Dlsd lsd(&x, "./specimen/a");
}
