obj = main.o md5.o sally.o 1dlsd.o utils.o shellcode.o entry.o bblock.o
BDIR = ./build
CFLAGS = -w -g
LDFLAGS = -lelflib -lx86disass -lelfcore -lreadline
PWD = "$(shell pwd)"

all: $(obj)
	@g++ $(addprefix $(BDIR)/,$(obj)) -o main $(LDFLAGS)
	@./main ./specimen/a

%.o: %.cc
	@g++ -c $< -o $(BDIR)/$@ $(CFLAGS)

%.o: core/%.cc
	@g++ -c $< -o $(BDIR)/$@ $(CFLAGS)

%.o: core/%.asm
	@nasm -f elf64 $< -o $(BDIR)/$@

clean:
	rm -rf $(BDIR) main
