.PHONY: all

CC = gcc

SRC_DAEMON = $(wildcard src/daemon/*.c)
SRC_EBPF = $(wildcard src/ebpf/*.c)

DAEMON = daemon
ECC = ./ecc

ECLI = ./ecli

EBPF = package.json

SKEL = include/check.skel.h
HEADER = include/vmlinux.h
OUTPUT = output/

all: build

$(EBPF): build

$(ECC):
	@wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc -O $(ECC)
	@chmod +x ${ECC}

$(ECLI):
	@wget https://aka.pw/bpf-ecli -O ecli && chmod +x $(ECLI)

$(HEADER):
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(HEADER)

build: $(ECC) $(ECLI) $(SRC_EBPF) $(HEADER) $(SRC_DAEMON)
	$(ECC) $(SRC_EBPF) -o $(OUTPUT)
	@bpftool gen skeleton $(OUTPUT)/check.bpf.o > $(SKEL)
	$(CC) $(SRC_DAEMON) -o $(DAEMON) -I include/ -lbpf -lm

clean:
	rm -f $(SRC)/*.o $(OUTPUT)/*.json $(OUTPUT)/* $(SKEL) $(DAEMON)

fclean: clean
	rm  $(ECLI) $(ECC) $(HEADER)