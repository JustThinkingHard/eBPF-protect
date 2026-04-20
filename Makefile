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
WHITELIST = whitelist.txt
BLACKLIST = blacklist.txt

all: build

$(EBPF): build

$(ECC):
	@wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc -O $(ECC)
	@chmod +x ${ECC}

$(ECLI):
	@wget https://aka.pw/bpf-ecli -O ecli && chmod +x $(ECLI)

$(HEADER):
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(HEADER)

$(WHITELIST):
	@echo "[*] Profiling system and building Zero-Trust Whitelist..."
	@find -L /usr/bin /bin /sbin /usr/sbin /usr/libexec /usr/local/bin /usr/lib/apt/methods /usr/lib/git-core /usr/lib/firefox /usr/share/code /opt /snap/*/current/usr/bin -type f -executable 2>/dev/null > whitelist.txt || true

$(BLACKLIST):
	@touch blacklist.txt

build: $(ECC) $(ECLI) $(SRC_EBPF) $(HEADER) $(SRC_DAEMON) $(WHITELIST) $(BLACKLIST)
	$(ECC) $(SRC_EBPF) -o $(OUTPUT)
	@bpftool gen skeleton $(OUTPUT)/check.bpf.o > $(SKEL)
	@$(CC) $(SRC_DAEMON) -o $(DAEMON) -I include/ -lbpf -lm
	@echo "[*] Ready to launch EDR."

clean:
	@rm -f $(SRC)/*.o $(OUTPUT)/*.json $(OUTPUT)/* $(SKEL) $(DAEMON)
	@echo "[*] Cleaning files."

fclean: clean
	@rm  $(ECLI) $(ECC) $(HEADER) $(WHITELIST) $(BLACKLIST)