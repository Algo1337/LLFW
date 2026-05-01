.PHONY: all

all: install build

dependencies:
	sudo apt install iptables -y
    sudo apt install conntrack -y
	git clone https://github.com/FlatStdlib/Stdlib.git
	git clone https://github.com/FlatStdlib/fsl.git
	cd Stdlib && sudo make && cd .
	rm -r ../Stdlib ../fsl

build:
	fsl --output t fw.c src/*.c --cflags -ggdb
