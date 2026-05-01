.PHONY: all

all: dependencies install

dependencies:
	sudo apt install iptables -y
    sudo apt install conntrack -y

install:
	ls /usr/lib/libfsl.a &>1 /dev/null && echo "FSL IS INSTALLED" || echo $(git clone https://github.com/FlatStdlib/Stdlib.git && git clone https://github.com/FlatStdlib/fsl.git; cd Stdlib && sudo make && cd .; rm -r ../Stdlib ../fsl ../1)
	fsl --output t fw.c src/*.c --cflags -ggdb
