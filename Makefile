.PHONY: all

all: build clean

dependency:
	sudo apt install iptables -y
	sudo apt install conntrack -y
    git clone https://github.com/FlatStdlib/Stdlib.git
	git clone https://github.com/FlatStdlib/fsl.git
	cd Stdlib && sudo make && cd .
	rm -r ../Stdlib ../fsl

build:
	gcc fw.c src/*.c -c -ffunction-sections -fdata-sections -nostdlib -ffreestanding -ggdb
	ld --no-relax --gc-sections -o t *.o /usr/lib/loader.o /usr/lib/libfsl.a
# 	fsl --output t fw.c src/*.c --cflags -ggdb

clean:
	rm -rf *.o