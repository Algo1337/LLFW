.PHONY: all

all: install

install:
	ls /usr/lib/libfslf.a &>1 /dev/null && echo "FSL IS INSTALLED" || echo $(git clone https://github.com/FlatStdlib/Stdlib.git && git clone https://github.com/FlatStdlib/fsl.git; cd Stdlib && sudo make && cd .; rm -r ../Stdlib ../fsl ../1)
	fsl --output t fw.c --cflags -ggdb
