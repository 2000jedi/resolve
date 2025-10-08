all: src build test

build: src
	mkdir -p build
	cd build && cmake ../src && make -j4

clangformat: src
	cd build && make clangformat

clean: build
	rm -rf build
