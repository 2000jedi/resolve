all: src build

build: src
	mkdir -p build
	cd build && cmake .. && make -j4

clangformat: src
	cd build && make clangformat

clean: build
	rm -rf build
