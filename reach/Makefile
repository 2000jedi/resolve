.PHONY: all clean build

all: build

build: src lib
	cmake -B build && cd build && make -j$(nproc)

# clangformat: src
# 	cd build && make clangformat

clean:
	rm -rf build
