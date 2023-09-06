
# C-ENCryptor

a cross-platform re-implementation of the core library from [MacPaw/ENCryptor](https://github.com/MacPaw/ENCryptor) encrypting/decrypting software.

The original repository is written in Objective-C and only for MAC OS, I decide to re-implement it with C so I can port it to other platforms.


## Dependencies

* OpenSSL 3
  * **you need to install OpenSSL development package by yourself**
  * **currently C-ENCryptor only support libssl3**
  * [install in windows](https://slproweb.com/products/Win32OpenSSL.html)
  * [install in ubuntu 22.04 and above](https://linuxhint.com/install-openssl-libraries-on-ubuntu/)
    * [for ubuntu 22.04 below](https://github.com/bkw777/mainline/wiki/Install-libssl3)
  * [install in macos](https://formulae.brew.sh/formula/openssl@3)
* ZLib
  * ZLib repository is included as a submodule of this repository


## Building

1. after you install OpenSSL
2. **git clone this repository RECURSIVELY**

```sh
git clone --recursive https://github.com/Gavin1937/C-ENCryptor
```

3. make sure you have [cmake](https://cmake.org/) install in your system
4. build C-ENCryptor with following commands

```sh
cd C-ENCryptor
mkdir build
cmake -S . -B build
cmake --build ./build/
```

### Building Demo

checkout [instruction inside demo folder](demo/README.md)

### Try out C-ENCryptor with Docker

You can build C-ENCryptor using Docker:

```sh
docker build -t cencryptor .
```

Docker will build & compile C-ENCryptor library and demo application inside an image.

After that, you can play with C-ENCryptor by launching a container from this image.

```sh
docker run -it --rm --name C-ENCryptor-demo cencryptor
```

### Building Shared / Static Library

By default, C-ENCryptor will be build into a shared library

You can use cmake build option to change that:

```sh
cmake -S . -B .\build\ -DCE_BUILD_SHARED_LIBS=ON
```

By adding option `-DCE_BUILD_SHARED_LIBS=ON` after above cmake command, you can set C-ENCryptor to build as a shared library.

If you change that option to `-DCE_BUILD_SHARED_LIBS=OFF`, C-ENCryptor will be build as a static library.

You can also use set this cmake option inside your CMakeLists.txt, checkout [demo/CMakeLists.txt](demo/CMakeLists.txt) for detail

**remember to recompile your project after switching**

