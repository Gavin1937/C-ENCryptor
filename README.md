
# C-ENCryptor

a cross-platform re-implementation of the core library from [MacPaw/ENCryptor](https://github.com/MacPaw/ENCryptor) encrypting/decrypting software.

The original repository is written in Objective-C and only for MAC OS, I decide to re-implement it with C so I can port it to other platforms.


## Dependencies

* OpenSSL
  * **you need to install OpenSSL development package by yourself**
  * [install in windows](https://slproweb.com/products/Win32OpenSSL.html)
  * [install in ubuntu](https://linuxhint.com/install-openssl-libraries-on-ubuntu/)
  * [install in macos](https://medium.com/@timmykko/using-openssl-library-with-macos-sierra-7807cfd47892)
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

