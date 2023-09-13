# Building C-ENCryptor


## Setup Dependencies & Environment

1. OpenSSL 3
   * **you need to install OpenSSL development package (libssl-dev) by yourself**
   * Although C-ENCryptor is [backward compatible with OpenSSL version < 3](#backward-compatible-with-openssl-version--3), we still recommend you to use OpenSSL 3 for better security and support.
   * [install on windows](https://slproweb.com/products/Win32OpenSSL.html)
   * [install on ubuntu 22.04 and above](https://linuxhint.com/install-openssl-libraries-on-ubuntu/)
     * [for ubuntu 20.04 and below](https://github.com/bkw777/mainline/wiki/Install-libssl3)
   * [install on MacOS](https://formulae.brew.sh/formula/openssl@3)
2. ZLib
   * ZLib repository is included as a submodule of this repository
3. Make sure you have [cmake](https://cmake.org/) install in your system
4. Finally, **git clone this repository RECURSIVELY** with following command

```sh
git clone --recursive https://github.com/Gavin1937/C-ENCryptor
```


## Building C-ENCryptor Library

You can build C-ENCryptor library using cmake with following commands

```sh
cd C-ENCryptor
mkdir build
cmake -S . -B build
cmake --build ./build/
```


## Building Shared / Static Library

By default, C-ENCryptor will be build into a shared library

You can use cmake build option to change that:

```sh
cmake -S . -B .\build\ -DCE_BUILD_SHARED_LIBS=ON
```

By adding option `-DCE_BUILD_SHARED_LIBS=ON` after above cmake command, you can set C-ENCryptor to build as a shared library.

If you change that option to `-DCE_BUILD_SHARED_LIBS=OFF`, C-ENCryptor will be build into a static library.

You can also set this cmake option inside your CMakeLists.txt, checkout [demo/CMakeLists.txt](demo/CMakeLists.txt) for detail

**Remember to rebuild cmake project after changing cmake option**


## Building Demo Application

checkout [instruction inside demo folder](demo/README.md)


## Try out C-ENCryptor with Docker

You can build C-ENCryptor and demo application with Docker:

```sh
docker build -t cencryptor .
```

Docker will build & compile C-ENCryptor library and demo application inside an image.

After that, you can play with C-ENCryptor by launching a container from this image.

```sh
docker run -it --rm --name C-ENCryptor-demo cencryptor
```


## Backward Compatible With OpenSSL version < 3

C-ENCryptor will automatically detect OpenSSL version and enable/disable OpenSSL backward compatible mode

But you can override it with cmake option.

```sh
cmake -S . -B .\build\ -DCE_OSSL_COMPATIBLE_MODE=ON
```

or

```sh
cmake -S . -B .\build\ -DCE_OSSL_COMPATIBLE_MODE=OFF
```

This is a compiler flag & cmake option, so you can add it by yourself.

**Remember to rebuild cmake project after changing cmake option**

**When you build C-ENCryptor inside a docker container with OpenSSL versoin < 3, you may need to rebuild it manually**
