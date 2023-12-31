
# Demonstration for C-ENCryptor library

## Folder Structure

```
./demo
    |
    ---- CMakeLists.txt
    |
    |
    ---- demo.c
    |
    |
    ---- data/
            |
            |
            ---- encrypted/
            |
            |
            ---- raw_data/
            |
            |
            ---- raw_folder/
            |
            |
            ---- password_for_all.txt
```

* [CMakeLists.txt](CMakeLists.txt) contains all the all the cmake setup scripts for integrating C-ENCryptor library to another cmake project.
* [demo.c](demo.c) demonstrates how to use C-ENCryptor API
* [data/](data/) contains all the testing files encrypted with Encrypto for windows (ver: 1.0.1, installer MD5: 782e39244e3bb0e1d64e1bb2dc4d1aa4)
* [data/encrpted/](data/encrpted/) contains all the .crypto archive files
* [data/raw_data/](data/raw_data/) contains all the raw file used in encryption
* [data/raw_folder/](data/raw_folder/) is a folder structure encrypted into [data/encrypted/encrypted_folder.crypto](data/encrypted/encrypted_folder.crypto) file
* [data/password_for_all.txt](data/password_for_all.txt) contains the password for all .crypto archive files


## Building Demo Application

Once you have [all the dependencies for C-ENCryptor library](../BUILD.md) ready

Assuming you are in `demo` folder, you can run following commands to build the demo application:

```sh
mkdir build
cmake -S . -B build
cmake --build ./build/
```

**cmake will automatically create a folder `output` for you to play with**

Demo application will take 2 arguments `[archive_filepath]` and `[output_folderpath]`

and then try to decrypt `[archive_filepath]`, print all the metadata inside it and

write decrypted preview image and file content to `[output_folderpath]`

Example:

```sh
./build/bin/demo ./data/encrypted/encrypted_img01.crypto ./output/
```
