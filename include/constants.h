#ifndef CONSTANTS_H
#define CONSTANTS_H


/* Header field identifiers, magic numbers, etc. In reversed order because of little endian CPU */
#define ENEncryptoHeader               0x3145504d // 'MPE1'
#define ENHeaderLocalFile              0x434c4448 // 'HDLC'
#define ENHeaderDirectory              0x52444448 // 'HDDR'
#define ENHeaderLocator                0x54434c48 // 'HLCT'
#define ENHeaderElementFileType        0x50595446 // 'FTYP'
#define ENHeaderElementFileSize        0x5a495346 // 'FSIZ'
#define ENHeaderElementFilePath        0x54415046 // 'FPAT'
#define ENHeaderElementFilePerm        0x4d525046 // 'FPRM'
#define ENHeaderElementFileOwner       0x4e574f46 // 'FOWN'
#define ENHeaderElementFileGroup       0x50524746 // 'FGRP'
#define ENHeaderElementFileMDat        0x54444d46 // 'FMDT'
#define ENHeaderElementFileCDat        0x54444346 // 'FCDT'
#define ENHeaderElementFileUTI         0x49545546 // 'FUTI'
#define ENHeaderElementFileHMAC        0x434d4846 // 'FHMC'
#define ENHeaderElementFileFlags       0x474c4646 // 'FFLG'
#define ENHeaderElementFileCSize       0x5a534346 // 'FCSZ'
#define ENHeaderElementLinkDestination 0x4b4e4c46 // 'FLNK'
#define ENHeaderElementExAttrs         0x41584546 // 'FEXA'
#define ENHeaderElementExSecOptions    0x53584546 // 'FEXS'
#define ENHeaderElementFileLocator     0x54434c46 // 'FLCT'
#define ENHeaderElementPadding         0x4e445046 // 'FPDN'
#define ENHeaderElementDirLocator      0x54434c44 // 'DLCT'
// #define ENHeaderElementDirSize      0x5a495344 // 'DSIZ'
#define ENHeaderElementDirFlags        0x474c4644 // 'DFLG'
#define ENHeaderElementMasterSalt      0x544c534d // 'MSLT'
#define ENHeaderElementDirLocatorSize  0x5a534c44 // 'DLSZ'
#define ENHeaderElementDirLocatorVer   0x52564c44 // 'DLVR'
#define ENHeaderElementPasswordHint    0x4e485350 // 'PSHN'
#define ENHeaderElementArchivePreview  0x56575250 // 'PRWV'
#define ENHeaderElementDirHMAC         0x434d4844 // 'DHMC'

// reserved encrypted field for DirLocator. Used to check password.
#define ENHeaderElementaDirLocatorR1 0x3145565245534552 // 'RESERVE1'


#define ENHeaderFileTypeRegular   0x00
#define ENHeaderFileTypeDirectory 0x01
#define ENHeaderFileTypeSymLink   0x02

#define ENFlagEncryptFiles     0x01
#define ENFlagEncryptDirectory 0x02
#define ENFlagHmacFiles        0x04
#define ENFlagHmacDirectory    0x08
#define ENFlagCompressFiles    0x10

#define ENFlagAES128 0x01
#define ENFlagAES192 0x02
#define ENFlagAES256 0x03

#define ENCR_BLOCK_SIZE 16
#define ENCR_BASE_KEY_SIZE 16
#define ENCR_PBKDF2_ROUNDS 4096
#define ENCR_SALT_LENGTH 16
#define ENCR_HMAC_KEY_LEN 16
#define ENCR_HMAC_LEN 32 // 256 bit
#define OUTPUT_BLOCK_SIZE 16384 // 16 * 1024, size of blocks to read from/write to files.


#endif