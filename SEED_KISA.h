
#ifndef SEED_H
#define SEED_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TYPE_DEFINITION
    #define TYPE_DEFINITION
    #if defined(__alpha)
        typedef unsigned int        DWORD;		/* unsigned 4-byte data type */
        typedef unsigned short      WORD;		/* unsigned 2-byte data type */
    #else
        typedef unsigned long int   DWORD;		/* unsigned 4-byte data type */
        typedef unsigned short int  WORD;		/* unsigned 2-byte data type */
    #endif
    typedef unsigned char           BYTE;		/* unsigned 1-byte data type */
#endif


#define NoRounds         16				/* номер раундов    */
#define NoRoundKeys      (NoRounds*2)			/* номер раундовых ключей */
#define SeedBlockSize    16    				/* длина блока в байтах    */
#define SeedBlockLen     128   				/* длина блока в битах     */


/* макросы */

/* макросы для левых или правых ротаций */
#if defined(_MSC_VER)
    #define ROTL(x, n)     (_lrotl((x), (n)))		/* левая  */
    #define ROTR(x, n)     (_lrotr((x), (n)))		/* правая */
#else
    #define ROTL(x, n)     (((x) << (n)) | ((x) >> (32-(n))))		/* левая  */
    #define ROTR(x, n)     (((x) >> (n)) | ((x) << (32-(n))))		/* правая */
#endif

/* макросы для endianess */
#define EndianChange(dwS)                       \
    ( (ROTL((dwS),  8) & (DWORD)0x00ff00ff) |   \
      (ROTL((dwS), 24) & (DWORD)0xff00ff00) )


void SeedEncrypt(		/* функция шифрования */
		BYTE *pbData, 				/* [in,out]	информация для шифрования        */
		DWORD *pdwRoundKey			/* [in]			раундовые ключи для шифрования */
		);

void SeedDecrypt(		/* то же самое для дешифрования */
		BYTE *pbData,
		DWORD *pdwRoundKey
		);

void SeedRoundKey(
		DWORD *pdwRoundKey, 			/* [out]	раундовые ключи для шифрования или дешифрования */
		BYTE *pbUserKey				/* [in]			секретный ключ пользователя                        */
		);

#endif
