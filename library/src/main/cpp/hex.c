
#include "sm3hash.h"
#include "include/openssl/ossl_typ.h"
#include "include/openssl/evp.h"
#include "log.h"
#include <stddef.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <memory.h>


char *buf2hexstr(const unsigned char *buffer, long len)
{
    static const char hexdig[] = "0123456789ABCDEF";
    char *tmp, *q;
    const unsigned char *p;
    int i;

    if (len == 0)
        return OPENSSL_zalloc(1);

    if ((tmp = OPENSSL_malloc(len * 3)) == NULL) {
        CRYPTOerr(CRYPTO_F_OPENSSL_BUF2HEXSTR, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    q = tmp;
    for (i = 0, p = buffer; i < len; i++, p++) {
        *q++ = hexdig[(*p >> 4) & 0xf];
        *q++ = hexdig[*p & 0xf];
        //*q++ = ':';
    }
    //q[-1] = 0;
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(tmp, tmp, q - tmp - 1);
#endif

    return tmp;
}


unsigned char *hexstr2buf(const char *str, long *len)
{
    unsigned char *hexbuf, *q;
    unsigned char ch, cl;
    int chi, cli;
    const unsigned char *p;
    size_t s;

    s = strlen(str);
    if ((hexbuf = OPENSSL_malloc(s >> 1)) == NULL) {
        CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (p = (const unsigned char *)str, q = hexbuf; *p; ) {
        ch = *p++;
//        if (ch == ':')
//            continue;
        cl = *p++;
        if (!cl) {
            CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF,
                      CRYPTO_R_ODD_NUMBER_OF_DIGITS);
            OPENSSL_free(hexbuf);
            return NULL;
        }
        cli = OPENSSL_hexchar2int(cl);
        chi = OPENSSL_hexchar2int(ch);
        if (cli < 0 || chi < 0) {
            OPENSSL_free(hexbuf);
            CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, CRYPTO_R_ILLEGAL_HEX_DIGIT);
            return NULL;
        }
        *q++ = (unsigned char)((chi << 4) | cli);
    }

    if (len)
        *len = q - hexbuf;
    return hexbuf;
}







int hexEncode(const char *input, int input_len, unsigned char *hexStr)
{

    //const char HexCode[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    unsigned char *hexStr1 = buf2hexstr(input,input_len);

    memcpy(hexStr,hexStr1,input_len*2);

    LOGD("hexStr->%s",hexStr);
//
//    for (int i = 0; i <input_len ; ++i){
//        hexStr[2*i]=HexCode[input[i] / 16];
//        hexStr[2*i+1]=HexCode[input[i] % 16];
//    }
//
//    hexStr[input_len*2+1]='\0';

   // LOGE(" %s ",hexStr);

    return 0;
}


int hexDecode(unsigned char *hexStr,unsigned char *output){


    int binSize = 0;
    unsigned char *output1 = hexstr2buf(hexStr,&binSize);

    memcpy(output,output1,binSize);

    //LOGD("bufStr->%s",output);

    return binSize;
}










