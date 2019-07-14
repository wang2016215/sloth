
#include "sm3hash.h"
#include "include/openssl/ossl_typ.h"
#include "include/openssl/evp.h"
#include "log.h"
int hexEncode(const char *input, int input_len, unsigned char *hexStr);


int hexDecode(unsigned char *hexStr,unsigned char *output);

