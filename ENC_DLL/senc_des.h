#ifndef LIBSENC_SENC_DES_H_
#define LIBSENC_SENC_DES_H_

#include "libsenc.h"

//*������API_calculateMAC()
//*���ܣ�MAC����||Calculate MAC
unsigned int API_calculateMAC(unsigned char *srcBuf, unsigned int len, unsigned char *key, unsigned char *init);


#endif //LIBSENC_SENC_DES_H_