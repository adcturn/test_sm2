#include "senc_des.h"
#include "libsenc.h"
#include "senc_assist.h"
#include <openssl/des.h>
#if defined(linux) || defined(__linux__)
#include <string.h>
#endif

//Xor procedure
void API_CalXor(unsigned char *src1, unsigned char *src2, unsigned int len)
{
	unsigned int i;
	for(i=0; i<len; i++)
	{
		src1[i] = src1[i]^src2[i];
	}
}

//*������API_calculateMAC()
//*���ܣ�����MAC||Calculate MAC
//*������unsigned char*		srcBuf				//Դ����
//		unsigned int		len					//Դ���ݳ���
//		unsigned char*		key					//������Կ
//		unsigned char*		init				//��ʼ����
//*���ڣ�2016/10/28
//by Wangjf
unsigned int API_calculateMAC(unsigned char *srcBuf, unsigned int len, unsigned char *key, unsigned char *init)
{
	unsigned int blockNum = (len%8);
	unsigned int ucStatus = SENC_SUCCESS;
	DES_cblock Deskey;
	DES_key_schedule KeySchedule;

	//source data should be 8-timed, fill the rest in 0x20
	if(blockNum != 0x00)
	{
		memset(srcBuf+len,0x20,(8-blockNum));
		len += (8-blockNum);
	}
	blockNum = (len>>3);

	//Xor loop
	while(blockNum)
	{
		memcpy(Deskey,key,8);
		DES_set_key_unchecked(&Deskey,&KeySchedule);

		API_CalXor(srcBuf, init, 8);

		DES_ecb_encrypt ((const_DES_cblock *)srcBuf,(DES_cblock *)init,&KeySchedule,DES_ENCRYPT);
// 		if(ucStatus != SENC_SUCCESS)
// 			return ucStatus;
		srcBuf += 8;
		blockNum--;
	}
	return ucStatus;
}
