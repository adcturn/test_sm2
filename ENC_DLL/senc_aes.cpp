#include "libsenc.h"
#include "senc_aes.h"
#include "senc_assist.h"
#include <openssl/aes.h>
#include "senc_error.h"
#if defined(linux) || defined(__linux__)
#include <string.h>
#endif



//*������SENC_AES_Dispersion()
//*���ܣ���Կ��ɢ�������Ự��Կ||Key dispersion and generate session key
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char*		RandNum						//��ʾ�����
//*���ڣ�2016/10/27
//by Wangjf
unsigned int SENC_AES_Dispersion(SENCryptCard* sencDev,			//���ܿ��豸handle
								 unsigned char* RandNum)			//��ʾ�����
{
	AES_KEY aeskey;
	unsigned char ciphertext[16]={0};
	unsigned char dispersion[16];

	//Parameters check
	if(!sencDev||!RandNum||!((KeyData*)(sencDev->DevCtx))->CommKey)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"Key Dispersion: Parameter Null");//SENC_ERROR_PARAMETER_ERROR;

	//key dispersion.
	//4 bytes Rand + 4 bytes 0x20
	memcpy(dispersion,RandNum,4);
	memset(dispersion+4,0x20,4);

	//fill last 8bytes by bits inversion
	for(int i=0;i<8;i++){
		dispersion[i+8]=~dispersion[i];
	}

	//encrypt by CommKey and SessionKey generated
	AES_set_encrypt_key(((KeyData*)(sencDev->DevCtx))->CommKey,SENC_AES_128,&aeskey);
	AES_ecb_encrypt(dispersion,ciphertext,&aeskey,AES_ENCRYPT);

	memcpy(((KeyData*)(sencDev->DevCtx))->SessionKey,ciphertext,16);

	return SENC_SUCCESS;
}


//*������SENC_AES_CmdDataEncrypt()
//*���ܣ�����֡AES����||Encrypt cmd frame by aes
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char*		pucCmdData					//�������������
//		unsigned char*		pucCryptograph				//�������
//		unsigned int*		DataLength					//�������
//*���ڣ�2016/10/28
//by Wangjf
unsigned int SENC_AES_CmdDataEncrypt(SENCryptCard* sencDev,				//���ܿ��豸handle
									 unsigned char* pucCmdData,			//�������������
									 unsigned char* pucCryptograph,		//�������
									 unsigned int* DataLength)			//�������
{
	AES_KEY aeskey;
	unsigned int length,nlen;
	unsigned int i=0;

	unsigned char plaintext[SENC_BUFFER_SIZE]={0};

	//parameters check
	if(!sencDev||!pucCmdData||!pucCryptograph||!DataLength)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"Comm Encryption: Parameter Null");//SENC_ERROR_PARAMETER_ERROR;

	//data reading
	memset(plaintext,0x00,sizeof(plaintext));
	length=((pucCmdData[1]<<8)|pucCmdData[2])+3;
	memcpy(plaintext,pucCmdData,length);

	//packing by every 16bytes
	nlen=length;
	length=(nlen/16+(nlen%16?1:0))*16;

	//using session key
	AES_set_encrypt_key(((KeyData*)(sencDev->DevCtx))->SessionKey,SENC_AES_128,&aeskey);

	//encryption loop
	while(i < length){
		AES_ecb_encrypt(plaintext+i,pucCryptograph+i,&aeskey,AES_ENCRYPT);
		i+=SENC_AES_BLOCK_SIZE;
	}

	*DataLength=length;

	return SENC_SUCCESS;
}



//*������SENC_AES_CmdDataDecrypt()
//*���ܣ�ʹ�ûỰ��Կ��������������||Decrypt data by session key
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char*		pucCryptograph				//�������������
//		unsigned char*		pucDecryptedData			//�������
//		unsigned int		DataLength					//���볤��
//*���ڣ�2016/10/28
//by Wangjf
unsigned int SENC_AES_CmdDataDecrypt(SENCryptCard*	sencDev,				//���ܿ��豸handle
									 unsigned char* pucCryptograph,			//�������������
									 unsigned char* pucDecryptedData,		//�������
									 unsigned int	DataLength)				//���볤��
{
	AES_KEY aeskey;
	unsigned int i=0;

	unsigned char plaintext[SENC_BUFFER_SIZE]={0};
	//parameter check
	if(!sencDev||!pucCryptograph||!pucDecryptedData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"Comm Decryption: Parameter Null");//SENC_ERROR_PARAMETER_ERROR;

	memset(plaintext,0x00,sizeof(plaintext));

	//using session key
	AES_set_decrypt_key(((KeyData*)(sencDev->DevCtx))->SessionKey,SENC_AES_128,&aeskey);

	//decryption loop
	while(i < DataLength){
		AES_ecb_encrypt(pucCryptograph+i,plaintext+i,&aeskey,AES_DECRYPT);
		i+=SENC_AES_BLOCK_SIZE;
	}

	memcpy(pucDecryptedData,plaintext,DataLength);

	return SENC_SUCCESS;
}

//*������SENC_AES_DHPrivCal()
//*���ܣ�����ͨ����Կ||Calculate communication key
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char*		ucInEncKey					//����ͨ����Կ
//*���ڣ�2016/10/27
//by Wangjf
unsigned int SENC_AES_DHPrivCal(SENCryptCard* sencDev,				//���ܿ��豸handle
								unsigned char* ucInEncKey)			//����ͨ����Կ
{
	AES_KEY aeskey;
	unsigned char ciphertext[16]={0};
	unsigned char dispersion[16];

	if(!sencDev||!ucInEncKey)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"Comm Key: Parameter Null");//SENC_ERROR_PARAMETER_ERROR;

	//using DH key 4bytes + 4bytes 0x00
	memcpy(dispersion,((KeyData*)(sencDev->DevCtx))->DHPrivKey,4);
	memset(dispersion+4,0x00,4);
	//fill last 8bytes by bit inversion
	for(int i=0;i<8;i++){
		dispersion[i+8]=~dispersion[i];
	}

	//decrypt data and get communication key
	AES_set_decrypt_key(dispersion,SENC_AES_128,&aeskey);
	AES_ecb_encrypt(ucInEncKey,ciphertext,&aeskey,AES_DECRYPT);

	memcpy(((KeyData*)(sencDev->DevCtx))->CommKey,ciphertext,16);

	return SENC_SUCCESS;
}
