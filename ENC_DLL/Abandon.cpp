
/*libsenc.h
***********************************************
*������SENC_Init()
*���ܣ���ʼ�����ܰ忨���||Initialize Sense encrypt card handle
*������SENCHANDLE		IN		SencDevHandle	//����ʼ���豸ָ��
*����ֵ�������룬0Ϊ�ɹ�
*���ڣ� 2016/12/26 by Wangjf
*��ע��
***********************************************
// unsigned int SENC_Init(IN SENCHANDLE IN SencDevHandle);




*/



/* senc_rsa.cpp

#include "SENC_DLL.h"
#include "senc_usbapi.h"
#include "openssl/rsa.h"
// #include <windows.h>

//RSA��������
void setRSA2048(RSA *key, unsigned char *buffer){
	memcpy(buffer,key->p->d,SENC_RSA_PARAMETER_LEN);
	memcpy(buffer+SENC_RSA_PARAMETER_LEN,key->q->d,SENC_RSA_PARAMETER_LEN);
	memcpy(buffer+SENC_RSA_PARAMETER_LEN*2,key->dmp1->d,SENC_RSA_PARAMETER_LEN);
	memcpy(buffer+SENC_RSA_PARAMETER_LEN*3,key->dmq1->d,SENC_RSA_PARAMETER_LEN);
	memcpy(buffer+SENC_RSA_PARAMETER_LEN*4,key->iqmp->d,SENC_RSA_PARAMETER_LEN);
}

void setRSA1024(RSA *key, unsigned char *buffer){
	BIGNUM *t1,*t2,*t3;
	BN_CTX *ctx;

	t1=BN_new();
	t2=BN_new();
	t3=BN_new();
	ctx=BN_CTX_new();

	BN_one(t1);
	t1->d[0]=0x02;
	BN_one(t2);
	t2->d[0]=0x0813;

	BN_exp(t3,t1,t2,ctx);
	BN_div(t1,t2,t3,key->n,ctx);

	// 	memcpy(buffer,t1->d,SENC_RSA_C_BLOCK_SIZE);
	// 	memset(buffer+SENC_RSA_C_BLOCK_SIZE,0x00,SENC_RSA_C_FILL_SIZE);
	// 	memcpy(buffer+SENC_RSA_C_BLOCK_SIZE+SENC_RSA_C_FILL_SIZE,key->d->d,SENC_RSA_PARAMETER_LEN);
	// 	memcpy(buffer+SENC_RSA_C_BLOCK_SIZE+SENC_RSA_C_FILL_SIZE+SENC_RSA_PARAMETER_LEN,key->n->d,SENC_RSA_PARAMETER_LEN);

	memcpy(buffer, key->n->d,SENC_RSA_PARAMETER_LEN);
	memcpy(buffer+SENC_RSA_PARAMETER_LEN, key->d->d,SENC_RSA_PARAMETER_LEN);
	memcpy(buffer+2*SENC_RSA_PARAMETER_LEN,t1->d,SENC_RSA_C_BLOCK_SIZE);
	memset(buffer+SENC_RSA_PARAMETER_LEN*2+SENC_RSA_C_BLOCK_SIZE,0x00,SENC_RSA_C_FILL_SIZE);


	BN_free(t1);
	BN_free(t2);
	BN_free(t3);
	BN_CTX_free(ctx);
}

//��������

//������SENC_RSA_Transfer_2048()
//���ܣ�RSA����ͨѶ||SENCrypted communication in RSA2048
//������SENCryptCard		sencDev,						//���ܿ��豸handle
//		RSA*			rsakey,						//��Կ
//		unsigned char*	pucSendData					//������message����
// 		unsigned int	uiSendLength				//�����������ܳ���
// 		unsigned char*	pucReadData					//��������
//		unsigned int	uiReadLength				//���������ܳ���
//����:2016/10/08
//by Wangjf
extern "C" unsigned int _stdcall SENC_RSA_Transfer_2048(SENCryptCard* sencDev,					//���ܿ��豸handle
														RSA* Key,							//RSA��Կ
														unsigned char* pucSendData,			//������message����
														unsigned int uiSendLength,			//�����������ܳ���
														unsigned char* pucReadData,			//��������
														unsigned int uiReadLength)			//���������ܳ���
{
	unsigned char SendBuf[2048]={0};
	unsigned char Plaintext[1024]={0};

	unsigned int ucRet = 0;

	if(Key==NULL) return SENC_ERROR_KEY_INVALID;
	else if(uiSendLength==NULL||uiReadLength==NULL) return SENC_ERROR_PARAMETER_ERROR;

	memcpy(Plaintext,pucSendData,SENC_RSA_MESSAGE_LENGTH);

	memset(SendBuf,0x00,sizeof(SendBuf));
	setRSA2048(Key,SendBuf);

	reverse(Plaintext,SENC_RSA_MESSAGE_LENGTH);
	memcpy(SendBuf+SENC_RSA_PARAMETER_LEN*5,Plaintext,SENC_RSA_MESSAGE_LENGTH);

	ucRet = SENC_Bulk_Write(sencDev,SENC_BULK_ENDPOINT_WRITE_1K,SendBuf,uiSendLength);

	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet = SENC_Bulk_Read(sencDev,SENC_BULK_ENDPOINT_READ_1K,pucReadData,uiReadLength);


	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	reverse(pucReadData,SENC_RSA_MESSAGE_LENGTH);

	return SENC_SUCCESS;
}

//������SENC_RSA_Transfer_1024()
//���ܣ�RSA����ͨѶ||SENCrypted communication in RSA1024
//������SENCryptCard		sencDev,						//���ܿ��豸handle
//		RSA*			rsakey,						//��Կ
//		unsigned char*	pucSendData					//������message����
// 		unsigned int	uiSendLength				//�����������ܳ���
// 		unsigned char*	pucReadData					//��������
//		unsigned int	uiReadLength				//���������ܳ���
//����:2016/10/09
//by Wangjf
extern "C" unsigned int _stdcall SENC_RSA_Transfer_1024(	SENCryptCard* sencDev,					//���ܿ��豸handle
														RSA* Key,							//RSA��Կ
														unsigned char* pucSendData,			//������message����
														unsigned int uiSendLength,			//�����������ܳ���
														unsigned char* pucReadData,			//��������
														unsigned int uiReadLength)			//���������ܳ���
{
	unsigned char SendBuf[2048]={0};

	unsigned char Plaintext[1024]={0};

	unsigned int ucRet = 0;

	if(Key==NULL) return SENC_ERROR_KEY_INVALID;
	else if(uiSendLength==NULL||uiReadLength==NULL) return SENC_ERROR_PARAMETER_ERROR;

	memcpy(Plaintext,pucSendData,SENC_RSA_MESSAGE_LENGTH);

	memset(SendBuf,0x00,sizeof(SendBuf));
	// 	setRSA1024(Key,sencDev->SendBuf);
	// 
	// 	reverse(Plaintext,SENC_RSA_MESSAGE_LENGTH);
	// 	memcpy(sencDev->SendBuf+SENC_RSA_C_BLOCK_SIZE+SENC_RSA_C_FILL_SIZE+SENC_RSA_PARAMETER_LEN*2,Plaintext,SENC_RSA_MESSAGE_LENGTH);

	reverse(Plaintext,SENC_RSA_MESSAGE_LENGTH);
	memcpy(SendBuf,Plaintext,SENC_RSA_MESSAGE_LENGTH);
	setRSA1024(Key,SendBuf+SENC_RSA_MESSAGE_LENGTH);

	ucRet = SENC_Bulk_Write(sencDev,SENC_BULK_ENDPOINT_WRITE_1K,SendBuf,uiSendLength);

	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet = SENC_Bulk_Read(sencDev,SENC_BULK_ENDPOINT_READ_1K,pucReadData,uiReadLength);


	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	reverse(pucReadData,SENC_RSA_MESSAGE_LENGTH);

	return SENC_SUCCESS;
}




//������SENC_Test()
//���ܣ�RSA����ͨѶ����||Communication test SENCrypted by RSA2048
//������SENCryptCard		sencDev,						//���ܿ��豸handle
//		RSA*			rsakey,						//��Կ
//		unsigned char*	pucSendData					//������message����
// 		unsigned int	uiSendLength				//�����������ܳ���
// 		unsigned char*	pucReadData					//��������
//		unsigned int	uiReadLength				//���������ܳ���
//����:2016/09/29
//by Wangjf
extern "C" unsigned int _stdcall SENC_Test(	SENCryptCard* sencDev,					//���ܿ��豸handle
										   RSA* Key,							//��Կ
										   unsigned char* pucSendData,			//������message����
										   unsigned int uiSendLength,			//�����������ܳ���
										   unsigned char* pucReadData,			//��������
										   unsigned int uiReadLength)			//���������ܳ���
{
	// 	int iActualSendLength=0;
	// 	int iActualReadLength=0;
	unsigned char Plaintext[1024]={0};
	unsigned char SendBuf[2048]={0};


	unsigned int ucRet = 0;

	if(Key==NULL) return SENC_ERROR_KEY_INVALID;
	else if(uiSendLength==NULL||uiReadLength==NULL) return SENC_ERROR_PARAMETER_ERROR;

	memcpy(Plaintext,pucSendData,SENC_TEST_MESSAGE_LENGTH);

	memset(SendBuf,0x00,sizeof(SendBuf));
	setRSA2048(Key,SendBuf);

	reverse(Plaintext,SENC_TEST_MESSAGE_LENGTH);
	memcpy(SendBuf+SENC_RSA_PARAMETER_LEN*5,Plaintext,SENC_TEST_MESSAGE_LENGTH);

	ucRet = SENC_Bulk_Write(sencDev,SENC_BULK_ENDPOINT_WRITE_1K,SendBuf,uiSendLength);

	// 	ucRet = libusb_bulk_transfer(sencDev.dev_handle,SENC_BULK_ENDPOINT_WRITE,sencDev.SendBuf,uiSendLength,&iActualSendLength,SENC_BULK_TIME_OUT);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;
	// 	else if(iActualSendLength!=uiSendLength)
	// 		return SENC_ERROR_TRANSFER_LENGTH_NOT_MATCH;

	ucRet = SENC_Bulk_Read(sencDev,SENC_BULK_ENDPOINT_READ_1K,pucReadData,uiReadLength);


	// 	ucRet = libusb_bulk_transfer(sencDev.dev_handle,SENC_BULK_ENDPOINT_READ,pucReadData,uiReadLength,&iActualReadLength, SENC_BULK_TIME_OUT);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;
	// 	else if(iActualReadLength!=uiReadLength)
	// 		return SENC_ERROR_TRANSFER_LENGTH_NOT_MATCH;

	reverse(pucReadData,SENC_TEST_MESSAGE_LENGTH);

	return SENC_SUCCESS;
}
*/







/* aes.cpp
//*������SENC_Bulk_AES_ecb()
//*���ܣ�AES ecb����ͨѶ||SENCrypted communication in AES ECB mode
//*������SENCryptCard		sencDev,						//���ܿ��豸handle
//		unsigned char*	Password,					//AES��Կ
//		unsigned char*	pucSendData					//������message����
// 		unsigned int	uiSendLength				//�����������ܳ���
// 		unsigned char*	pucReadData					//��������
//		unsigned int	uiReadLength				//���������ܳ���
//*���ڣ�2016/10/09
//by Wangjf
unsigned int SENC_Bulk_AES_ecb(	SENCryptCard* sencDev,					//���ܿ��豸handle
													unsigned char* Password,			//AES��Կ
													unsigned char* pucSendData,			//������message����
													unsigned int uiSendLength,			//�����������ܳ���
													unsigned char* pucReadData,			//��������
													unsigned int uiReadLength)			//���������ܳ���
{
	AES_KEY aeskey;
	int i;
	unsigned int uiRet=0;
	unsigned char ciphertext[SENC_BUFFER_SIZE]={0};
	unsigned char ReceiveBuff[SENC_BUFFER_SIZE]={0};

	AES_set_encrypt_key(Password,SENC_AES_256,&aeskey);

	i=0;
	while(i < (int)uiSendLength){
		AES_ecb_encrypt(pucSendData+i,ciphertext+i,&aeskey,AES_ENCRYPT);
		i+=SENC_AES_BLOCK_SIZE;
	}

	uiRet = SENC_Bulk_Transfer(sencDev,ciphertext,uiSendLength,ReceiveBuff,uiReadLength);

	if(uiRet != SENC_SUCCESS)
		return uiRet;

	AES_set_encrypt_key(Password,SENC_AES_256,&aeskey);

	i = 0;
	while(i < (int)uiReadLength){
		AES_ecb_encrypt(ReceiveBuff,pucReadData,&aeskey,AES_DECRYPT);
	}


	return SENC_SUCCESS;
}


//*������SENC_Bulk_AES_cbc()
//*���ܣ�AES cbc����ͨѶ||SENCrypted communication in AES CBC mode
//*������SENCryptCard		sencDev,						//���ܿ��豸handle
//		unsigned char*	Password,					//AES��Կ
//		unsigned char*	pucSendData					//������message����
// 		unsigned int	uiSendLength				//�����������ܳ���
// 		unsigned char*	pucReadData					//��������
//		unsigned int	uiReadLength				//���������ܳ���
//*���ڣ�2016/10/09
//by Wangjf
unsigned int SENC_Bulk_AES_cbc(	SENCryptCard* sencDev,					//���ܿ��豸handle
													unsigned char* Password,			//AES��Կ
													unsigned char* pucSendData,			//������message����
													unsigned int uiSendLength,			//�����������ܳ���
													unsigned char* pucReadData,			//��������
													unsigned int uiReadLength)			//���������ܳ���
{
	AES_KEY aeskey;
// 	int i;
	unsigned int uiRet=0;
	unsigned char ciphertext[SENC_BUFFER_SIZE]={0};
	unsigned char ReceiveBuff[SENC_BUFFER_SIZE]={0};

	unsigned char iv[1024]={0};
	unsigned char iv0[1024]={0};

	RAND_bytes(iv0,sizeof(iv0));
	memcpy(iv,iv0,sizeof(iv));


	AES_set_encrypt_key(Password,SENC_AES_256,&aeskey);
	AES_cbc_encrypt(pucSendData,ciphertext,uiSendLength,&aeskey,iv,AES_ENCRYPT);


	uiRet = SENC_Bulk_Transfer(sencDev,ciphertext,uiSendLength,ReceiveBuff,uiReadLength);

	if(uiRet != SENC_SUCCESS)
		return uiRet;

	memcpy(iv,iv0,sizeof(iv));
	AES_set_encrypt_key(Password,SENC_AES_256,&aeskey);
	AES_cbc_encrypt(ReceiveBuff,pucReadData,uiReadLength,&aeskey,iv,AES_DECRYPT);


	return SENC_SUCCESS;
}
*/

/*  aes.cpp
unsigned int SENC_AES_DataEncrypt(SENCryptCard* sencDev,					//���ܿ��豸handle
								  unsigned char EncType,
								  unsigned char* inAesKey,
								  unsigned int inAesKeyLength,
								  unsigned char* pucCmdData,			//�������������
								  unsigned int inDataLength,
								  unsigned char* pucCryptograph,			//�������
								  unsigned int* DataLength)			//�������
{
	AES_KEY aeskey;
	unsigned int length,nlen;
	unsigned int i=0;

	unsigned char plaintext[SENC_BUFFER_SIZE]={0};
	unsigned char key[32]={0};

	if(!sencDev||!inAesKey||!pucCmdData||!pucCryptograph||!DataLength)
		return SENC_ERROR_PARAMETER_ERROR;


	memset(plaintext,0x00,sizeof(plaintext));
	length=inDataLength;
	memcpy(plaintext,pucCmdData,length);
	nlen=length;
	length=(nlen/16+(nlen%16?1:0))*16;

	memcpy(key,inAesKey,inAesKeyLength>32?32:inAesKeyLength);

	switch (EncType)
	{
	case 0x01:
		AES_set_encrypt_key(key,SENC_AES_128,&aeskey);
		break;
	case 0x02:
		AES_set_encrypt_key(key,SENC_AES_256,&aeskey);
		break;
	default:
		return SENC_ERROR_PARAMETER_ERROR;
	}	

	while(i < length){
		AES_ecb_encrypt(plaintext+i,pucCryptograph+i,&aeskey,AES_ENCRYPT);
		i+=SENC_AES_BLOCK_SIZE;
	}

	*DataLength=length;

	return SENC_SUCCESS;
}
*/


/*  crc.cpp
unsigned int  Crc16( unsigned char *ptr,unsigned int len)		//CRCѭ������У��
{
	unsigned int crc;
	unsigned int i,count;
	count=len;
	crc=0;
	for( i=0; i<count; i++ )
	{
		crc = xcrc(crc,*ptr);
		ptr++;
	}
	return crc;
}
*/


/*des.cpp
// *������SENC_DES_CalMac()
// *���ܣ�����MAC||Calculate MAC
// *������SENCryptCard		sencDev						//���ܿ��豸handle
//		unsigned char*		CalData						//��Ҫ���������
//		unsigned char*		CaledMac					//�������MAC
// *���ڣ�2016/10/28
//by Wangjf
unsigned int SENC_DES_CalMac(SENCryptCard* sencDev,				//���ܿ��豸handle
							 unsigned char* CalData,			//��Ҫ���������
							 unsigned char* CaledMac)			//�������MAC
{
	DES_cblock Deskey;
	DES_key_schedule KeySchedule;
	unsigned int length;
	unsigned int CalLen;
	unsigned char CalBuf[SENC_BUFFER_SIZE];
	unsigned char output[SENC_BUFFER_SIZE];
	DES_cblock ivec;
	
	//parameter check
	if(!sencDev)
		return SENC_ERROR_DEVICE_NOT_FOUND;

	if(!CalData||!CaledMac)
		return SENC_ERROR_PARAMETER_ERROR;

	
	memcpy(Deskey,((KeyData*)(sencDev->DevCtx))->SessionKey,8);
	DES_set_key_unchecked(&Deskey,&KeySchedule);
	memset(CalBuf,0x20,sizeof(CalBuf));
	memset((char*)&ivec,0x00,sizeof(ivec));

	length=(CalData[9]<<8)|CalData[10];

	memcpy(CalBuf,CalData,5);
	memcpy(CalBuf+5,CalData+9,length+2);

	if((length+7)%8!=0)
		CalLen=((length+7)/8+1)*8;
	else
		CalLen=length+7;

	DES_ncbc_encrypt(CalBuf,output,CalLen,&KeySchedule,&ivec,DES_ENCRYPT);

	memcpy(CaledMac,output+CalLen-4,4);

	return SENC_SUCCESS;
}
*/



/* assist
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
CLock lock;
void LockedRandGenerate(unsigned char* randbuf,int buflen){

	CGuard guard(lock);

	RAND_bytes(randbuf,buflen);

	return;
}
#endif
*/



/* internal.cpp
// *������SENC_CMD_Write()
// *���ܣ�SENC���ܿ����ݴ���||Data transfer
// *������SENCryptCard		sencDev,				//���ܿ��豸handle
//		unsigned char		EncryptType				//���ܱ�ʾ
// 		unsigned char*		pucSendData				//����������֡����
// *���ڣ�2016/10/28
//by Wangjf
unsigned int SENC_CMD_Write(	SENCryptCard*			sencDev,					//���ܿ��豸handle
							unsigned char			EncryptType,				//���ܱ�ʾ
							unsigned char*			pucSendData)				//����������֡����
{
	unsigned int ucRet = 0;
	unsigned char Rand[4];
	unsigned char SendBuf[SENC_BUFFER_SIZE];
	unsigned int CmdLength;
	unsigned char Mac[4]={0};
	unsigned int crc;

	if(sencDev==NULL) return SENC_ERROR_DEVICE_NOT_FOUND;

	if((EncryptType!=SENC_PLAINTEXT_SIGN&&EncryptType!=SENC_CIPHER_SIGN)||pucSendData==NULL) return SENC_ERROR_PARAMETER_ERROR;

	RAND_bytes(Rand,sizeof(Rand));

	memset(SendBuf,0x00,sizeof(SendBuf));
	SendBuf[0]=SENC_CMD_HEAD;
	SendBuf[1]=EncryptType;
	memcpy(SendBuf+2,Rand,4);

	switch (EncryptType)
	{
	case SENC_PLAINTEXT_SIGN:

		CmdLength=((pucSendData[1]<<8)|pucSendData[2])+3;
		SendBuf[10]=(CmdLength>>8)&0xff;
		SendBuf[11]=CmdLength&0xff;
		memcpy(SendBuf+12,pucSendData,CmdLength);

		crc=Crc16T(SendBuf+1,CmdLength+7);
		SendBuf[8]=(crc>>8)&0xff;
		SendBuf[9]=crc&0xff;

		break;

	case SENC_CIPHER_SIGN:
		ucRet=SENC_AES_Dispersion(sencDev,Rand);
		if(ucRet!=SENC_SUCCESS)
			return ucRet;
		ucRet=SENC_AES_CmdDataEncrypt(sencDev,pucSendData,SendBuf+12,&CmdLength);
		if(ucRet!=SENC_SUCCESS)
			return ucRet;
		SendBuf[10]=(CmdLength>>8)&0xff;
		SendBuf[11]=CmdLength&0xff;


		ucRet=SENC_DES_CalMac(sencDev,SendBuf+1,Mac);
		if(ucRet!=SENC_SUCCESS)
			return ucRet;

		memcpy(SendBuf+6,Mac,4);

		break;
	default:
		return SENC_ERROR_PARAMETER_ERROR;
	}

	if(CmdLength+12>1024){
		ucRet = SENC_Bulk_Write(sencDev,SENC_BULK_ENDPOINT_WRITE_2K,SendBuf,2048);
	}else{
		ucRet = SENC_Bulk_Write(sencDev,SENC_BULK_ENDPOINT_WRITE_1K,SendBuf,1024);
	}

	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}


// *������SENC_CMD_Read()
// *���ܣ�SENC���ܿ����ݴ���||Data transfer
// *������SENCryptCard		sencDev,				//���ܿ��豸handle
//		unsigned char		EncryptType				//���ܱ�ʾ
// 		unsigned char*		pucSendData				//����������֡����
// *���ڣ�2016/10/28
//by Wangjf
unsigned int SENC_CMD_Read(	SENCryptCard*			sencDev,					//���ܿ��豸handle
						   unsigned char			ReadEndPoint,			//����������֡����
						   unsigned char*			pucReadData,			//����������֡����
						   unsigned int		uiReadLength)				
{
	unsigned int ucRet = 0;
	unsigned char Rand[4];
	unsigned char ReadBuf[SENC_BUFFER_SIZE];
	unsigned int CmdLength;
	unsigned int crc;
	unsigned char Mac[4]={0};



	if(sencDev==NULL)
		return SENC_ERROR_DEVICE_NOT_FOUND;

	if(uiReadLength==NULL||pucReadData==NULL||(ReadEndPoint!=SENC_BULK_ENDPOINT_READ_2K&&ReadEndPoint!=SENC_BULK_ENDPOINT_READ_1K))
		return SENC_ERROR_PARAMETER_ERROR;

	ucRet = SENC_Bulk_Read(sencDev,ReadEndPoint,ReadBuf,uiReadLength);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	if(ReadBuf[0]!=SENC_CMD_HEAD)
		return SENC_ERROR_RECEIVED_DATA_HEAD_ERROR;

	CmdLength=(ReadBuf[10]<<8)|ReadBuf[11];

	switch (ReadBuf[1])
	{
	case SENC_PLAINTEXT_SIGN:
		crc=Crc16T(ReadBuf+1,CmdLength+7);
		if(crc!=((ReadBuf[8]<<8)|ReadBuf[9]))
			return SENC_ERROR_CRC_ERROR;

		memcpy(pucReadData,ReadBuf+12,CmdLength);

		break;

	case SENC_CIPHER_SIGN:
		ucRet=SENC_DES_CalMac(sencDev,ReadBuf+1,Mac);
		if(ucRet!=SENC_SUCCESS)
			return ucRet;
		if(memcmp(Mac,ReadBuf+6,4)!=0)
			return SENC_ERROR_MAC_ERROR;

		memcpy(Rand,ReadBuf+2,4);
		ucRet=SENC_AES_Dispersion(sencDev,Rand);
		if(ucRet!=SENC_SUCCESS)
			return ucRet;

		ucRet=SENC_AES_CmdDataDecrypt(sencDev,ReadBuf+12,pucReadData,CmdLength);
		if(ucRet!=SENC_SUCCESS)
			return ucRet;

		break;

	default:
		return SENC_ERROR_RECEIVED_DATA_HEAD_ERROR;
	}

	return SENC_SUCCESS;
}
*/



/* usbapi.cpp
	unsigned int USB_Open(SENCryptCard* sencDev,SENCryptCardList* senclist,unsigned int CardIdx)
{
	int ucRet = 0;

	if(sencDev->OpenSign == TRUE)
		return SENC_ERROR_DEVICE_OPENED;

	if(senclist==NULL||(CardIdx<0||CardIdx>=8))
		return SENC_ERROR_PARAMETER_ERROR;

	ucRet = libusb_init(&sencDev->ctx);//��ʼ�����ݽṹ��
	if(ucRet<SENC_SUCCESS){
		return usbErrorCheck(ucRet);
	}

	ucRet = libusb_open(senclist->senc_devs[CardIdx],&sencDev->dev_handle);//ͨ��pid��vid�����豸�����Ϊ·��
	if(ucRet < SENC_SUCCESS)
	{
		libusb_exit(sencDev->ctx);
		return usbErrorCheck(ucRet);
	}

	if(libusb_kernel_driver_active(sencDev->dev_handle,0) == 1){//�������
		libusb_detach_kernel_driver(sencDev->dev_handle,0);
	}
	ucRet = libusb_claim_interface(sencDev->dev_handle,0);//���벢��ռ�ӿ�
	if(ucRet<SENC_SUCCESS){ 
		libusb_attach_kernel_driver(sencDev->dev_handle,0);
		libusb_close(sencDev->dev_handle);
		libusb_exit(sencDev->ctx);

		return usbErrorCheck(ucRet);		
	}

	sencDev->OpenSign = TRUE;
	return SENC_SUCCESS;
}
// 


// *������USB_InterfaceClaim()
// *���ܣ������ռ�ӿ�||Claim for interface
// *������SENCryptCard		sencDev,						//���ܿ��豸handle
// *���ڣ�2016/09/29
//by Wangjf
unsigned int USB_InterfaceClaim(SENCryptCard* sencDev)
{
	unsigned int ucRet = 0;
	// 	libusb_context *ctx;
	if(sencDev == NULL) return SENC_ERROR_DEVICE_NOT_FOUND;

	if(sencDev->ErrCode!=SENC_SUCCESS)
		return sencDev->ErrCode;

	if(sencDev->OpenSign == FALSE)//�ر��豸������ʶ
		return SENC_ERROR_DEVICE_CLOSED;

	if(libusb_kernel_driver_active(sencDev->dev_handle,0) == 1){//�������
		libusb_detach_kernel_driver(sencDev->dev_handle,0);
	}
	ucRet = libusb_claim_interface(sencDev->dev_handle,0);//���벢��ռ�ӿ�
	if(ucRet<SENC_SUCCESS){ 
		libusb_attach_kernel_driver(sencDev->dev_handle,0);
		libusb_close(sencDev->dev_handle);
		return SENC_ERROR_INTERFACE_CANNOT_OPEN;
	}

	return SENC_SUCCESS;
}

// *������USB_Open_VP()
// *���ܣ������豸��ռ�ýӿ�||Open device and claim for interface
// *������SENCryptCard		sencDev,						//���ܿ��豸handle
// *���ڣ�2016/09/29
//by Wangjf
unsigned int USB_Open_VP(SENCryptCard* sencDev)
{
	int ucRet = 0;
	libusb_device **devs;
	// 	libusb_context *ctx;

	if(sencDev->OpenSign == TRUE)
		return SENC_ERROR_DEVICE_OPENED;

	if(gDevs==0){
		ucRet = libusb_init(&gctx);//��ʼ�����ݽṹ��
		if(ucRet<SENC_SUCCESS){
			return usbErrorCheck(ucRet);
		}
	}	

	ucRet = libusb_get_device_list(gctx, &devs);//��ȡ�豸�б�
	if(ucRet<SENC_SUCCESS){
		return usbErrorCheck(ucRet);
	}

	sencDev->dev_handle = libusb_open_device_with_vid_pid(gctx,SENC_SS_VID,SENC_SS_PID);//ͨ��pid��vid�����豸�����Ϊ·��
	if(sencDev->dev_handle == NULL)
	{
		libusb_free_device_list(devs,1);
		if(gDevs==0)
			libusb_exit(gctx);
		return SENC_ERROR_DEVICE_NOT_FOUND;
	}

	libusb_free_device_list(devs,1);//�ͷ��豸�б�

	if(libusb_kernel_driver_active(sencDev->dev_handle,0) == 1){//�������
		libusb_detach_kernel_driver(sencDev->dev_handle,0);
	}
	ucRet = libusb_claim_interface(sencDev->dev_handle,0);//���벢��ռ�ӿ�
	if(ucRet<SENC_SUCCESS){ 
		libusb_attach_kernel_driver(sencDev->dev_handle,0);
		libusb_close(sencDev->dev_handle);
		if(gDevs==0)
			libusb_exit(gctx);

		return usbErrorCheck(ucRet);		
	}
	gDevs++;
	sencDev->OpenSign = TRUE;
	return SENC_SUCCESS;
}


//*������USB_Init()
//*���ܣ���ʼ���豸||Initial device
//*������SENCryptCard		sencDev,						//���ܿ��豸handle
//*���ڣ�2016/09/29
//by Wangjf
unsigned int USB_Init(SENCryptCard* sencDev)
{
	memset(sencDev->DHPrivKey,0x00,sizeof(sencDev->DHPrivKey));
	memset(sencDev->CommKey,0x00,sizeof(sencDev->CommKey));
	memset(sencDev->SessionKey,0x00,sizeof(sencDev->SessionKey));
	sencDev->EncAttr->EncryptLength=0x00;
	sencDev->EncAttr->EncryptMode=0x00;
	sencDev->EncAttr->KeyId=0x00;
	// 	memset(sencDev->SendBuf,0,sizeof(sencDev->SendBuf));
	// 	memset(ReceiveBuf,0,sizeof(ReceiveBuf));
	// 	memset(CacheBuf,0,sizeof(CacheBuf));
	// 	memset(sencDev.Plaintext,0,sizeof(sencDev.Plaintext));
	return SENC_SUCCESS;
}

*/






	/*libsenc.cpp




	//*������SENC_Bulk_Transfer()
	//*���ܣ�USB BULK_ONLYģʽ���ݴ���||Data transfer in USB BulkOnly mode
	//*������SENCryptCard		sencDev,						//���ܿ��豸handle
	//		unsigned char*	pucSendData					//����������
	// 		unsigned int	uiSendLength				//���������ݳ���
	// 		unsigned char*	pucReadData					//��������
	//		unsigned int	uiReadLength				//�������ݳ���
	//*���ڣ�2016/09/29
	//by Wangjf
	unsigned int SENC_Bulk_Transfer(	SENCryptCard*			sencDev,						//���ܿ��豸handle
	unsigned char*		pucSendData,				//����������
	unsigned int		uiSendLength,				//���������ݳ���
	unsigned char*		pucReadData,				//��������
	unsigned int		uiReadLength)				//�������ݳ���
	{


	unsigned int ucRet = 0;

	if(uiSendLength==NULL||uiReadLength==NULL) return SENC_ERROR_PARAMETER_ERROR;

	ucRet = SENC_Bulk_Write(sencDev,SENC_BULK_ENDPOINT_WRITE_2K,pucSendData,uiSendLength);

	if(ucRet!=SENC_SUCCESS)
	return ucRet;

	ucRet = SENC_Bulk_Read(sencDev,SENC_BULK_ENDPOINT_WRITE_2K,pucReadData,uiReadLength);

	if(ucRet!=SENC_SUCCESS)
	return ucRet;

	return SENC_SUCCESS;
	}
	*/
