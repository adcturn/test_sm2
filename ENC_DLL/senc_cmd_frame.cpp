#include "senc_cmd_frame.h"
#include "libsenc.h"
#include "senc_internalapi.h"
#include "senc_assist.h"
#include "senc_error.h"
#if defined(linux) || defined(__linux__)
#include <string.h>
#endif

#pragma warning(disable:4127)
#pragma warning(disable:4244)

//*������SENC_CMD_KEX_KeyExchange()
//*���ܣ���Կ����||Key exchange
//*������SENCryptCard*	sencDev					//���ܿ��豸handle
//		unsigned char*	pucCmpAttr,				//���͵ļ������A
//		unsigned char*	pucRecvCmpAttr,			//�յ��ļ������B
//		unsigned char*	pucRetPrivCommuKey)		//����ͨ����Կ
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_KEX_KeyExchange(SENCryptCard*		sencDev,				//���ܿ��豸handle
									  unsigned char*	pucCmpAttr,				//���͵ļ������A
									  unsigned char*	pucRecvCmpAttr,			//�յ��ļ������B
									  unsigned char*	pucRetPrivCommuKey)		//����ͨ����Կ
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//parameter check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"Key Exchange: Device Not Found");
	if(!pucCmpAttr||!pucRetPrivCommuKey||!pucRecvCmpAttr)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"Key Exchange: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//cmd frame build-up 
	cmdBuf[0]=SENC_CMD_KEY_EXCHANGE;
	cmdBuf[2]=0x04;
	memcpy(cmdBuf+3,pucCmpAttr,4);

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);

		if(ucRet!=SENC_SUCCESS)
			break;

		//ret-value check
		ucRet=RetCheck(revBuf,&retLen,SENC_CMD_KEY_EXCHANGE);
		ERROR_LOG(ucRet,"Key Exchange: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//calcu-param B 4bytes
		memcpy(pucRecvCmpAttr,revBuf+6,4);

		//communication key encrypted by DH key 16bytes
		memcpy(pucRetPrivCommuKey,revBuf+10,16);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_EC_GetState()
//*���ܣ���ȡ���ܿ�״̬||Get state of encrypt card
//*������SENCryptCard*	sencDev				//���ܿ��豸handle
//		unsigned char*	pucRetState,		//���ذ忨״̬
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_EC_GetState(SENCryptCard*		sencDev,			//���ܿ��豸handle
								  unsigned char*	pucRetState)		//���ذ忨״̬

{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;

	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Get State: Device Not Found");
	if(!pucRetState)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Get State: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_ENCRYPT_CARD_OPERATION;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_ECARD_GET_STAT;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//ret-value check
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_ENCRYPT_CARD_OPERATION<<4)|SENC_ECARD_GET_STAT));
		ERROR_LOG(ucRet,"CMD Get State: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//card state 1byte
		memcpy(pucRetState,revBuf+6,1);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_EC_GetID()
//*���ܣ���ȡ���ܿ�ID||Get the ID of encrypt card
//*������SENCryptCard*		sencDev,						//���ܿ��豸handle
//		unsigned char*		pucRetID						//����ID����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_EC_GetID(SENCryptCard*	sencDev,		//���ܿ��豸handle
							   unsigned char*	pucRetID)		//����ID����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Get ID: Device Not Found");
	if(!pucRetID)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Get ID: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_ENCRYPT_CARD_OPERATION;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_ECARD_GET_ID;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//ret-value check
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_ENCRYPT_CARD_OPERATION<<4)|SENC_ECARD_GET_ID));
		ERROR_LOG(ucRet,"CMD Get ID: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//card ID 8 bytes
		memcpy(pucRetID,revBuf+6,SENC_CARD_ID_LENGTH);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}




//*������SENC_CMD_EC_GetVersion()
//*���ܣ���ȡ���ܿ��汾||Get the version of encrypt card and firmware
//*������SENCryptCard*		sencDev,						//���ܿ��豸handle
//		unsigned char*		pucRetHardwareVer				//����Ӳ���汾
//		unsigned char*		pucRetFirmwareVer				//���ع̼��汾
//*���ڣ�2016/10/25 
//by Wangjf
unsigned int SENC_CMD_EC_GetVersion(SENCryptCard*	sencDev,			//���ܿ��豸handle
									unsigned char*	pucRetHardwareVer,	//����Ӳ���汾
									unsigned char*	pucRetFirmwareVer)	//���ع̼��汾
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Get Version: Device Not Found");
	if(!pucRetHardwareVer||!pucRetFirmwareVer)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Get Version: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_ENCRYPT_CARD_OPERATION;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_ECARD_GET_VERSION;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//ret-value check
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_ENCRYPT_CARD_OPERATION<<4)|SENC_ECARD_GET_VERSION));
		ERROR_LOG(ucRet,"CMD Get Version: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//hardware version 8 bytes
		memcpy(pucRetHardwareVer,revBuf+6,8);

		//firmware version 8 bytes
		memcpy(pucRetFirmwareVer,revBuf+14,8);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_MC_NewMasterCard()
//*���ܣ�����¹���||Add an new master card
//*������SENCryptCard*		sencDev,						//���ܿ��豸handle
//		unsigned char*		pucRetAddedCardId				//������ӿ�
//		unsigned char*		pucRetRestNums					//����ʣ�����ӿ�����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_NewMasterCard(SENCryptCard*	sencDev,			//���ܿ��豸handle
									   unsigned char*	pucRetAddedCardId,	//������ӿ�ID
									   unsigned char*	pucRetRestNums)		//����ʣ�����ӿ�����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD New Master Card: Device Not Found");
	if(!pucRetAddedCardId||!pucRetRestNums)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD New Master Card: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_MANAGEMENT;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_MANAGE_ADDITION;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_MANAGEMENT<<4)|SENC_MANAGE_ADDITION));
		ERROR_LOG(ucRet,"CMD New Master Card: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//master card ID 8 bytes
		memcpy(pucRetAddedCardId,revBuf+6,SENC_CARD_ID_LENGTH);

		//number of master cards can be added 1byte
		memcpy(pucRetRestNums,revBuf+14,1);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_MC_VerifyMasterCard()
//*���ܣ���֤����||Verify master card
//*������SENCryptCard*		sencDev,						//���ܿ��豸handle
//		unsigned char*		pucRetVerifiedCardId			//���ر���֤��ID
//		unsigned char*		pucRetPermission				//���ؿ�Ȩ��
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_VerifyMasterCard(SENCryptCard*		sencDev,				//���ܿ��豸handle
										  unsigned char*	pucRetVerifiedCardId,	//���ر���֤��ID
										  unsigned char*	pucRetPermission)		//���ؿ�Ȩ��
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Verify Master Card: Device Not Found");
	if(!pucRetVerifiedCardId||!pucRetPermission)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Verify Master Card: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_MANAGEMENT;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_MANAGE_VERIFITION;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_MANAGEMENT<<4)|SENC_MANAGE_VERIFITION));
		ERROR_LOG(ucRet,"CMD Verify Master Card: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//verified master card ID 8 bytes
		memcpy(pucRetVerifiedCardId,revBuf+6,SENC_CARD_ID_LENGTH);

		//permission 1 bytes|| 1 for in management state, 0 for more cards needed
		memcpy(pucRetPermission,revBuf+14,1);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_MC_DeleteMasterCard()
//*���ܣ�ɾ������||Delete master card
//*������SENCryptCard*		sencDev,						//���ܿ��豸handle
//		unsigned char*		pucDelCardId					//��ɾ����ID
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_DeleteMasterCard(SENCryptCard*		sencDev,			//���ܿ��豸handle
										  unsigned char*	pucDelCardId)		//��ɾ����ID
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Delete Master Card: Device Not Found");
	if(!pucDelCardId)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Delete Master Card: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_MANAGEMENT;
	cmdBuf[2]=0x09;
	cmdBuf[3]=SENC_MANAGE_DELETION;
	memcpy(cmdBuf+4,pucDelCardId,SENC_CARD_ID_LENGTH); //deleted master card ID 8 bytes

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_MANAGEMENT<<4)|SENC_MANAGE_DELETION));
		ERROR_LOG(ucRet,"CMD Delete Master Card: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_MC_GetMasterCardId()
//*���ܣ���ȡ����ID|| Get all master cards' ID
//*������SENCryptCard*		sencDev,							//���ܿ��豸handle
//							unsigned char*	pucRetData			//���ع�����Ϣ
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_GetMasterCardId(SENCryptCard*		sencDev,		//���ܿ��豸handle
										 unsigned char*		pucRetData)		//��������
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Get Mcard ID: Device Not Found");
	if(!pucRetData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Get Mcard ID: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_MANAGEMENT;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_MANAGE_GET_ID;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_MANAGEMENT<<4)|SENC_MANAGE_GET_ID));
		ERROR_LOG(ucRet,"CMD Get Mcard ID: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//total 45 bytes
		//5 master cards and each master card has: card verify flag 1 byte + ID 8bytes
		//card verify flag: 0 not verified || 1 verified || 0xFF card not existed
		//if card doesn't existed, ID would be 8 bytes 0x00
		memcpy(pucRetData,revBuf+6,(SENC_CARD_ID_LENGTH+1)*5);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_MC_GetBackupKey()
//*���ܣ���ȡ������Կ|| Get back-up keys
//*������SENCryptCard*		sencDev,							//���ܿ��豸handle
//		unsigned char*		pucRetEncryptSign					//���ؿ����ܱ�ʶ
//		unsigned char*		pucRetKeys							//���ؼ��ܱ�����Կ����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_GetBackupKey(SENCryptCard*		sencDev,			//���ܿ��豸handle
									  unsigned char*	pucRetEncryptSign,	//���ؿ����ܱ�ʶ
									  unsigned char*	pucRetKeys)			//���ؼ��ܱ�����Կ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Get Backup Key: Device Not Found");
	if(!pucRetEncryptSign||!pucRetKeys)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Get Backup Key: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_MANAGEMENT;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_MANAGE_BACKUP_KEY;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_MANAGEMENT<<4)|SENC_MANAGE_BACKUP_KEY));
		ERROR_LOG(ucRet,"CMD Get Backup Key: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//total 5 bytes or 213 bytes
		//first 5 bytes stand for master cards verified state. 1 for verified, 0 for not. 
		//only all 5 cards verified (0x01 0x01 0x01 0x01 0x01), the following 208 bytes are available.
		//8 bytes random numbers, 8 bytes card ID * 5(40 bytes) and 10 encrypted backup key (16 bytes for each)
		memcpy(pucRetEncryptSign,revBuf+6,5);

		memcpy(pucRetKeys,revBuf+11,SENC_BAKCUP_KEYS_LENGTH);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_MC_SetRecoveryKey()
//*���ܣ����ûָ�������Կ|| Set back-up keys for recovery
//*������SENCryptCard*		sencDev,							//���ܿ��豸handle
//		unsigned char*		pucInKeys,							//��ָ��ļ��ܱ�����Կ����
//		unsigned char*		pucRetDecryptSign					//���ع������ܱ�ʶ
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_SetRecoveryKey(SENCryptCard*	sencDev,			//���ܿ��豸handle
										unsigned char*	pucInKeys,			//��ָ��ļ��ܱ�����Կ����
										unsigned char*	pucRetDecryptSign)	//���ع������ܱ�ʶ	
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Set Recovery Key: Device Not Found");
	if(!pucInKeys||!pucRetDecryptSign)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Set Recovery Key: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_MANAGEMENT;
	cmdBuf[2]=0xD1;
	cmdBuf[3]=SENC_MANAGE_RECOVERY_KEY;
	memcpy(cmdBuf+4,pucInKeys,SENC_BAKCUP_KEYS_LENGTH); //backup key 208 bytes

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_MANAGEMENT<<4)|SENC_MANAGE_RECOVERY_KEY));
		ERROR_LOG(ucRet,"CMD Set Recovery Key: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//master cards verify flag 5 bytes + encrypt card set-up flag 1 byte
		//2 master cards required for verified. if 2 cards passed, the last card setup flag would be 1.
		memcpy(pucRetDecryptSign,revBuf+6,6);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_MC_MngQuit()
//*���ܣ��˳�����״̬|| Quit management state
//*������SENCryptCard*		sencDev,							//���ܿ��豸handle
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_MngQuit(SENCryptCard*	sencDev)			//���ܿ��豸handle
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Quit Management: Device Not Found");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_MANAGEMENT;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_MANAGE_QUIT;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_MANAGEMENT<<4)|SENC_MANAGE_QUIT));
		ERROR_LOG(ucRet,"CMD Quit Management: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_MC_WorkStandby()
//*���ܣ����빤��״̬|| Set to Standby state;
//*������SENCryptCard*		sencDev,							//���ܿ��豸handle
//*���ڣ�2016/11/04
//by Wangjf
unsigned int SENC_CMD_MC_WorkStandby(SENCryptCard*	sencDev)			//���ܿ��豸handle
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Set Standby: Device Not Found");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_MANAGEMENT;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_MANAGE_WORK_STANDBY;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_MANAGEMENT<<4)|SENC_MANAGE_WORK_STANDBY));
		ERROR_LOG(ucRet,"CMD Set Standby: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_Dongle_NewDongle()
//*���ܣ��������|| Add a new key dongle;
//*������SENCryptCard*		sencDev,							//���ܿ��豸handle
//		unsigned char*		pucDongleId,						//��ID
//		unsigned char*		pucInKeyData,						//�ⲿ��֤��Կ
//		unsigned char*		pucKeyIdx,							//�����
//		unsigned char*		pucPlaintextKey,					//����flash key
//*���ڣ�2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_NewDongle(SENCryptCard*	sencDev,			//���ܿ��豸handle
									   unsigned char*	pucDongleId,		//��ID
									   unsigned char	keyIdx1,
									   unsigned char	keyIdx2,
									   unsigned char*	pucInKeyData,		//�ⲿ��֤��Կ
									   unsigned char*	pucPlaintextKey)	//����flash key
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD New Dongle: Device Not Found");
	if(!pucInKeyData||!pucDongleId||!pucPlaintextKey)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD New Dongle: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_DONGLE_OPERATION;//�����ʶ
	cmdBuf[2]=29;//����
	cmdBuf[3]=SENC_DONGLE_ADDITION;//������ʶ
	memcpy(cmdBuf+4,pucDongleId,SENC_CMD_LENGTH_DONGLE_ID); //dongle ID 8bytes
	cmdBuf[13]=keyIdx1;
	cmdBuf[15]=keyIdx2;
	memcpy(cmdBuf+16,pucInKeyData,SENC_CMD_LENGTH_DONGLE_KEY_DATA); //dongle key 16 bytes

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_DONGLE_OPERATION<<4)|SENC_DONGLE_ADDITION));
		ERROR_LOG(ucRet,"CMD New Dongle: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(pucPlaintextKey,revBuf+6,8);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_Dongle_SetEncryptedKey()
//*���ܣ���������key|| Set the encrypted key;
//*������SENCryptCard*		sencDev 							//���ܿ��豸handle
//		unsigned char*		pucEncKeyData						//����key
//*���ڣ�2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_SetEncryptedKey(SENCryptCard*	sencDev,			//���ܿ��豸handle
											 unsigned char*	pucEncKeyData)		//����key
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Set Dongle EncKey: Device Not Found");
	if(!pucEncKeyData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Set Dongle EncKey: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_DONGLE_OPERATION;//�����ʶ
	cmdBuf[2]=9;//����
	cmdBuf[3]=SENC_DONGLE_SET_KEY;//������ʶ
	memcpy(cmdBuf+4,pucEncKeyData,8); //half AES key, encrypted, 8bytes

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_DONGLE_OPERATION<<4)|SENC_DONGLE_SET_KEY));
		ERROR_LOG(ucRet,"CMD Set Dongle EncKey: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_Dongle_Delete()
//*���ܣ�ɾ����|| Delete bound key dongle;
//*������SENCryptCard*		sencDev				//���ܿ��豸handle
//		unsigned char*		KeyId,				//��ɾ����ID
//*���ڣ�2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_Delete(SENCryptCard*	sencDev,		//���ܿ��豸handle
									unsigned char*	KeyId)			//��ɾ����ID
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Delete Dongle: Device Not Found");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_DONGLE_OPERATION;//�����ʶ
	cmdBuf[2]=0x09;//����
	cmdBuf[3]=SENC_DONGLE_DELETION;//������ʶ
	memcpy(cmdBuf+4,KeyId,SENC_CMD_LENGTH_DONGLE_ID);

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_DONGLE_OPERATION<<4)|SENC_DONGLE_DELETION));
		ERROR_LOG(ucRet,"CMD Delete Dongle: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_Dongle_GetVerifyRand()
//*���ܣ���ȡ��֤�����|| Get verification random number;
//*������SENCryptCard*		sencDev					//���ܿ��豸handle
//		unsigned char*		pucDongleId				//��ID
//		unsigned char*		pucRetRandNum			//������֤�����
//		unsigned char*		pucDongleIdx			//�����
//		unsigned char*		pucEncFlashKey			//����flash key
//*���ڣ�2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_GetVerifyRand(SENCryptCard*	sencDev,			//���ܿ��豸handle
										   unsigned char*	pucDongleId,		//��ID
										   unsigned char*	keyIdx1,
										   unsigned char*	keyIdx2,
										   unsigned char*	pucRetRandNum,		//������֤�����
										   unsigned char*	pucEncFlashKey)		//����flash key
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Get Verify Rand Num: Device Not Found");
	if(!pucRetRandNum||!pucDongleId||!pucEncFlashKey) 
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Get Verify Rand Num: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_DONGLE_OPERATION;
	cmdBuf[2]=0x09;
	cmdBuf[3]=SENC_DONGLE_GET_VERIFITION_DATA;
	memcpy(cmdBuf+4,pucDongleId,SENC_CMD_LENGTH_DONGLE_ID); //dongle ID 8 bytes

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_DONGLE_OPERATION<<4)|SENC_DONGLE_GET_VERIFITION_DATA));
		ERROR_LOG(ucRet,"CMD Get Verify Rand Num: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//random number 8 bytes + dongle key sign 1 byte
		*keyIdx1=*(revBuf+7);
		*keyIdx2=*(revBuf+9);
		memcpy(pucRetRandNum,revBuf+10,SENC_CMD_LENGTH_DONGLE_RAND);//�����8�ֽ�
		memcpy(pucEncFlashKey,revBuf+18,8);//encrypted flash key, half one, 8 bytes.
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_Dongle_Verify()
//*���ܣ���֤��|| Verify inserted dongle;
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char*		pucDongleId					//��ID
//		unsigned char*		pucDongleIdx				//�����
//		unsigned char*		pucInKeyVerifyData			//��֤��������
//		unsigned char*		pucDecFlashKey				//���ܺ�flash key
//*���ڣ�2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_Verify(SENCryptCard*	sencDev,				//���ܿ��豸handle
									unsigned char*	pucDongleId,			//��ID
									unsigned char*	pucInKeyVerifyData,		//��֤��������
									unsigned char*	pucDecFlashKey)			//���ܺ�flash key
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Dongle Verify: Device Not Found");
	if(!pucInKeyVerifyData||!pucDongleId||!pucDecFlashKey) 
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Dongle Verify: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_DONGLE_OPERATION;
	cmdBuf[2]=25;
	cmdBuf[3]=SENC_DONGLE_VERIFITION;
	memcpy(cmdBuf+4,pucDongleId,SENC_CMD_LENGTH_DONGLE_ID); //dongle ID 8 bytes
	memcpy(cmdBuf+12,pucInKeyVerifyData,8); //verification data 8 bytes encrypted
	memcpy(cmdBuf+20,pucDecFlashKey,8);//half of flash key, decrypted, 8 bytes

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_DONGLE_OPERATION<<4)|SENC_DONGLE_VERIFITION));
		ERROR_LOG(ucRet,"CMD Dongle Verify: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_Get_Dongle_ID()
//*���ܣ���ȡ��ID|| Get dongles ID
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucRetData						//����ID����
//*���ڣ�2017/02/14
//by Wangjf
unsigned int SENC_CMD_Get_Dongle_ID(SENCryptCard*	sencDev,				//���ܿ��豸handle
									unsigned char*	pucRetData)				//����ID����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Get Dongle ID: Device Not Found");
	if(!pucRetData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Get Dongle ID: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_DONGLE_OPERATION;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_DONGLE_GET_ID;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_DONGLE_OPERATION<<4)|SENC_DONGLE_GET_ID));
		ERROR_LOG(ucRet,"CMD Get Dongle ID: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//total 27 bytes
		//3 dongles and for each dongle : dongle index 1 byte + ID 8bytes
		//dongle index: 1-3 || 0xFF card not existed
		//if dongle doesn't existed(index is 0xff), ID would be 8 bytes 0x00
		memcpy(pucRetData,revBuf+6,(SENC_CMD_LENGTH_DONGLE_ID+1)*3);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_Dongle_Quit()
//*���ܣ��˳�����ģʽ|| Quit from operation state;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Dongle_Quit(SENCryptCard*	sencDev)	//���ܿ��豸handle
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Quit Operation: Device Not Found");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_DONGLE_OPERATION;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_DONGLE_QUIT;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_DONGLE_OPERATION<<4)|SENC_DONGLE_QUIT));
		ERROR_LOG(ucRet,"CMD Quit Operation: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_AES_Encrypt()
//*���ܣ�AES����|| Encrypt in AES
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		CBCiv							//cbc��ʼ����
//		unsigned char*		pucInData						//����������
//		unsigned int		uiInDataLen						//���������ݳ���
//		unsigned char*		pucCipherData					//���ܷ�������
//		unsigned int*		uiCipherDataLen					//���������ݳ���
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_AES_Encrypt(SENCryptCard*		sencDev,				//���ܿ��豸handle
								  EncryptAttr*		EncAttributes,
								  unsigned char*	CBCiv,					//cbc��ʼ����
								  unsigned char*	pucInData,				//����������
								  unsigned int		uiInDataLen,			//���������ݳ���
								  unsigned char*	pucCipherData,			//���ܷ�������
								  unsigned int*		uiCipherDataLen)		//���������ݳ���
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD AES Encryption: Device Not Found");
	if(!uiCipherDataLen||!pucInData||!pucCipherData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD AES Encryption: Parameter Null");
	if(EncAttributes->AES_EncMode==0x02&&!CBCiv) //CBCiv cannot be NULL in CBC mode
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD AES Encryption: IV Null");
	if(EncAttributes->AES_EncIdx<65||EncAttributes->AES_EncIdx>128) //AES key 1-64 are reserved for RSA key encryption
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"AES Encryption: Encryption Attributes Error");

	//total data could not more than 1K.
	// 	if((EncAttributes->AES_EncMode==0x01&&uiInDataLen>1024)||(EncAttributes->AES_EncMode==0x02&&uiInDataLen>1024)||(uiInDataLen <= 0x00))
	// 		return SENC_ERROR_DATA_OVERFLOW;
	if(uiInDataLen>2016||uiInDataLen<1)
		return ERROR_LOG(SENC_ERROR_AES_LENGTH_ERROR,"CMD AES Encryption: Data Length Error");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	if(uiInDataLen%16!=0){
		uiInDataLen=(uiInDataLen/16+1)*16;
	}

	//frame buildup
	cmdBuf[0]=SENC_CMD_AES;//��������
	cmdBuf[1]=((4+uiInDataLen)>>8)&0xff;//�����
	cmdBuf[2]=(4+uiInDataLen)&0xff;
	cmdBuf[3]=SENC_AES_ENCRYPTION;//��������
	cmdBuf[4]=EncAttributes->AES_EncLength;//�㷨���� 128|256
	cmdBuf[5]=EncAttributes->AES_EncMode;//����ģʽ ecb|cbc
	cmdBuf[6]=EncAttributes->AES_EncIdx;//��Կ���� 1-128
	//cbc��ecb�Ĳ�ͬ����
	switch (EncAttributes->AES_EncMode)
	{
	case 0x01:
		memcpy(cmdBuf+7,pucInData,uiInDataLen);//ecbֱ�ӷ���
		break;
	case 0x02:
		cmdBuf[1]=((16+4+uiInDataLen)>>8)&0xff;//�����+16
		cmdBuf[2]=(16+4+uiInDataLen)&0xff;
		memcpy(cmdBuf+7,CBCiv,16);//cbc��16bytes��ʼ����
		memcpy(cmdBuf+23,pucInData,uiInDataLen);
		break;
	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD AES Encryption: Encryption Attributes Error");
	}

	do{
		//�������ݳ��Ⱦ������ͽ��ܶ˿�
		if(uiInDataLen<989&&uiInDataLen>0)
			ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		else
			ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);

		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_AES<<4)|SENC_AES_ENCRYPTION));
		ERROR_LOG(ucRet,"CMD AES Encryption: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//���ܲ����Ƚ�
		if(revBuf[6]!=EncAttributes->AES_EncLength||revBuf[7]!=EncAttributes->AES_EncMode||revBuf[8]!=EncAttributes->AES_EncIdx)
			return ERROR_LOG(SENC_ERROR_RETURN_ENC_ATTRIBUTES_NOT_MATCH,"CMD AES Encryption: Returned Attributes Not Match");

		//returned ciphertext
		memcpy(pucCipherData,revBuf+9,retLen-6);
		*uiCipherDataLen=retLen-6;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_AES_Decrypt()
//*���ܣ�AES����|| Decrypt in AES
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		CBCiv							//cbc��ʼ����
//		unsigned char*		pucInData						//����������
//		unsigned int		uiInDataLen						//���������ݳ���
//		unsigned char*		pucDecryptedData				//���ܷ�������
//		unsigned int*		uiDecryptedDataLen				//���������ݳ���
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_AES_Decrypt(SENCryptCard*		sencDev,				//���ܿ��豸handle
								  EncryptAttr*		EncAttributes,
								  unsigned char*	CBCiv,					//cbc��ʼ����
								  unsigned char*	pucInData,				//����������
								  unsigned int		uiInDataLen,			//���������ݳ���
								  unsigned char*	pucDecryptedData,		//���ܷ�������
								  unsigned int*		uiDecryptedDataLen)		//���������ݳ���
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD AES Decryption: Device Not Found");
	if(!uiDecryptedDataLen||!pucInData||!pucDecryptedData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD AES Decryption: Parameter Null");
	if(EncAttributes->AES_EncMode==0x02&&!CBCiv) //CBCiv cannot be NULL in CBC mode
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD AES Decryption: IV Null");
	if(EncAttributes->AES_EncIdx<64||EncAttributes->AES_EncIdx>128) //AES key 1-64 are reserved for RSA key encryption
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"CMD AES Decryption: Encryption Attributes Error");

	//total data could not more than 1K.
	// 	if((EncAttributes->AES_EncMode==0x01&&uiInDataLen>1024)||(EncAttributes->AES_EncMode==0x02&&uiInDataLen>1024)||(uiInDataLen <=0x00))
	// 		return SENC_ERROR_DATA_OVERFLOW;
	if(uiInDataLen>2016||uiInDataLen<1)
		return ERROR_LOG(SENC_ERROR_AES_LENGTH_ERROR,"CMD AES Decryption: Data Length Error");


	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_AES;//��������
	cmdBuf[1]=((4+uiInDataLen)>>8)&0xff;//�����
	cmdBuf[2]=(4+uiInDataLen)&0xff;
	cmdBuf[3]=SENC_AES_DECRYPTION;//��������
	cmdBuf[4]=EncAttributes->AES_EncLength;//�㷨���� 128|256
	cmdBuf[5]=EncAttributes->AES_EncMode;//����ģʽ ecb|cbc
	cmdBuf[6]=EncAttributes->AES_EncIdx;//��Կ���� 1-64

	//cbc��ecb�Ĳ�ͬ����
	switch (EncAttributes->AES_EncMode)
	{
	case 0x01:
		memcpy(cmdBuf+7,pucInData,uiInDataLen);//ecbֱ�ӷ���
		break;
	case 0x02:
		cmdBuf[1]=((16+4+uiInDataLen)>>8)&0xff;//�����+16
		cmdBuf[2]=(16+4+uiInDataLen)&0xff;
		memcpy(cmdBuf+7,CBCiv,16);//cbc��16bytes��ʼ����
		memcpy(cmdBuf+23,pucInData,uiInDataLen);
		break;
	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD AES Decryption: Encryption Attributes Error");
	}

	do{
		//�������ݳ��Ⱦ������ͽ��ܶ˿�
		if(uiInDataLen<989&&uiInDataLen>0)
			ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		else
			ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);

		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_AES<<4)|SENC_AES_DECRYPTION));
		ERROR_LOG(ucRet,"CMD AES Decryption: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//���ܲ����Ƚ�
		if(revBuf[6]!=EncAttributes->AES_EncLength||revBuf[7]!=EncAttributes->AES_EncMode||revBuf[8]!=EncAttributes->AES_EncIdx)
		{
			ucRet = ERROR_LOG(SENC_ERROR_RETURN_ENC_ATTRIBUTES_NOT_MATCH,"CMD AES Decryption: Returned Attributes Not Match");
			break;
		}

		//returned plaintext
		memcpy(pucDecryptedData,revBuf+9,retLen);
		*uiDecryptedDataLen=retLen-6;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_RSA_Signature_External()
//*���ܣ��ⲿRSAǩ��|| Signature by RSA encryption
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucRsaKey						//ǩ����RSA��Կ����
//		unsigned char*		pucInData						//��ǩ������
//		unsigned char*		pucSignedData					//ǩ����������
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_RSA_Signature_External(SENCryptCard*	sencDev,				//���ܿ��豸handle
											 EncryptAttr*		EncAttributes,
											 unsigned char* pucIV,
											 unsigned char* pucMac,
											 unsigned char*	pucRsaKey,				//ǩ����RSA��Կ����
											 unsigned char*	pucInData,				//��ǩ������
											 unsigned char*	pucSignedData)			//ǩ����������
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD RSA Signature External: Device Not Found");
	if(!pucRsaKey||!pucInData||!pucSignedData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD RSA Signature External: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//�������ݷ�֡
	cmdBuf[0]=SENC_CMD_RSA;	//��������
	cmdBuf[1]=((SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_IV_LENGTH+SENC_ENC_MAC_LENGTH+256+4)>>8)&0xff; //����
	cmdBuf[2]=(SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_IV_LENGTH+SENC_ENC_MAC_LENGTH+256+4)&0xff;
	cmdBuf[3]=SENC_RSA_SIGNATURE_EXTERNAL;//��������
	cmdBuf[4]=EncAttributes->RSA_Mode;//ǩ���㷨����
	cmdBuf[5]=EncAttributes->RSA_PrikeyEncMode;//˽Կ��������
	cmdBuf[6]=EncAttributes->RSA_PrikeyEncIdx;//˽Կ��Կ����
	memcpy(cmdBuf+7,pucRsaKey,SENC_RSA_PRIVATE_KEY_LENGTH);//RSA˽Կ����
	memcpy(cmdBuf+7+SENC_RSA_PRIVATE_KEY_LENGTH,pucMac,SENC_ENC_MAC_LENGTH);
	memcpy(cmdBuf+7+SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_MAC_LENGTH,pucIV,SENC_ENC_IV_LENGTH);
	memcpy(cmdBuf+SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_IV_LENGTH+SENC_ENC_MAC_LENGTH+7,pucInData,256);//��ǩ������
	reverse(cmdBuf+SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_IV_LENGTH+SENC_ENC_MAC_LENGTH+7,256);//Little Endian ת��

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_RSA<<4)|SENC_RSA_SIGNATURE_EXTERNAL));
		ERROR_LOG(ucRet,"CMD RSA Signature External: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//תΪBig Endian
		reverse(revBuf+6,256);
		memcpy(pucSignedData,revBuf+6,256);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_RSA_Signature_Internal()
//*���ܣ�RSA�ڲ���Կǩ��|| Signature by RSA encryption with internal key
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucInData						//��ǩ������
//		unsigned char*		pucSignedData					//��������
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_RSA_Signature_Internal(SENCryptCard*	sencDev,				//���ܿ��豸handle
											 EncryptAttr*		EncAttributes,
											 unsigned char*	pucInData,				//��ǩ������
											 unsigned char*	pucSignedData)			//��������
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD RSA Signature Internal: Device Not Found");
	if(!pucInData||!pucSignedData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD RSA Signature Internal: Parameter Null");
	if(EncAttributes->RSA_InternalKeyIdx<1||EncAttributes->RSA_InternalKeyIdx>128)
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"CMD RSA Signature Internal: Encryption Attributes Error");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//�������ݷ�֡
	cmdBuf[0]=SENC_CMD_RSA;	//��������
	cmdBuf[1]=((256+3)>>8)&0xff; //����
	cmdBuf[2]=(256+3)&0xff;
	cmdBuf[3]=SENC_RSA_SIGNATURE_INTERNAL;//��������
	cmdBuf[4]=EncAttributes->RSA_Mode;//ǩ���㷨����
	cmdBuf[5]=EncAttributes->RSA_InternalKeyIdx;//˽Կ��Կ����
	memcpy(cmdBuf+6,pucInData,256);//��ǩ������
	reverse(cmdBuf+6,256);//Little Endian ת��

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_RSA<<4)|SENC_RSA_SIGNATURE_INTERNAL));
		ERROR_LOG(ucRet,"CMD RSA Signature Internal: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//תΪBig Endian
		reverse(revBuf+6,256);
		memcpy(pucSignedData,revBuf+6,256);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_RSA_Decrypt_External()
//*���ܣ��ⲿRSA����|| Decryption by RSA encryption
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucEncRsaPrivKey				//����RSA��Կ����
//		unsigned char*		pucInEncData					//����������
//		unsigned char*		pucOutDecData					//�����ѽ�������
//*���ڣ�2017/02/16
//by Wangjf
unsigned int SENC_CMD_RSA_Decrypt_External(SENCryptCard*	sencDev,				//���ܿ��豸handle
										   EncryptAttr*		EncAttributes,
										   unsigned char*	pucIV,
										   unsigned char*	pucMac,
										   unsigned char*	pucEncRsaPrivKey,		//����RSA��Կ����
										   unsigned char*	pucInEncData,			//����������
										   unsigned char*	pucOutDecData)			//�����ѽ�������
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD RSA Decryption External: Device Not Found");
	if(!pucEncRsaPrivKey||!pucInEncData||!pucOutDecData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD RSA Decryption External: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//�������ݷ�֡
	cmdBuf[0]=SENC_CMD_RSA;	//��������
	cmdBuf[1]=((SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_IV_LENGTH+SENC_ENC_MAC_LENGTH+256+4)>>8)&0xff; //����
	cmdBuf[2]=(SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_IV_LENGTH+SENC_ENC_MAC_LENGTH+256+4)&0xff;
	cmdBuf[3]=SENC_RSA_DECRYPT_EXTERNAL;//��������
	cmdBuf[4]=EncAttributes->RSA_Mode;//ǩ���㷨����
	cmdBuf[5]=EncAttributes->RSA_PrikeyEncMode;//˽Կ��������
	cmdBuf[6]=EncAttributes->RSA_PrikeyEncIdx;//˽Կ��Կ����
	memcpy(cmdBuf+7,pucEncRsaPrivKey,SENC_RSA_PRIVATE_KEY_LENGTH);//RSA˽Կ����
	memcpy(cmdBuf+7+SENC_RSA_PRIVATE_KEY_LENGTH,pucMac,SENC_ENC_MAC_LENGTH);
	memcpy(cmdBuf+7+SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_MAC_LENGTH,pucIV,SENC_ENC_IV_LENGTH);
	memcpy(cmdBuf+SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_IV_LENGTH+SENC_ENC_MAC_LENGTH+7,pucInEncData,256);//��ǩ������
	reverse(cmdBuf+SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_IV_LENGTH+SENC_ENC_MAC_LENGTH+7,256);//Little Endian ת��

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_RSA<<4)|SENC_RSA_DECRYPT_EXTERNAL));
		ERROR_LOG(ucRet,"CMD RSA Decryption External: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//תΪBig Endian
		reverse(revBuf+6,256);
		memcpy(pucOutDecData,revBuf+6,256);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_RSA_Decrypt_Internal()
//*���ܣ�RSA�ڲ���Կ����|| RSA Decryption with internal key
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucInEncData					//����������
//		unsigned char*		pucOutDecData					//�����ѽ�������
//*���ڣ�2017/02/16
//by Wangjf
unsigned int SENC_CMD_RSA_Decrypt_Internal(SENCryptCard*	sencDev,				//���ܿ��豸handle
										   EncryptAttr*		EncAttributes,
										   unsigned char*	pucInEncData,			//����������
										   unsigned char*	pucOutDecData)			//�����ѽ�������
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD RSA Decryption Internal: Device Not Found");
	if(!pucInEncData||!pucOutDecData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD RSA Decryption Internal: Parameter Null");
	if(EncAttributes->RSA_InternalKeyIdx<1||EncAttributes->RSA_InternalKeyIdx>128)
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"CMD RSA Decryption Internal: Encryption Attributes Error");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//�������ݷ�֡
	cmdBuf[0]=SENC_CMD_RSA;	//��������
	cmdBuf[1]=((256+3)>>8)&0xff; //����
	cmdBuf[2]=(256+3)&0xff;
	cmdBuf[3]=SENC_RSA_DECRYPT_INTERNAL;//��������
	cmdBuf[4]=EncAttributes->RSA_Mode;//ǩ���㷨����
	cmdBuf[5]=EncAttributes->RSA_InternalKeyIdx;//˽Կ��Կ����
	memcpy(cmdBuf+6,pucInEncData,256);//��ǩ������
	reverse(cmdBuf+6,256);//Little Endian ת��

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_RSA<<4)|SENC_RSA_DECRYPT_INTERNAL));
		ERROR_LOG(ucRet,"CMD RSA Decryption Internal: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//תΪBig Endian
		reverse(revBuf+6,256);
		memcpy(pucOutDecData,revBuf+6,256);
	}while(0);


	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}



//*������SENC_CMD_Key_RSA_Generate_Ret()
//*���ܣ�RSA��Կ���ɲ�����|| Generate an RSA key and export;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucRetRsaPrivKey				//�����Ѽ���˽Կ����
//		unsigned char*		pucRetRsaPubKey					//�����Ѽ��ܹ�Կ����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_RSA_Generate_Ret(SENCryptCard*	sencDev,				//���ܿ��豸handle
										   EncryptAttr*		EncAttributes,
										   unsigned char*	pucIV,
										   unsigned char*	pucMAC,
										   unsigned char*	pucRetRsaPrivKey,		//�����Ѽ���˽Կ����
										   unsigned char*	pucRetRsaPubKey)		//�����Ѽ��ܹ�Կ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Generate Enc RSA Key Pair: Device Not Found");
	if(!pucRetRsaPrivKey||!pucRetRsaPubKey||!pucIV||!pucMAC)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Generate Enc RSA Key Pair: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_KEY_OPERATION;
	cmdBuf[2]=0x04+16;
	cmdBuf[3]=SENC_KEYS_RSA_KEY_GENERATION_RETURN;
	cmdBuf[4]=EncAttributes->RSA_Mode;
	cmdBuf[5]=EncAttributes->RSA_PrikeyEncMode;
	cmdBuf[6]=EncAttributes->RSA_PrikeyEncIdx;
	memcpy(cmdBuf+7,pucIV,16);

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_KEY_OPERATION<<4)|SENC_KEYS_RSA_KEY_GENERATION_RETURN));
		ERROR_LOG(ucRet,"CMD Generate Enc RSA Key Pair: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//encryption mode check
		if(revBuf[6]!=EncAttributes->RSA_Mode)
		{
			ucRet = ERROR_LOG(SENC_ERROR_RETURN_ENC_ATTRIBUTES_NOT_MATCH,"CMD Generate Enc RSA Key Pair: Returned Attributes Not Match");
			break;
		}

		//private key data 1412 + 16 ��+ 16 iv?�� bytes
		memcpy(pucRetRsaPrivKey,revBuf+7,SENC_RSA_PRIVATE_KEY_LENGTH);
		memcpy(pucMAC,revBuf+7+SENC_RSA_PRIVATE_KEY_LENGTH,SENC_ENC_MAC_LENGTH);

		//public key data 512 bytes n->e (only rsa2048 available)
		/*
		if(revBuf[6]==0x01)
		memcpy(pucRetRsaPubKey,revBuf+647,256);
		else if(revBuf[6]==0x02)
		memcpy(pucRetRsaPubKey,revBuf+647,512);
		*/
		memcpy(pucRetRsaPubKey,revBuf+7+SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_MAC_LENGTH+SENC_ENC_IV_LENGTH,SENC_RSA_PUBLIC_KEY_LENGTH);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_Key_RSA_Generate_Internal()
//*���ܣ�RSA��Կ���ɲ��洢����|| Generate an RSA key and storage at card
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char		EncryptLength					//���ܳ���1024|2048
//		unsigned char		RsaKeyIdx						//����RSA��Կ�洢����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_RSA_Generate_Internal(SENCryptCard*	sencDev,			//���ܿ��豸handle
												unsigned char	EncryptLength,		//���ܳ���1024|2048
												unsigned char	RsaKeyIdx)			//����RSA��Կ�洢����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Generate RSA Key Pair Internal: Device Not Found");
	if(EncryptLength!=1||RsaKeyIdx<1||RsaKeyIdx>128)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Generate RSA Key Pair Internal: Parameter Index Error");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_KEY_OPERATION;
	cmdBuf[2]=0x03;
	cmdBuf[3]=SENC_KEYS_RSA_KEY_GENERATION_INTERNAL_STORAGE;
	cmdBuf[4]=EncryptLength;
	cmdBuf[5]=RsaKeyIdx;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_KEY_OPERATION<<4)|SENC_KEYS_RSA_KEY_GENERATION_INTERNAL_STORAGE));
		ERROR_LOG(ucRet,"CMD Generate RSA Key Pair Internal: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//mode check
		if(revBuf[6]!=EncryptLength||revBuf[7]!=RsaKeyIdx)
		{
			ucRet = ERROR_LOG(SENC_ERROR_RETURN_ENC_ATTRIBUTES_NOT_MATCH,"CMD Generate RSA Key Pair Internal: Returned Attributes Not Match");
			break;
		}
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_Key_RSA_GetPublicKey()
//*���ܣ���ȡĿ��RSA��Կ|| Get RSA public key
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char		EncryptLength				//���ܳ���1024|2048
//		unsigned char		KeyIndex					//Ŀ����Կ����
//		unsigned char*		pucRetRsaPubKey				//����RSA��Կ
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_RSA_GetPublicKey(SENCryptCard*	sencDev,				//���ܿ��豸handle
										   unsigned char	EncryptLength,			//���ܳ���1024|2048
										   unsigned char	KeyIndex,				//Ŀ����Կ����
										   unsigned char*	pucRetRsaPubKey)		//����RSA��Կ
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Get Internal RSA Pubkey: Device Not Found");
	if(!pucRetRsaPubKey)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Get Internal RSA Pubkey: Parameter Null");
	if(EncryptLength!=1||KeyIndex<1||KeyIndex>128)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Get Internal RSA Pubkey: Parameter Index  Error");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_KEY_OPERATION;
	cmdBuf[2]=0x03;
	cmdBuf[3]=SENC_KEYS_GET_RSA_PUBLIC_KEY;
	cmdBuf[4]=EncryptLength;
	cmdBuf[5]=KeyIndex;


	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_KEY_OPERATION<<4)|SENC_KEYS_GET_RSA_PUBLIC_KEY));
		ERROR_LOG(ucRet,"CMD Get Internal RSA Pubkey: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		if(revBuf[6]!=EncryptLength)
		{
			ucRet = ERROR_LOG(SENC_ERROR_RETURN_ENC_ATTRIBUTES_NOT_MATCH,"CMD Get Internal RSA Pubkey: Returned Attributes Not Match");
			break;
		}

		//public key receiving
		memcpy(pucRetRsaPubKey,revBuf+7,512);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_Key_Symmetric_Key_Generate()
//*���ܣ�AES��Կ����|| Generate an AES key
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char		EncryptLength				//���ܳ���128|256
//		unsigned char		InAesKeyIndex				//AES��Կ�洢����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Symmetric_Key_Generate(SENCryptCard*	sencDev,			//���ܿ��豸handle
												 unsigned char	EncryptLength,		//���ܷ�ʽAES 128/AES 256/SM4
												 unsigned char	InAesKeyIndex)		//��Կ�洢����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Generate Symmetric Key: Device Not Found");

	switch (EncryptLength)
	{
	case 0x01:
	case 0x02:
		if(InAesKeyIndex<1||InAesKeyIndex>128)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Generate Symmetric Key: Parameter Index  Error");
		break;
	case 0x03:
		if(InAesKeyIndex<1||InAesKeyIndex>64)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Generate Symmetric Key: Parameter Index  Error");
		break;

	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Generate Symmetric Key: Parameter Type Error");
	}

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_KEY_OPERATION;
	cmdBuf[2]=0x03;
	cmdBuf[3]=SENC_KEYS_AES_KEY_GENERATION;
	cmdBuf[4]=EncryptLength;
	cmdBuf[5]=InAesKeyIndex;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_KEY_OPERATION<<4)|SENC_KEYS_AES_KEY_GENERATION));
		ERROR_LOG(ucRet,"CMD Generate Symmetric Key: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		if(revBuf[6]!=EncryptLength||revBuf[7]!=InAesKeyIndex)
		{
			ucRet = ERROR_LOG(SENC_ERROR_RETURN_ENC_ATTRIBUTES_NOT_MATCH,"CMD Generate Symmetric Key: Returned Attributes Not Match");
			break;
		}
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_Key_Import()
//*���ܣ���Կ����|| Import keys
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char		InAlgorithmType					//������Կ�㷨
//		unsigned char		InKeyIndex						//������ԿĿ������
//		unsigned char*		InKeyData						//������Կ����
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_Key_Import(SENCryptCard*		sencDev,			//���ܿ��豸handle
								 unsigned char		InAlgorithmType,	//������Կ�㷨
								 unsigned char		InKeyIndex,			//������ԿĿ������
								 unsigned char*		InKeyData)			//������Կ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Key Import: Device Not Found");
	if(!InKeyData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Key Import: Parameter Null");

	switch (InAlgorithmType)
	{
	case 0x01:
	case 0x02:
		if(InKeyIndex<65||InKeyIndex>128)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Key Import: Parameter Index Error");
		break;
	case 0x03:
		if(InKeyIndex<1||InKeyIndex>64)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Key Import: Parameter Index Error");
		break;

	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Key Import: Parameter Type Error");
	}	

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_KEY_OPERATION;
	cmdBuf[3]=SENC_KEYS_IMPORT_KEY;
	cmdBuf[4]=InAlgorithmType;
	cmdBuf[5]=InKeyIndex;

	//fill length and key data
	switch (InAlgorithmType)
	{
	case SENC_ALG_AES_128:
	case SENC_ALG_SM4:
		cmdBuf[2]=19;
		memcpy(cmdBuf+6,InKeyData,16);
		break;
	case SENC_ALG_AES_256:
		cmdBuf[2]=35;
		memcpy(cmdBuf+6,InKeyData,32);
		break;
	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Key Import: Parameter AlgoType Error");
	}

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_KEY_OPERATION<<4)|SENC_KEYS_IMPORT_KEY));
		ERROR_LOG(ucRet,"CMD Key Import: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//type and index check
		if(revBuf[6]!=InAlgorithmType||revBuf[7]!=InKeyIndex)
		{
			ucRet = ERROR_LOG(SENC_ERROR_RETURN_ENC_ATTRIBUTES_NOT_MATCH,"CMD Key Import: Returned Attributes Not Match");
			break;
		}
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_Key_Delete()
//*���ܣ���Կɾ��|| Delete a key
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char		EncryptType					//���ܷ�ʽ
//		unsigned char		ucDelKeyIndex				//ɾ��Ŀ����Կ����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Delete(SENCryptCard*	sencDev,			//���ܿ��豸handle
								 unsigned char	EncryptType,		//���ܷ�ʽ
								 unsigned char	ucDelKeyIndex)		//ɾ��Ŀ����Կ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Delete Key: Device Not Found");
	switch (EncryptType)
	{
	case 0x01:
	case 0x02:
	case 0x04:
		if(ucDelKeyIndex<1||ucDelKeyIndex>128)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Delete Key: Parameter Index Error");
		break;
	case 0x03:
		if(ucDelKeyIndex<1||ucDelKeyIndex>64)	//only 64 SM4 keys are stored
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Delete Key: Parameter Index Error");
		break;

	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Delete Key: Parameter Type Error");
	}

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_KEY_OPERATION;
	cmdBuf[2]=0x03;
	cmdBuf[3]=SENC_KEYS_DELETION;
	cmdBuf[4]=EncryptType;
	cmdBuf[5]=ucDelKeyIndex;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_KEY_OPERATION<<4)|SENC_KEYS_DELETION));
		ERROR_LOG(ucRet,"CMD Delete Key: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		if(revBuf[6]!=EncryptType||revBuf[7]!=ucDelKeyIndex)
		{
			ucRet = ERROR_LOG(SENC_ERROR_RETURN_ENC_ATTRIBUTES_NOT_MATCH,"CMD Delete Key: Returned Attributes Not Match");
			break;
		}
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_Key_Query()
//*���ܣ���Կ��ѯ|| Query for key state
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucAES128State					//����AES128��Կ״̬��
//		unsigned char*		pucAES256State					//����AES256��Կ״̬��
// 		unsigned char*		pucSM4State						//����SM4��Կ״̬��
// 		unsigned char*		pucRSA2048State					//����RSA2048��Կ״̬��
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Query(SENCryptCard*	sencDev,				//���ܿ��豸handle
								unsigned char*	pucAES128State,			//����AES128��Կ״̬��
								unsigned char*	pucAES256State,			//����AES256��Կ״̬��
								unsigned char*	pucSM4State,			//����SM4��Կ״̬��
								unsigned char*	pucRSA2048State)		//����RSA2048��Կ״̬��
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Key Query: Device Not Found");
	if(!pucAES128State&&!pucAES256State&&!pucSM4State&&!pucRSA2048State)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Key Query: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_KEY_OPERATION;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_KEYS_QUERY;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_KEY_OPERATION<<4)|SENC_KEYS_QUERY));
		ERROR_LOG(ucRet,"CMD Key Query: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//key type check
		if(revBuf[6]!=0x01||revBuf[23]!=0x02||revBuf[40]!=0x03||revBuf[49]!=0x04)
		{
			ucRet = ERROR_LOG(SENC_ERROR_RETURN_ENC_ATTRIBUTES_NOT_MATCH,"CMD Key Query: Returned Attributes Not Match");
			break;
		}

		//key state data, 16 bytes X 3 , SM4 has only 8 bytes(64 keys)
		if(pucAES128State)
			memcpy(pucAES128State,revBuf+7,16);
		if(pucAES256State)
			memcpy(pucAES256State,revBuf+24,16);
		if(pucSM4State)
			memcpy(pucSM4State,revBuf+41,8);
		if(pucRSA2048State)
			memcpy(pucRSA2048State,revBuf+50,16);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_Key_Backup()
//*���ܣ���Կ����|| Backup a key
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char		EncryptType						//���ܷ�ʽ
//		unsigned char		ucBakKeyIndex					//����Ŀ����Կ����
//		unsigned char*		pucBakKeyData					//���ر���Ŀ����Կ����
//		unsigned int*		pucBakKeyDataLength				//���ر���Ŀ����Կ���ݳ���
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Backup(SENCryptCard*		sencDev,				//���ܿ��豸handle
								 unsigned char		EncryptType,			//���ܷ�ʽ
								 unsigned char		ucBakKeyIndex,			//����Ŀ����Կ����
								 unsigned char*		pucBakKeyData,			//���ر���Ŀ����Կ����
								 unsigned int*		pucBakKeyDataLength)	//���ر���Ŀ����Կ���ݳ���
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Backup Key: Device Not Found");
	if(!pucBakKeyData||!pucBakKeyDataLength)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Backup Key: Parameter Null");
	switch (EncryptType)
	{
	case 0x01:
	case 0x02:
	case 0x04:
		if(ucBakKeyIndex<1||ucBakKeyIndex>128)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Backup Key: Parameter Index Error");
		break;
	case 0x03:
		if(ucBakKeyIndex<1||ucBakKeyIndex>64)	//only 64 SM4 keys are stored
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Backup Key: Parameter Index Error");
		break;

	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Backup Key: Parameter Type Error");
	}

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_KEY_OPERATION;
	cmdBuf[2]=0x03;
	cmdBuf[3]=SENC_KEYS_BACKUP;
	cmdBuf[4]=EncryptType;
	cmdBuf[5]=ucBakKeyIndex;

	switch (EncryptType)
	{
	case 1:
	case 2:
	case 3:
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		break;
	case 4:
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		break;
	default:
		break;
	}

	do{
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_KEY_OPERATION<<4)|SENC_KEYS_BACKUP));
		ERROR_LOG(ucRet,"CMD Backup Key: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		if(revBuf[6]!=EncryptType||revBuf[7]!=ucBakKeyIndex)
		{
			ucRet = ERROR_LOG(SENC_ERROR_RETURN_ENC_ATTRIBUTES_NOT_MATCH,"CMD Backup Key: Returned Attributes Not Match");
			break;
		}

		//returned key data, ciphertext
		memcpy(pucBakKeyData,revBuf+8,retLen-5);
		*pucBakKeyDataLength=retLen-5;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_Key_Recover()
//*���ܣ���Կ�ָ�|| Recover a key
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char		EncryptType						//���ܷ�ʽ
// 		unsigned char		ucBakKeyIndex					//����Ŀ����Կ����
// 		unsigned int		ucBakKeyDataLength				//����Ŀ����Կ���ݳ���
// 		unsigned char*		pucBakKeyData					//����Ŀ����Կ����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Recover(SENCryptCard*		sencDev,				//���ܿ��豸handle
								  unsigned char		EncryptType,			//���ܷ�ʽ
								  unsigned char		ucBakKeyIndex,			//����Ŀ����Կ����
								  unsigned int		ucBakKeyDataLength,		//����Ŀ����Կ���ݳ���
								  unsigned char*	pucBakKeyData)			//����Ŀ����Կ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Recover Key: Device Not Found");
	if(!pucBakKeyData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Recover Key: Parameter Null");
	switch (EncryptType)
	{
	case 0x01:
	case 0x02:
	case 0x04:
		if(ucBakKeyIndex<1||ucBakKeyIndex>128)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Recover Key: Parameter Index Error");
		break;
	case 0x03:
		if(ucBakKeyIndex<1||ucBakKeyIndex>64)	//only 64 SM4 keys are stored
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Recover Key: Parameter Index Error");
		break;

	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Recover Key: Parameter Type Error");
	}

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_KEY_OPERATION;
	cmdBuf[1]=((ucBakKeyDataLength+3)>>8)&0xff;
	cmdBuf[2]=(ucBakKeyDataLength+3)&0xff;
	cmdBuf[3]=SENC_KEYS_RECOVERY;
	cmdBuf[4]=EncryptType;
	cmdBuf[5]=ucBakKeyIndex;
	memcpy(cmdBuf+6,pucBakKeyData,ucBakKeyDataLength);

	do{
		if(ucBakKeyDataLength>0&&ucBakKeyDataLength<1024-6)
			ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		else if(ucBakKeyDataLength>=1024-6&&ucBakKeyDataLength<2048-6)
			ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		else
		{
			ucRet = ERROR_LOG(SENC_ERROR_DATA_OVERFLOW,"CMD Recover Key: Data Overflow");
			break;
		}

		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_KEY_OPERATION<<4)|SENC_KEYS_RECOVERY));
		ERROR_LOG(ucRet,"CMD Recover Key: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//algorithm type and index check
		if(revBuf[6]!=EncryptType||revBuf[7]!=ucBakKeyIndex)
		{
			ucRet = ERROR_LOG(SENC_ERROR_RETURN_ENC_ATTRIBUTES_NOT_MATCH,"CMD Recover Key: Returned Attributes Not Match");
			break;
		}
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_Product_SetCardId()
//*���ܣ����ü��ܿ�ID|| Set the ID of encrypt card
//*������SENCryptCard*		sencDev				//���ܿ��豸handle
// 		unsigned char*		pucEcardId			//���ü��ܿ�ID
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_SetCardId(SENCryptCard*		sencDev,		//���ܿ��豸handle
										unsigned char*		pucEcardId)		//���ü��ܿ�ID
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Set Card ID: Device Not Found");
	if(!pucEcardId)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Set Card ID: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_PRODUCTION;
	cmdBuf[2] = 0x01 + 0x10;
	cmdBuf[3]=SENC_PRODUCT_SET_ID;
	memcpy(cmdBuf+4,pucEcardId,16); //senc card ID 8 bytes

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_PRODUCTION<<4)|SENC_PRODUCT_SET_ID));
		ERROR_LOG(ucRet,"CMD Set Card ID: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_Product_SetCardVersion()
//*���ܣ����ü��ܿ��汾��|| Set version of encrypt card
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
// 		unsigned char*		pucEcardHardwareVer				//���ü��ܿ�Ӳ���汾
// 		unsigned char*		pucEcardFirmwareVer				//���ü��ܿ��̼��汾
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_SetCardVersion(SENCryptCard*		sencDev,				//���ܿ��豸handle
											 unsigned char*		pucEcardHardwareVer,	//���ü��ܿ�Ӳ���汾
											 unsigned char*		pucEcardFirmwareVer)	//���ü��ܿ��̼��汾
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Set Card Version: Device Not Found");
	if(!pucEcardHardwareVer||!pucEcardFirmwareVer)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Set Card Version: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_PRODUCTION;
	cmdBuf[2]=0x11;
	cmdBuf[3]=SENC_PRODUCT_SET_VERSION;
	memcpy(cmdBuf+4,pucEcardHardwareVer,8); //hardware version 8 bytes
	memcpy(cmdBuf+12,pucEcardFirmwareVer,8); //firmware version 8 bytes

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_PRODUCTION<<4)|SENC_PRODUCT_SET_VERSION));
		ERROR_LOG(ucRet,"CMD Set Card Version: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_Product_GenerateFlashKey()
//*���ܣ�����FLASH��Կ|| Generate FLASH key
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_GenerateFlashKey(SENCryptCard*		sencDev)	//���ܿ��豸handle
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Generate Flash Key: Device Not Found");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_PRODUCTION;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_PRODUCT_GENERATE_FLASH_KEY;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_PRODUCTION<<4)|SENC_PRODUCT_GENERATE_FLASH_KEY));
		ERROR_LOG(ucRet,"CMD Generate Flash Key: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_Product_SetDHAttributes()
//*���ܣ�����Diffie Hellman��Կ������P,G����|| Set P&G for Diffie-Hellman key exchange
//*������SENCryptCard*		sencDev				//���ܿ��豸handle
// 		unsigned char*		pucP				//DH��Կ��������P
// 		unsigned char*		pucG				//DH��Կ��������G
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_SetDHAttributes(SENCryptCard*			sencDev,		//���ܿ��豸handle
											  unsigned char*		pucP,			//DH��Կ��������P
											  unsigned char*		pucG)			//DH��Կ��������G
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Set DH Arguments: Device Not Found");
	if(!pucP||!pucG)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Set DH Arguments: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_PRODUCTION;
	cmdBuf[2]=0x06;
	cmdBuf[3]=SENC_PRODUCT_SET_DH_PARAMETER;
	memcpy(cmdBuf+4,pucP,4); //P, 4 bytes
	memcpy(cmdBuf+8,pucG,1); //g, 1 byte

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_PRODUCTION<<4)|SENC_PRODUCT_SET_DH_PARAMETER));
		ERROR_LOG(ucRet,"CMD Set DH Arguments: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}
//********************************************************************************************************//
//*������SENC_CMD_Product_SM2_Generate()
//*���ܣ����ɰ忨�豸��Կ��|| Generate Senc Card RSA Keys;
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
// 		 uint8_t			EncryptLength				//���ܳ���
// 		 uint8_t			RsaKeyIdx					//RSA��Կ�洢����
//*���ڣ�2018/11/1
//by Zhang Tao
unsigned int SENC_CMD_Product_SM2_Generate(SENCryptCard*	sencDev,
										   uint8_t			EncryptLength,
										   uint8_t			RsaKeyIdx)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE] = { 0 };
	unsigned char revBuf[SENC_BUFFER_SIZE] = { 0 };

	//param check
	if (!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "CMD RSAKey Generate: Device Not Found");
	if (EncryptLength != 0x02)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "CMD RSAKey Generate: Parameter Type Error");
	if (RsaKeyIdx<1 || RsaKeyIdx>128)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "CMD RSAKey Generate: Parameter Index Error");

	//frame buildup
	cmdBuf[0] = SENC_CMD_PRODUCTION;
	cmdBuf[1] = (0x01 + 2 * sizeof(uint8_t)) >> 8;
	cmdBuf[2] = (0x01 + 2 * sizeof(uint8_t)) & 0xff;
	cmdBuf[3] = SENC_PRODUCT_GENERATE_RSA_KEY;
	cmdBuf[4] = EncryptLength;
	cmdBuf[5] = RsaKeyIdx;

	do{
		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_1K, SENC_BULK_ENDPOINT_READ_1K, cmdBuf, SENC_TRANSFER_LENGTH_1K, revBuf, SENC_TRANSFER_LENGTH_1K);
		if (ucRet != SENC_SUCCESS)
			break;

		ucRet = RetCheck(revBuf, &retLen, ((SENC_CMD_PRODUCTION << 4) | SENC_PRODUCT_GENERATE_RSA_KEY));
		ERROR_LOG(ucRet, "CMD RSAKey Generate: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;
	} while (0);

	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	memset(revBuf, 0x00, sizeof(revBuf));

	return ucRet;
}
//********************************************************************************************************//
//*������SENC_CMD_Product_RequestCSR()
//*���ܣ����豸����CSR|| Request CSR From Device;
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
// 		 uint32_t*			CsrLen						//����CSR����
// 		 uint8_t*			Csr							//����CSR����
//*���ڣ�2018/11/1
//by Zhang Tao
unsigned int SENC_CMD_Product_RequestCSR(SENCryptCard*	sencDev,
										 uint32_t*		CsrLen,
										 uint8_t*		Csr)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE] = { 0 };
	unsigned char revBuf[SENC_BUFFER_SIZE] = { 0 };

	//param check
	if (!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "CMD Request CSR: Device Not Found");
	if (!CsrLen || !Csr)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "CMD Request CSR: Parameter Null");

	//frame buildup
	cmdBuf[0] = SENC_CMD_PRODUCTION;
	cmdBuf[2] = 0x01;
	cmdBuf[3] = SENC_PRODUCT_REQUEST_CSR;

	do{
		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_2K, SENC_BULK_ENDPOINT_READ_2K, cmdBuf, SENC_TRANSFER_LENGTH_2K, revBuf, SENC_TRANSFER_LENGTH_2K);
		if (ucRet != SENC_SUCCESS)
			break;

		ucRet = RetCheck(revBuf, &retLen, ((SENC_CMD_PRODUCTION << 4) | SENC_PRODUCT_REQUEST_CSR));
		ERROR_LOG(ucRet, "CMD Request CSR: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;
		*CsrLen = (revBuf[6] << 8) + revBuf[7];
		memcpy(Csr, revBuf + 6 + 2, (*CsrLen));
	} while (0);

	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	memset(revBuf, 0x00, sizeof(revBuf));

	return ucRet;
}
//********************************************************************************************************//
//*������SENC_CMD_Product_DownLoadCert()
//*���ܣ�����֤��|| Download Certification;
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
// 		 uint8_t			CertType					//֤������
// 		 uint32_t			CertLen						//֤�鳤��
// 		 uint8_t*			Cert						//֤������
//*���ڣ�2018/11/1
//by Zhang Tao
unsigned int SENC_CMD_Product_DownLoadCert(SENCryptCard*	sencDev,
										   uint8_t			CertType,
										   uint32_t			CertLen,
										   uint8_t*			Cert)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE] = { 0 };
	unsigned char revBuf[SENC_BUFFER_SIZE] = { 0 };

	//param check
	if (!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "CMD DownLoad Cert: Device Not Found");
	if (!Cert)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "CMD DownLoad Cert: Parameter Null");

	//frame buildup
	cmdBuf[0] = SENC_CMD_PRODUCTION;
	cmdBuf[1] = (0x04 + CertLen) >> 8;
	cmdBuf[2] = (0x04 + CertLen) & 0xff;
	cmdBuf[3] = SENC_PRODUCT_DOWNLOAD_CERT;
	memcpy(cmdBuf + 4, &CertType, 1);
	cmdBuf[5] = CertLen >> 8;
	cmdBuf[6] = CertLen & 0xff;
	memcpy(cmdBuf + 0x07, Cert, CertLen);

	do{
		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_2K, SENC_BULK_ENDPOINT_READ_2K, cmdBuf, SENC_TRANSFER_LENGTH_2K, revBuf, SENC_TRANSFER_LENGTH_2K);
		if (ucRet != SENC_SUCCESS)
			break;

		ucRet = RetCheck(revBuf, &retLen, ((SENC_CMD_PRODUCTION << 4) | SENC_PRODUCT_DOWNLOAD_CERT));
		ERROR_LOG(ucRet, "CMD DownLoad Cert: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;
	} while (0);

	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	memset(revBuf, 0x00, sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_Product_SetDefault()
//*���ܣ�����Ϊ����״̬|| Set to default state
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_SetDefault(SENCryptCard* sencDev)	//���ܿ��豸handle
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Set Default: Device Not Found");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_PRODUCTION;
	cmdBuf[2]=0x01;
	cmdBuf[3]=SENC_PRODUCT_SET_DONE;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_PRODUCTION<<4)|SENC_PRODUCT_SET_DONE));
		ERROR_LOG(ucRet,"CMD Set Default: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_ProTest_RSA_Signature()
//*���ܣ���������RSAǩ��|| Signature by RSA in production
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		rsaKey							//rsa private key
//		unsigned char*		pucInData						//��ǩ������
//		unsigned char*		pucSignedData					//ǩ����������
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_RSA_Signature(SENCryptCard*	sencDev,				//���ܿ��豸handle
											unsigned char*	rsaKey,					//rsa private key
											unsigned char*	pucInData,				//��ǩ������
											unsigned char*	pucSignedData)			//ǩ����������
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD RSA Test: Device Not Found");
	if(!pucInData||!pucSignedData||!rsaKey)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD RSA Test: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//�������ݷ�֡
	cmdBuf[0]=SENC_CMD_PRO_TEST;	//��������
	cmdBuf[1]=((256+1412+1)>>8)&0xff; //����
	cmdBuf[2]=(256+1412+1)&0xff;
	cmdBuf[3]=SENC_PRO_TEST_RSA_SIGNATURE;//��������
	memcpy(cmdBuf+4,rsaKey,1412);//��ǩ������
	memcpy(cmdBuf+1412+4,pucInData,256);//��ǩ������
	reverse(cmdBuf+1412+4,256);//Little Endian ת��

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_PRO_TEST<<4)|SENC_PRO_TEST_RSA_SIGNATURE));
		ERROR_LOG(ucRet,"CMD RSA Test: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//תΪBig Endian
		reverse(revBuf+6,256);
		memcpy(pucSignedData,revBuf+6,256);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_ProTest_AES_Encrypt()
//*���ܣ���������AES����(256 ECB)|| AES encryption test in production (256 ECB)
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pwkey							//AES key
//		unsigned char*		pucInData						//����������
//		unsigned char*		pucSignedData					//���ؼ�������(256 ECB)
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_AES_Encrypt(SENCryptCard*		sencDev,				//���ܿ��豸handle
										  unsigned char*	pwkey,					//AES key
										  unsigned char*	pucInData,				//����������
										  unsigned char*	pucSignedData)			//���ؼ�������(256 ECB)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD AES Test: Device Not Found");
	if(!pucInData||!pucSignedData||!pwkey)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD AES Test: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//�������ݷ�֡
	cmdBuf[0]=SENC_CMD_PRO_TEST;	//��������
	cmdBuf[1]=((256+32+1)>>8)&0xff; //����
	cmdBuf[2]=(256+32+1)&0xff;
	cmdBuf[3]=SENC_PRO_TEST_AES_ENCRYPTION;//��������
	memcpy(cmdBuf+4,pwkey,32);//��ǩ������
	memcpy(cmdBuf+36,pucInData,256);//��ǩ������

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_PRO_TEST<<4)|SENC_PRO_TEST_AES_ENCRYPTION));
		ERROR_LOG(ucRet,"CMD AES Test: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//encrypted by AES256 ECB
		memcpy(pucSignedData,revBuf+6,256);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//*������SENC_CMD_ProTest_Write_NoEP()
//*���ܣ�д���ݲ���(�˷���)|| data write test without eject-proof
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucInData						//д���������
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_Write_NoEP(SENCryptCard*	sencDev,				//���ܿ��豸handle
										 unsigned char*	pucInData)				//д���������
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Write NoEP Test: Device Not Found");
	if(!pucInData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Write NoEP Test: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//�������ݷ�֡
	cmdBuf[0]=SENC_CMD_PRO_TEST;	//��������
	cmdBuf[1]=((256+1)>>8)&0xff; //����
	cmdBuf[2]=(256+1)&0xff;
	cmdBuf[3]=SENC_PRO_TEST_WRITE_NO_PROTECT;//��������
	memcpy(cmdBuf+4,pucInData,256);//д���������
	// 	reverse(cmdBuf+4,256);//Little Endian ת��???? necessary?

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_PRO_TEST<<4)|SENC_PRO_TEST_WRITE_NO_PROTECT));
		ERROR_LOG(ucRet,"CMD Write NoEP Test: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_ProTest_Write_EP()
//*���ܣ�д���ݲ���(δ�˷���)|| data write test with eject-proof
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucInData						//д���������
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_Write_EP(SENCryptCard*	sencDev,				//���ܿ��豸handle
									   unsigned char*	pucInData)				//д���������
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Write EP Test: Device Not Found");
	if(!pucInData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Write EP Test: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//�������ݷ�֡
	cmdBuf[0]=SENC_CMD_PRO_TEST;	//��������
	cmdBuf[1]=((256+1)>>8)&0xff; //����
	cmdBuf[2]=(256+1)&0xff;
	cmdBuf[3]=SENC_PRO_TEST_WRITE_EJECT_PROTECT;//��������
	memcpy(cmdBuf+4,pucInData,256);//д���������
	// 	reverse(cmdBuf+4,256);//Little Endian ת��???? necessary?

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_PRO_TEST<<4)|SENC_PRO_TEST_WRITE_EJECT_PROTECT));
		ERROR_LOG(ucRet,"CMD Write EP Test: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_ProTest_Read()
//*���ܣ������ݲ���|| data read test
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucRetData						//���ض�ȡ����
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_Read(SENCryptCard*	sencDev,				//���ܿ��豸handle
								   unsigned char*	pucRetData)				//���ض�ȡ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Read Test: Device Not Found");
	if(!pucRetData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Read Test: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//�������ݷ�֡
	cmdBuf[0]=SENC_CMD_PRO_TEST;	//��������
	cmdBuf[1]=((1)>>8)&0xff; //����
	cmdBuf[2]=(1)&0xff;
	cmdBuf[3]=SENC_PRO_TEST_READ;//��������

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_PRO_TEST<<4)|SENC_PRO_TEST_READ));
		ERROR_LOG(ucRet,"CMD Read Test: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
		//תΪBig Endian
		// 	reverse(revBuf+6,256);
		memcpy(pucRetData,revBuf+6,256);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//*������SENC_CMD_ProTest_Flash_sweep()
//*���ܣ�FLASH���ݲ���|| flash memory sweeper
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_Flash_sweep(SENCryptCard*	sencDev)				//���ܿ��豸handle
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Flash Sweeper: Device Not Found");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//�������ݷ�֡
	cmdBuf[0]=SENC_CMD_PRO_TEST;	//��������
	cmdBuf[1]=((1)>>8)&0xff; //����
	cmdBuf[2]=(1)&0xff;
	cmdBuf[3]=SENC_PRO_TEST_FLASH_SWEEP;//��������

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_PLAINTEXT_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,((SENC_CMD_PRO_TEST<<4)|SENC_PRO_TEST_FLASH_SWEEP));
		ERROR_LOG(ucRet,"CMD Flash Sweeper: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

#if defined __ALTER_ON__


unsigned int SENC_CMD_Alternative_Hash(SENCryptCard*	sencDev,				//���ܿ��豸handle
									   unsigned char hashAlgo,
									   const unsigned char* inData,
									   unsigned int inDataLen,
									   unsigned char*	pucRetData,
									   unsigned int* pucRetDataLen)				//���ض�ȡ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Hash: Device Not Found");
	if(!pucRetData||!inData||!pucRetDataLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD Hash: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//�������ݷ�֡
	cmdBuf[0]=SENC_CMD_ALTERNATIVE_HASH;	//��������
	cmdBuf[1]=((1+inDataLen)>>8)&0xff; //����
	cmdBuf[2]=(1+inDataLen)&0xff;
	cmdBuf[3]=hashAlgo;//��������
	memcpy(cmdBuf+4,inData,inDataLen);

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		//���������
		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_ALTERNATIVE_HASH&0xf)<<4)|hashAlgo));
		ERROR_LOG(ucRet,"CMD Hash: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		switch (hashAlgo)
		{
		case 0x01:
			memcpy(pucRetData,revBuf+6,20);
			*pucRetDataLen=20;
			break;
		case 0x02:
			memcpy(pucRetData,revBuf+6,32);
			*pucRetDataLen=32;
			break;
		case 0x03:
			memcpy(pucRetData,revBuf+6,64);
			*pucRetDataLen=64;
			break;
		default:
			break;
		}
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


unsigned int SENC_CMD_Alternative_GenRsaKeyPair(SENCryptCard*	sencDev,				//���ܿ��豸handle
												unsigned char keyBits,
												unsigned char EncAlgo,
												unsigned char EncIdx,
												unsigned char*	pucIV,
												unsigned char*	pucMAC,
												unsigned char*	pucRetRsaPrivKey,		//�����Ѽ���˽Կ����
												unsigned char*	pucRetRsaPubKey)		//�����Ѽ��ܹ�Կ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD GenRsaKeyPairAlter: Device Not Found");
	if(!pucRetRsaPrivKey||!pucRetRsaPubKey||!pucIV||!pucMAC)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD GenRsaKeyPairAlter: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_ALTERNATIVE_RSA;
	cmdBuf[2]=0x14;
	cmdBuf[3]=SENC_ALTERNATIVE_RSA_KEY_PAIR_GENERATION;
	cmdBuf[4]=keyBits;
	cmdBuf[5]=EncAlgo;
	cmdBuf[6]=EncIdx;
	memcpy(cmdBuf+7,pucIV,16);

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_ALTERNATIVE_RSA&0xf)<<4)|SENC_ALTERNATIVE_RSA_KEY_PAIR_GENERATION));
		ERROR_LOG(ucRet,"CMD GenRsaKeyPairAlter: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		//encryption mode check
		if(revBuf[6]!=keyBits)
		{
			ucRet = ERROR_LOG(SENC_ERROR_RETURN_ENC_ATTRIBUTES_NOT_MATCH,"CMD GenRsaKeyPairAlter: Returned Attributes Not Match");
			break;
		}

		//private key data 1412 + 16 ��+ 16 iv?�� bytes
		memcpy(pucRetRsaPrivKey,revBuf+7,SENC_RSA_PRIVATE_KEY_LENGTH);
		memcpy(pucMAC,revBuf+7+SENC_RSA_PRIVATE_KEY_LENGTH,SENC_ENC_MAC_LENGTH);

		//public key data 512 bytes n->e (only rsa2048 available)
		/*
		if(revBuf[6]==0x01)
		memcpy(pucRetRsaPubKey,revBuf+647,256);
		else if(revBuf[6]==0x02)
		memcpy(pucRetRsaPubKey,revBuf+647,512);
		*/
		memcpy(pucRetRsaPubKey,revBuf+7+SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_MAC_LENGTH+SENC_ENC_IV_LENGTH,SENC_RSA_PUBLIC_KEY_LENGTH);
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


unsigned int SENC_CMD_Alternative_SignatureExternal(SENCryptCard*	sencDev,				//���ܿ��豸handle
													unsigned char keyBits,
													unsigned char EncAlgo,
													unsigned char EncIdx,
													unsigned char*	pucIV,
													unsigned char*	pucMAC,
													unsigned char*	pucRsaPrivKey,		//�����Ѽ���˽Կ����
													unsigned char*	inData,
													unsigned char* retSignedData)		//�����Ѽ��ܹ�Կ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD RSA SignExAlter: Device Not Found");
	if(!pucRsaPrivKey||!retSignedData||!pucIV||!pucMAC||!inData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD RSA SignExAlter: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_ALTERNATIVE_RSA;
	cmdBuf[1]=(1444+256+4)>>8;
	cmdBuf[2]=(1444+256+4)&0xff;
	cmdBuf[3]=SENC_ALTERNATIVE_RSA_SIGNATURE_EXTERNAL;
	cmdBuf[4]=keyBits;
	cmdBuf[5]=EncAlgo;
	cmdBuf[6]=EncIdx;
	memcpy(cmdBuf+7,pucRsaPrivKey,1412);
	memcpy(cmdBuf+7+1412,pucMAC,16);
	memcpy(cmdBuf+7+1412+16,pucIV,16);
	memcpy(cmdBuf+7+1444,inData,256);

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_ALTERNATIVE_RSA&0xf)<<4)|SENC_ALTERNATIVE_RSA_SIGNATURE_EXTERNAL));
		ERROR_LOG(ucRet,"CMD RSA SignExAlter: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(retSignedData,revBuf+6,256);

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


unsigned int SENC_CMD_Alternative_VerifyExternal(SENCryptCard*	sencDev,				//���ܿ��豸handle
												 unsigned char keyBits,
												 unsigned char*	pucRsaPubKey,		//�����Ѽ���˽Կ����
												 unsigned char*	inSignedData,
												 unsigned char* retDecrypto)		//�����Ѽ��ܹ�Կ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD RSA VeriExAlter: Device Not Found");
	if(!pucRsaPubKey||!inSignedData||!retDecrypto)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD RSA VeriExAlter: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_ALTERNATIVE_RSA;
	cmdBuf[1]=(516+256+2)>>8;
	cmdBuf[2]=(516+256+2)&0xff;
	cmdBuf[3]=SENC_ALTERNATIVE_RSA_VIRIFY_EXTERNAL;
	cmdBuf[4]=keyBits;
	cmdBuf[6]=0x08;

	memcpy(cmdBuf+9,pucRsaPubKey,512);
	memcpy(cmdBuf+9+512,inSignedData,256);

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_ALTERNATIVE_RSA&0xf)<<4)|SENC_ALTERNATIVE_RSA_VIRIFY_EXTERNAL));
		ERROR_LOG(ucRet,"CMD RSA VeriExAlter: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(retDecrypto,revBuf+6,256);

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


unsigned int SENC_CMD_Alternative_SignatureInternal(SENCryptCard*	sencDev,				//���ܿ��豸handle
													unsigned char keyBits,
													unsigned char KeyIdx,
													unsigned char*	inData,
													unsigned char* retSignedData)		//�����Ѽ��ܹ�Կ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD RSA SignInAlter: Device Not Found");
	if(!retSignedData||!inData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD RSA SignInAlter: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_ALTERNATIVE_RSA;
	cmdBuf[1]=(256+3)>>8;
	cmdBuf[2]=(256+3)&0xff;
	cmdBuf[3]=SENC_ALTERNATIVE_RSA_SIGNATURE_INTERNAL;
	cmdBuf[4]=keyBits;
	cmdBuf[5]=KeyIdx;

	memcpy(cmdBuf+6,inData,256);

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_ALTERNATIVE_RSA&0xf)<<4)|SENC_ALTERNATIVE_RSA_SIGNATURE_INTERNAL));
		ERROR_LOG(ucRet,"CMD RSA SignInAlter: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(retSignedData,revBuf+6,256);

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


unsigned int SENC_CMD_Alternative_VerifyInternal(SENCryptCard*	sencDev,				//���ܿ��豸handle
												 unsigned char keyBits,
												 unsigned char KeyIdx,
												 unsigned char* inSignedData,
												 unsigned char* retDecrypto)		//�����Ѽ��ܹ�Կ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD RSA VeriInAlter: Device Not Found");
	if(!inSignedData||!retDecrypto)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD RSA VeriInAlter: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_ALTERNATIVE_RSA;
	cmdBuf[1]=(256+3)>>8;
	cmdBuf[2]=(256+3)&0xff;
	cmdBuf[3]=SENC_ALTERNATIVE_RSA_VIRIFY_INTERNAL;
	cmdBuf[4]=keyBits;
	cmdBuf[5]=KeyIdx;
	memcpy(cmdBuf+6,inSignedData,256);

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_ALTERNATIVE_RSA&0xf)<<4)|SENC_ALTERNATIVE_RSA_VIRIFY_INTERNAL));
		ERROR_LOG(ucRet,"CMD RSA VeriInAlter: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(retDecrypto,revBuf+6,256);

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


unsigned int SENC_CMD_Alternative_PBKDF2Encrypt(SENCryptCard*	sencDev,				//���ܿ��豸handle
												unsigned char hashAlgo,
												unsigned char hashSaltAttr,
												unsigned int iteration,
												unsigned int outputKeyLen,
												unsigned char* inSaltData,
												unsigned int inSaltLen,
												unsigned char* inKeyData,
												unsigned int inKeyLen,
												unsigned char* outputKey)		//�����Ѽ��ܹ�Կ����
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE];
	unsigned char revBuf[SENC_BUFFER_SIZE];

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD PBKDF2 Enc: Device Not Found");
	if(!inSaltData||!inKeyData||!outputKey)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"CMD PBKDF2 Enc: Parameter Null");

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	//frame buildup
	cmdBuf[0]=SENC_CMD_ALTERNATIVE_PBKDF2;
	cmdBuf[1]=((inSaltLen+inKeyLen+10)>>8)&0xff;
	cmdBuf[2]=(inSaltLen+inKeyLen+10)&0xff;
	cmdBuf[3]=hashAlgo;
	cmdBuf[4]=(inKeyLen>>8)&0xff;
	cmdBuf[5]=inKeyLen&0xff;
	cmdBuf[6]=hashSaltAttr;
	cmdBuf[7]=(inSaltLen>>8)&0xff;
	cmdBuf[8]=inSaltLen&0xff;
	cmdBuf[9]=(iteration>>8)&0xff;
	cmdBuf[10]=iteration&0xff;
	cmdBuf[11]=(outputKeyLen>>8)&0xff;
	cmdBuf[12]=outputKeyLen&0xff;
	memcpy(cmdBuf+13,inKeyData,inKeyLen);
	memcpy(cmdBuf+13+inKeyLen,inSaltData,inSaltLen);

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_ALTERNATIVE_PBKDF2&0xf)<<4)|hashAlgo));
		ERROR_LOG(ucRet,"CMD PBKDF2 Enc: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(outputKey,revBuf+6,outputKeyLen);

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

#endif

#if defined __DATA_PROTECTOR_ON__
//ǩ���û���Կ
unsigned int SENC_CMD_DataProtector_SignUserPubKey(SENCryptCard* IN sencDev,				
												   UserPubKey* IN  userkey,
												   UserPubKey* OUT userkey_new)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE]={0};
	unsigned char revBuf[SENC_BUFFER_SIZE]={0};

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD SignUserPubkey: Device Not Found");

	//frame buildup
	cmdBuf[0]=SENC_CMD_DATA_PROTECTION;
	cmdBuf[1]=(sizeof(UserPubKey)+4)>>8;
	cmdBuf[2]=(sizeof(UserPubKey)+4)&0xff;
	cmdBuf[3]=DP_SIGN_USER_PUB_KEY;
	memcpy(cmdBuf+4,userkey,sizeof(UserPubKey));

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_DATA_PROTECTION&0xf)<<4)|DP_SIGN_USER_PUB_KEY));
		ERROR_LOG(ucRet,"CMD SignUserPubkey: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(userkey_new, revBuf+6, sizeof(UserPubKey));

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//�����ƶ���Կ
unsigned int SENC_CMD_DataProtector_GenWebKey(SENCryptCard*	IN sencDev,				
											  KeyRecordRequest* IN req, 
											  UserPubKey* IN userPubKey,
											  KeyRecord* OUT key)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE]={0};
	unsigned char revBuf[SENC_BUFFER_SIZE]={0};

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD GenerateWebKey: Device Not Found");

	//frame buildup
	cmdBuf[0]=SENC_CMD_DATA_PROTECTION;
	cmdBuf[1]=(sizeof(KeyRecordRequest)+sizeof(UserPubKey)+4)>>8;
	cmdBuf[2]=(sizeof(KeyRecordRequest)+sizeof(UserPubKey)+4)&0xff;
	cmdBuf[3]=DP_GEN_WEB_KEY;
	memcpy(cmdBuf+4,req,sizeof(KeyRecordRequest));
	memcpy(cmdBuf+4+sizeof(KeyRecordRequest), userPubKey, sizeof(UserPubKey));

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_DATA_PROTECTION&0xf)<<4)|DP_GEN_WEB_KEY));
		ERROR_LOG(ucRet,"CMD GenerateWebKey: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(key,revBuf+6,sizeof(KeyRecord));

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

//�����ƶ���Կ��Ч��
unsigned int SENC_CMD_DataProtector_SetWebKeyPeriod(SENCryptCard* IN sencDev,				
													KeyRecord* IN key,
													UserPubKey*	IN userPubKey,
													KeyPeriod*	IN keyPeriod,
													KeyRecord*	OUT key_new)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE]={0};
	unsigned char revBuf[SENC_BUFFER_SIZE]={0};

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD SetWebKeyPeriod: Device Not Found");

	//frame buildup
	cmdBuf[0]=SENC_CMD_DATA_PROTECTION;
	cmdBuf[1]=(sizeof(UserPubKey)+sizeof(KeyPeriod)+sizeof(KeyRecord)+4)>>8;
	cmdBuf[2]=(sizeof(UserPubKey)+sizeof(KeyPeriod)+sizeof(KeyRecord)+4)&0xff;
	cmdBuf[3]=DP_SET_WEB_KEY_PERIOD;
	memcpy(cmdBuf+4,key,sizeof(KeyRecord));
	memcpy(cmdBuf+4+sizeof(KeyRecord), userPubKey, sizeof(UserPubKey));
	memcpy(cmdBuf+4+sizeof(KeyRecord)+sizeof(UserPubKey), keyPeriod, sizeof(KeyPeriod));

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_DATA_PROTECTION&0xf)<<4)|DP_SET_WEB_KEY_PERIOD));
		ERROR_LOG(ucRet,"CMD SetWebKeyPeriod: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(key_new,revBuf+6,sizeof(KeyRecord));

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}


//������Կ����S1
unsigned int SENC_CMD_DataProtector_GenS1(SENCryptCard*	IN sencDev,
										  KeyRecord* IN key,
										  UserPubKey* IN userkey,
										  License* IN license,
										  S1Cipher* OUT S1_E_Kc,
										  S1Cipher* OUT S1_E_Ku,
										  License* OUT license_new)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE]={0};
	unsigned char revBuf[SENC_BUFFER_SIZE]={0};

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD Generate S1Key: Device Not Found");

	//frame buildup
	cmdBuf[0]=SENC_CMD_DATA_PROTECTION;
	cmdBuf[1]=(sizeof(KeyRecord)+sizeof(UserPubKey)+sizeof(License)+4)>>8;
	cmdBuf[2]=(sizeof(KeyRecord)+sizeof(UserPubKey)+sizeof(License)+4)&0xff;
	cmdBuf[3]=DP_GEN_KEY_SEED_S1;
	memcpy(cmdBuf+4,key,sizeof(KeyRecord));
	memcpy(cmdBuf+4+sizeof(KeyRecord),userkey,sizeof(UserPubKey));
	memcpy(cmdBuf+4+sizeof(KeyRecord)+sizeof(UserPubKey),license,sizeof(License));

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_DATA_PROTECTION&0xf)<<4)|DP_GEN_KEY_SEED_S1));
		ERROR_LOG(ucRet,"CMD Generate S1Key: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(S1_E_Kc,revBuf+6,sizeof(S1Cipher));
		memcpy(S1_E_Ku,revBuf+6+sizeof(S1Cipher),sizeof(S1Cipher));
		memcpy(license_new,revBuf+6+sizeof(S1Cipher)*2,sizeof(License));

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}
//ǩ�����
unsigned int SENC_CMD_DataProtector_IssueLicense(SENCryptCard* IN sencDev,
												 KeyRecord* IN key,
												 UserPubKey* IN userkey,
												 uint8_t* IN LicID,
												 License* IN fatherLic,
												 LicenseRequest* IN LicReq,
												 License* OUT Lic)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE]={0};
	unsigned char revBuf[SENC_BUFFER_SIZE]={0};

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD IssueLicense: Device Not Found");

	//frame buildup
	cmdBuf[0]=SENC_CMD_DATA_PROTECTION;
	cmdBuf[3]=DP_ISSUE_LICENSE;
	memcpy(cmdBuf+4,key,sizeof(KeyRecord));
	memcpy(cmdBuf+4+sizeof(KeyRecord),userkey,sizeof(UserPubKey));
	memcpy(cmdBuf+4+sizeof(KeyRecord)+sizeof(UserPubKey),LicID,16);

	if(fatherLic==NULL){
		cmdBuf[1]=(sizeof(KeyRecord)+sizeof(UserPubKey)+sizeof(LicenseRequest)+20)>>8;
		cmdBuf[2]=(sizeof(KeyRecord)+sizeof(UserPubKey)+sizeof(LicenseRequest)+20)&0xff;
		memcpy(cmdBuf+20+sizeof(KeyRecord)+sizeof(UserPubKey),LicReq,sizeof(LicenseRequest));
	}else{
		cmdBuf[1]=(sizeof(KeyRecord)+sizeof(UserPubKey)+sizeof(LicenseRequest)+sizeof(License)+20)>>8;
		cmdBuf[2]=(sizeof(KeyRecord)+sizeof(UserPubKey)+sizeof(LicenseRequest)+sizeof(License)+20)&0xff;
		memcpy(cmdBuf+20+sizeof(KeyRecord)+sizeof(UserPubKey),fatherLic,sizeof(License));
		memcpy(cmdBuf+20+sizeof(KeyRecord)+sizeof(UserPubKey)+sizeof(License),LicReq,sizeof(LicenseRequest));
	}

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_DATA_PROTECTION&0xf)<<4)|DP_ISSUE_LICENSE));
		ERROR_LOG(ucRet,"CMD IssueLicense: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(Lic,revBuf+6,sizeof(License));

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}
//ת������
unsigned int SENC_CMD_DataProtector_CipherConvert(SENCryptCard*	IN sencDev,
												  KeyRecord* IN key,
												  UserPubKey* IN userkey,
												  License* IN Lic,
												  S1Cipher* IN S1_E_Kc,
												  S1Cipher* IN S1_E_Ku,
												  License* OUT Lic_new)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE]={0};
	unsigned char revBuf[SENC_BUFFER_SIZE]={0};

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD ConvertCipher: Device Not Found");

	//frame buildup
	cmdBuf[0]=SENC_CMD_DATA_PROTECTION;
	cmdBuf[3]=DP_CIPHER_CONVERT;
	memcpy(cmdBuf+4,key,sizeof(KeyRecord));
	memcpy(cmdBuf+4+sizeof(KeyRecord),userkey,sizeof(UserPubKey));

	if(Lic==NULL){
		cmdBuf[1]=(sizeof(KeyRecord)+sizeof(UserPubKey)+sizeof(S1Cipher)+4)>>8;
		cmdBuf[2]=(sizeof(KeyRecord)+sizeof(UserPubKey)+sizeof(S1Cipher)+4)&0xff;
		memcpy(cmdBuf+4+sizeof(KeyRecord)+sizeof(UserPubKey),S1_E_Kc,sizeof(S1Cipher));
	}else{
		cmdBuf[1]=(sizeof(KeyRecord)+sizeof(UserPubKey)+sizeof(License)+sizeof(S1Cipher)+4)>>8;
		cmdBuf[2]=(sizeof(KeyRecord)+sizeof(UserPubKey)+sizeof(License)+sizeof(S1Cipher)+4)&0xff;
		memcpy(cmdBuf+4+sizeof(KeyRecord)+sizeof(UserPubKey),Lic,sizeof(License));
		memcpy(cmdBuf+4+sizeof(KeyRecord)+sizeof(UserPubKey)+sizeof(License),S1_E_Kc,sizeof(S1Cipher));
	}


	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_DATA_PROTECTION&0xf)<<4)|DP_CIPHER_CONVERT));
		ERROR_LOG(ucRet,"CMD ConvertCipher: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		if(Lic==NULL){
			memcpy(S1_E_Ku,revBuf+6,sizeof(S1Cipher));
		}else{
			memcpy(S1_E_Ku,revBuf+6,sizeof(S1Cipher));
			memcpy(Lic_new,revBuf+6+sizeof(S1Cipher),sizeof(License));
		}
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

unsigned int SENC_CMD_DataProtector_SetMacCalculateKey(SENCryptCard* IN sencDev,
													   uint8_t* data, 
													   uint32_t datalen)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE]={0};
	unsigned char revBuf[SENC_BUFFER_SIZE]={0};

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD ConvertCipher: Device Not Found");

	//frame buildup
	cmdBuf[0]=SENC_CMD_DATA_PROTECTION;
	cmdBuf[1]=((datalen+2)>>8)%0xff;
	cmdBuf[2]=(datalen+2)&0xff;
	cmdBuf[3]=DP_SET_CALC_KEY;
	cmdBuf[4]=DP_SCK_MAC;
	memcpy(cmdBuf+5,data,datalen);

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_1K,SENC_BULK_ENDPOINT_READ_1K,cmdBuf,SENC_TRANSFER_LENGTH_1K,revBuf,SENC_TRANSFER_LENGTH_1K);
		if(ucRet!=SENC_SUCCESS)
			break;
		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_DATA_PROTECTION&0xf)<<4)|DP_SET_CALC_KEY));
		ERROR_LOG(ucRet,"CMD SetMacCalculateKey: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;
	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

unsigned int SENC_CMD_DataProtector_GetRTCTime(SENCryptCard* IN sencDev,
												   uint64_t* OUT RTCTime)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE]={0};
	unsigned char revBuf[SENC_BUFFER_SIZE]={0};

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD GetRTCTime: Device Not Found");

	//frame buildup
	cmdBuf[0]=SENC_CMD_DATA_PROTECTION;
	cmdBuf[1]=(4)>>8;
	cmdBuf[2]=(4)&0xff;
	cmdBuf[3]=DP_GET_RTC_TIME;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_DATA_PROTECTION&0xf)<<4)|DP_GET_RTC_TIME));
		ERROR_LOG(ucRet,"CMD GetRTCTime: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(RTCTime, revBuf+6, 8);

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}

unsigned int SENC_CMD_DataProtector_GetSupportedAlgorithm(SENCryptCard*	IN sencDev,
											   uint8_t* OUT supportedAlgorithm)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE]={0};
	unsigned char revBuf[SENC_BUFFER_SIZE]={0};

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD GetSupportedAlgorithm: Device Not Found");

	//frame buildup
	cmdBuf[0]=SENC_CMD_DATA_PROTECTION;
	cmdBuf[1]=(4)>>8;
	cmdBuf[2]=(4)&0xff;
	cmdBuf[3]=DP_GET_SUPPORTED_ALGORITHM;

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_DATA_PROTECTION&0xf)<<4)|DP_GET_SUPPORTED_ALGORITHM));
		ERROR_LOG(ucRet,"CMD GetSupportedAlgorithm: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

		memcpy(supportedAlgorithm, revBuf+6, 1);

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}



unsigned int SENC_CMD_DataProtector_SetRTCTime(SENCryptCard* IN sencDev,
											   uint8_t* IN PinCode,
											   uint64_t* IN TimeStamp)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE]={0};
	unsigned char revBuf[SENC_BUFFER_SIZE]={0};

	//param check
	if(!sencDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"CMD SetRTCTime: Device Not Found");

	//frame buildup
	cmdBuf[0]=SENC_CMD_DATA_PROTECTION;
	cmdBuf[1]=(20)>>8;
	cmdBuf[2]=(20)&0xff;
	cmdBuf[3]=DP_SET_RTC_TIME;
	memcpy(cmdBuf+4,PinCode,8);
	memcpy(cmdBuf+12,TimeStamp,8);

	do{
		ucRet=SENC_CMD_Transfer(sencDev,SENC_CIPHER_SIGN,SENC_BULK_ENDPOINT_WRITE_2K,SENC_BULK_ENDPOINT_READ_2K,cmdBuf,SENC_TRANSFER_LENGTH_2K,revBuf,SENC_TRANSFER_LENGTH_2K);
		if(ucRet!=SENC_SUCCESS)
			break;

		ucRet=RetCheck(revBuf,&retLen,(((SENC_CMD_DATA_PROTECTION&0xf)<<4)|DP_SET_RTC_TIME));
		ERROR_LOG(ucRet,"CMD SetRTCTime: Returned Error");
		if(ucRet!=SENC_SUCCESS)
			break;

	}while(0);

	memset(cmdBuf,0x00,sizeof(cmdBuf));
	memset(revBuf,0x00,sizeof(revBuf));

	return ucRet;
}



//��ȡ�忨��ʼ��״̬
unsigned int SENC_CMD_DataProtector_GetChipInitStatus(SENCryptCard* IN sencDev,
													  unsigned char*	OUT	pucRetState)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;

	unsigned char cmdBuf[SENC_BUFFER_SIZE] = { 0 };
	unsigned char revBuf[SENC_BUFFER_SIZE] = { 0 };

	//param check
	if (!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "CMD GetChipInitState: Device Not Found");
	if (!pucRetState)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "CMD GetChipInitState: Parameter Null");

	//frame buildup
	cmdBuf[0] = SENC_CMD_DOE_MANAGEMENT;
	cmdBuf[1] = 0x00;
	cmdBuf[2] = 0x01;
	cmdBuf[3] = DP_GET_CHIP_INIT_STATUS;

	do{
		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_1K, SENC_BULK_ENDPOINT_READ_1K, cmdBuf, SENC_TRANSFER_LENGTH_1K, revBuf, SENC_TRANSFER_LENGTH_1K);
		if (ucRet != SENC_SUCCESS)
			break;

		//ret-value check
		ucRet = RetCheck(revBuf, &retLen, (((SENC_CMD_DOE_MANAGEMENT & 0xf) << 4) | DP_GET_CHIP_INIT_STATUS));
		ERROR_LOG(ucRet, "CMD GetChipInitState: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;

		//card state 1byte
		memcpy(pucRetState, revBuf + 6, 1);
	} while (0);

	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	memset(revBuf, 0x00, sizeof(revBuf));

	return ucRet;
}

//�Ӱ忨��ȡ��ʼ�������
unsigned int SENC_CMD_DataProtector_GetInitReq(SENCryptCard* IN sencDev,
											   ChipInitRequest* OUT Req,
											   uint8_t* OUT CaCert,
											   uint32_t* OUT CaCertLen,
											   uint8_t* OUT Cert,
											   uint32_t* OUT CertLen,
											   uint8_t* OUT Pri,
											   uint8_t* OUT Pub)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned int offset;
	unsigned char cmdBuf[SENC_BUFFER_SIZE] = { 0 };
	unsigned char revBuf[SENC_BUFFER_SIZE] = { 0 };

	//param check
	if (!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "CMD GetInitReq: Device Not Found");

	//frame buildup
	cmdBuf[0] = SENC_CMD_DOE_MANAGEMENT;
	cmdBuf[1] = 0x00;
	cmdBuf[2] = 0x02;
	cmdBuf[3] = DP_GET_INIT_REQ;
	cmdBuf[4] = SENC_CERT_DEVICE;

	do{
		//�����ʼ���������Device Cert
		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_2K, SENC_BULK_ENDPOINT_READ_2K, cmdBuf, SENC_TRANSFER_LENGTH_2K, revBuf, SENC_TRANSFER_LENGTH_2K);
		if (ucRet != SENC_SUCCESS)
			break;

		ucRet = RetCheck(revBuf, &retLen, (((SENC_CMD_DOE_MANAGEMENT & 0xf) << 4) | DP_GET_INIT_REQ));
		ERROR_LOG(ucRet, "CMD GetInitReq: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;
		if (revBuf[6] != SENC_CERT_DEVICE)
			break;
		*CertLen = (revBuf[7] << 8) + revBuf[8];
		memcpy(Req, revBuf + 9, sizeof(ChipInitRequest));
		memcpy(Cert, revBuf + 9 + sizeof(ChipInitRequest), (*CertLen));

		//����CA Cert
		memset(revBuf, 0x00, sizeof(revBuf));
		cmdBuf[4] = SENC_CERT_CA;
		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_2K, SENC_BULK_ENDPOINT_READ_2K, cmdBuf, SENC_TRANSFER_LENGTH_2K, revBuf, SENC_TRANSFER_LENGTH_2K);
		if (ucRet != SENC_SUCCESS)
			break;

		ucRet = RetCheck(revBuf, &retLen, (((SENC_CMD_DOE_MANAGEMENT & 0xf) << 4) | DP_GET_INIT_REQ));
		ERROR_LOG(ucRet, "CMD GetInitReq: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;
		if (revBuf[6] != SENC_CERT_CA)
			break;

		*CaCertLen = (revBuf[7] << 8) + revBuf[8];
		memcpy(CaCert, revBuf + 9 + sizeof(ChipInitRequest), (*CaCertLen));
		memcpy(Pri, revBuf + 9 + sizeof(ChipInitRequest)+(*CaCertLen), 32);
		memcpy(Pub, revBuf + 9 + sizeof(ChipInitRequest)+(*CaCertLen)+32, 65);
	} while (0);

	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	memset(revBuf, 0x00, sizeof(revBuf));

	return ucRet;
}
//�忨ִ�г�ʼ�������
unsigned int SENC_CMD_DataProtector_ChipInit(SENCryptCard* IN sencDev,
											 ChipInitCommand IN Cmd,
											 uint8_t * IN CaCert,
											 uint32_t IN CaCertLen,
											 uint8_t * IN Cert,
											 uint32_t IN CertLen)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE] = { 0 };
	unsigned char revBuf[SENC_BUFFER_SIZE] = { 0 };

	//param check
	if (!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "CMD ChipInit: Device Not Found");

	//frame buildup
	cmdBuf[0] = SENC_CMD_DOE_MANAGEMENT;
	cmdBuf[3] = DP_CHIP_INIT;
	cmdBuf[1] = (1 + 3 + sizeof(ChipInitCommand) + CaCertLen) >> 8;
	cmdBuf[2] = (1 + 3 + sizeof(ChipInitCommand) + CaCertLen) & 0xff;
	cmdBuf[4] = 2;
	cmdBuf[5] = CaCertLen >> 8;
	cmdBuf[6] = CaCertLen & 0xff;
	memcpy(cmdBuf + 7, &Cmd, sizeof(ChipInitCommand));
	memcpy(cmdBuf + 7 + sizeof(ChipInitCommand), CaCert, CaCertLen);
	//memcpy(cmdBuf + 7 + sizeof(ChipInitCommand), Cert, CertLen);

	do{
		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_2K, SENC_BULK_ENDPOINT_READ_2K, cmdBuf, SENC_TRANSFER_LENGTH_2K, revBuf, SENC_TRANSFER_LENGTH_2K);
		if (ucRet != SENC_SUCCESS)
			break;

		ucRet = RetCheck(revBuf, &retLen, (((SENC_CMD_DOE_MANAGEMENT & 0xf) << 4) | DP_CHIP_INIT));
		ERROR_LOG(ucRet, "CMD GetInitReq: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;

		memset(cmdBuf, 0x00, sizeof(cmdBuf));
		memset(revBuf, 0x00, sizeof(revBuf));
		cmdBuf[0] = SENC_CMD_DOE_MANAGEMENT;
		cmdBuf[3] = DP_CHIP_INIT;
		cmdBuf[1] = (1 + 3 + sizeof(ChipInitCommand) + CertLen) >> 8;
		cmdBuf[2] = (1 + 3 + sizeof(ChipInitCommand) + CertLen) & 0xff;
		cmdBuf[4] = 4;
		cmdBuf[5] = CertLen >> 8;
		cmdBuf[6] = CertLen & 0xff;
		memcpy(cmdBuf + 7, &Cmd, sizeof(ChipInitCommand));
		memcpy(cmdBuf + 7 + sizeof(ChipInitCommand), Cert, CertLen);

		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_2K, SENC_BULK_ENDPOINT_READ_2K, cmdBuf, SENC_TRANSFER_LENGTH_2K, revBuf, SENC_TRANSFER_LENGTH_2K);
		if (ucRet != SENC_SUCCESS)
			break;

		ucRet = RetCheck(revBuf, &retLen, (((SENC_CMD_DOE_MANAGEMENT & 0xf) << 4) | DP_CHIP_INIT));
		ERROR_LOG(ucRet, "CMD GetInitReq: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;
	} while (0);

	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	memset(revBuf, 0x00, sizeof(revBuf));

	return ucRet;
}
//�Ӱ忨��ȡ��֤����Ա�����ݰ�
unsigned int SENC_CMD_DataProtector_GetAuthPackage(SENCryptCard* IN sencDev,
												   AuthAdminKey* OUT Pkg)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned char cmdBuf[SENC_BUFFER_SIZE] = { 0 };
	unsigned char revBuf[SENC_BUFFER_SIZE] = { 0 };

	//param check
	if (!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "CMD GetAuthPackage: Device Not Found");

	//frame buildup
	cmdBuf[0] = SENC_CMD_DOE_MANAGEMENT;
	cmdBuf[1] = 0x00;
	cmdBuf[2] = 0x01;
	cmdBuf[3] = DP_GET_AUTH_PACKAGE;

	do{
		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_2K, SENC_BULK_ENDPOINT_READ_2K, cmdBuf, SENC_TRANSFER_LENGTH_2K, revBuf, SENC_TRANSFER_LENGTH_2K);
		if (ucRet != SENC_SUCCESS)
			break;

		ucRet = RetCheck(revBuf, &retLen, (((SENC_CMD_DOE_MANAGEMENT & 0xf) << 4) | DP_GET_AUTH_PACKAGE));
		ERROR_LOG(ucRet, "CMD GetAuthPackage: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;

		memcpy(Pkg, revBuf + 6, sizeof(AuthAdminKey));
	} while (0);

	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	memset(revBuf, 0x00, sizeof(revBuf));

	return ucRet;
}

//����KeyChain
unsigned int SENC_CMD_KeyManager_CreateKeyChain(SENCryptCard* IN sencDev,
												KeychainCreateReq IN KCCreateReq,
												uint32_t IN KCCreateReqLen,
												uint8_t* IN CaCert,
												uint32_t IN CaCertLen,
												uint8_t* IN FirmailCert,
												uint32_t IN FirmailCertLen,
												uint8_t* IN KeyBagId,
												KeychainCreateCode* OUT KCCreateCode,
												uint32_t* OUT KCCreateCodeLen)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned int sendLen;
	unsigned int offset;
	unsigned char cmdBuf[SENC_BUFFER_SIZE] = { 0 };
	unsigned char revBuf[SENC_BUFFER_SIZE] = { 0 };

	//�������
	if (!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "CMD CreateKeyChain: Device Not Found");

	sendLen = 1 + KCCreateReqLen + CaCertLen + FirmailCertLen + KEYBAG_ID_LEN + 6;
	//���
	cmdBuf[0] = SENC_CMD_KEY_MANAGEMENT;
	cmdBuf[1] = sendLen >> 8;
	cmdBuf[2] = sendLen & 0xff;
	cmdBuf[3] = KM_CREATE_KEY_CHAIN;
	//������������ȼ�����
	cmdBuf[4] = KCCreateReqLen >> 8;
	cmdBuf[5] = KCCreateReqLen & 0xff;
	offset = 6;
	memcpy(cmdBuf + offset, &KCCreateReq, KCCreateReqLen);
	offset += KCCreateReqLen;
	//KeyBag ID
	memcpy(cmdBuf + offset, KeyBagId, KEYBAG_ID_LEN);
	offset += 8;
	//CA֤�鳤�ȼ�����
	cmdBuf[offset] = CaCertLen >> 8;
	cmdBuf[offset + 1] = CaCertLen & 0xff;
	offset += 2;
	memcpy(cmdBuf + offset, CaCert, CaCertLen);
	offset += CaCertLen;
	//Firmail֤�鳤�ȼ�����
	cmdBuf[offset] = FirmailCertLen >> 8;
	cmdBuf[offset + 1] = FirmailCertLen & 0xff;
	offset += 2;
	memcpy(cmdBuf + offset, FirmailCert, FirmailCertLen);

	do{
		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_2K, SENC_BULK_ENDPOINT_READ_2K, cmdBuf, SENC_TRANSFER_LENGTH_2K, revBuf, SENC_TRANSFER_LENGTH_2K);
		if (ucRet != SENC_SUCCESS)
			break;

		ucRet = RetCheck(revBuf, &retLen, (((SENC_CMD_KEY_MANAGEMENT & 0xf) << 4) | KM_CREATE_KEY_CHAIN));
		ERROR_LOG(ucRet, "CMD CreateKeyChain: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;

		*KCCreateCodeLen = (revBuf[6] << 8) + revBuf[7];
		memcpy(KCCreateCode, revBuf + 8, *KCCreateCodeLen);
	} while (0);

	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	memset(revBuf, 0x00, sizeof(revBuf));

	return ucRet;
}

//ǩ��BindCode
unsigned int SENC_CMD_KeyManager_BindCode(SENCryptCard* IN sencDev,
										  KeybagBindCode IN KBBindCode,
										  uint32_t IN KBBindCodeLen,
										  uint8_t* IN CaCert,
										  uint32_t IN CaCertLen,
										  uint8_t* IN KeyBagCert,
										  uint32_t IN KeyBagCertLen,
										  uint8_t* OUT BindCodePlain,
										  uint8_t* OUT PhoneNumber,
										  uint8_t* OUT BindCodeCipher,
										  uint32_t* OUT BindCodeCipherLen)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned int sendLen;
	unsigned int offset;
	unsigned char cmdBuf[SENC_BUFFER_SIZE] = { 0 };
	unsigned char revBuf[SENC_BUFFER_SIZE] = { 0 };

	//�������
	if (!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "CMD BindCode: Device Not Found");

	sendLen = 1 + KBBindCodeLen + CaCertLen + KeyBagCertLen  + 6;
	//���
	cmdBuf[0] = SENC_CMD_KEY_MANAGEMENT;
	cmdBuf[1] = sendLen >> 8;
	cmdBuf[2] = sendLen & 0xff;
	cmdBuf[3] = KM_SIGN_BIND_CODE;
	//���볤�ȼ�����
	cmdBuf[4] = KBBindCodeLen >> 8;
	cmdBuf[5] = KBBindCodeLen & 0xff;
	offset = 6;
	memcpy(cmdBuf + offset, &KBBindCode, KBBindCodeLen);
	offset += KBBindCodeLen;
	//CA֤�鳤�ȼ�����
	cmdBuf[offset] = CaCertLen >> 8;
	cmdBuf[offset + 1] = CaCertLen & 0xff;
	offset += 2;
	memcpy(cmdBuf + offset, CaCert, CaCertLen);
	offset += CaCertLen;
	//Firmail֤�鳤�ȼ�����
	cmdBuf[offset] = KeyBagCertLen >> 8;
	cmdBuf[offset + 1] = KeyBagCertLen & 0xff;
	offset += 2;
	memcpy(cmdBuf + offset, KeyBagCert, KeyBagCertLen);

	do{
		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_2K, SENC_BULK_ENDPOINT_READ_2K, cmdBuf, SENC_TRANSFER_LENGTH_2K, revBuf, SENC_TRANSFER_LENGTH_2K);
		if (ucRet != SENC_SUCCESS)
			break;

		ucRet = RetCheck(revBuf, &retLen, (((SENC_CMD_KEY_MANAGEMENT & 0xf) << 4) | KM_SIGN_BIND_CODE));
		ERROR_LOG(ucRet, "CMD BindCode: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;

		//��������
		offset = 6;
		memcpy(BindCodePlain, revBuf + offset, BINDCODE_PLAIN_LEN);
		offset += BINDCODE_PLAIN_LEN;
		//�绰����
		memcpy(PhoneNumber, revBuf + offset, PHONE_NUMBER_LEN);
		offset += PHONE_NUMBER_LEN;
		//����У������ĳ��ȼ�����
		*BindCodeCipherLen = (revBuf[offset] << 8) + revBuf[offset+1];
		offset += 2;
		memcpy(BindCodeCipher, revBuf + offset, *BindCodeCipherLen);
	} while (0);

	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	memset(revBuf, 0x00, sizeof(revBuf));

	return ucRet;
}

//����Circle
unsigned int SENC_CMD_KeyManager_CreateCircle(SENCryptCard* IN sencDev,
											  uint8_t* IN circle_id,
											  KeybagCreateCircleReq IN KBCreateCircleReq,
											  uint32_t IN KBCreateCircleReqLen,
											  uint8_t* IN BindCodeVrfPkgCipher,
											  uint32_t IN BindCodeVrfPkgCipherLen,
											  uint32_t* OUT TimeStamp,
											  KeybagCircle* OUT KBCircle,
											  uint32_t* OUT KBCircleLen)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned int sendLen;
	unsigned int offset;
	unsigned char cmdBuf[SENC_BUFFER_SIZE] = { 0 };
	unsigned char revBuf[SENC_BUFFER_SIZE] = { 0 };

	//�������
	if (!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "CMD CreateCircle: Device Not Found");

	sendLen = 1 + CIRCLE_ID_LEN + KBCreateCircleReqLen + BindCodeVrfPkgCipherLen + 4;
	//���
	cmdBuf[0] = SENC_CMD_KEY_MANAGEMENT;
	cmdBuf[1] = sendLen >> 8;
	cmdBuf[2] = sendLen & 0xff;
	cmdBuf[3] = KM_CREATE_CIRCLE;
	memcpy(cmdBuf + 4, circle_id, CIRCLE_ID_LEN);
	offset = 4 + CIRCLE_ID_LEN;
	//Circle��������ȼ�����
	cmdBuf[offset] = KBCreateCircleReqLen >> 8;
	cmdBuf[offset + 1] = KBCreateCircleReqLen & 0xff;
	offset += 2;
	memcpy(cmdBuf + offset, &KBCreateCircleReq, KBCreateCircleReqLen);
	offset += KBCreateCircleReqLen;
	//BindCodeУ������ĳ��ȼ�����
	cmdBuf[offset] = BindCodeVrfPkgCipherLen >> 8;
	cmdBuf[offset + 1] = BindCodeVrfPkgCipherLen & 0xff;
	offset += 2;
	memcpy(cmdBuf + offset, BindCodeVrfPkgCipher, BindCodeVrfPkgCipherLen);

	do{
		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_2K, SENC_BULK_ENDPOINT_READ_2K, cmdBuf, SENC_TRANSFER_LENGTH_2K, revBuf, SENC_TRANSFER_LENGTH_2K);
		if (ucRet != SENC_SUCCESS)
			break;

		ucRet = RetCheck(revBuf, &retLen, (((SENC_CMD_KEY_MANAGEMENT & 0xf) << 4) | KM_CREATE_CIRCLE));
		ERROR_LOG(ucRet, "CMD CreateCircle: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;

		//ʱ���
		offset = 6;
		memcpy(TimeStamp, revBuf + offset, 4);
		offset += 4;
		//Circle�����ȼ�����
		*KBCircleLen = (revBuf[offset] << 8) + revBuf[offset + 1];
		offset += 2;
		memcpy(KBCircle, revBuf + offset, 52);
		offset += 52;
		if (sizeof(KeybagCircle)+KBCircle->Count*sizeof(KeybagCirclePubkey)-sizeof(KBCircle->kcPubKey) > *KBCircleLen)
			return SENC_ERROR_PARAMETER_LENGTH_ERROR;
		memcpy(KBCircle->kcPubKey, revBuf + offset, KBCircle->Count*sizeof(KeybagCirclePubkey));
		offset += KBCircle->Count*sizeof(KeybagCirclePubkey);
		memcpy(KBCircle->Signature, revBuf + offset, sizeof(KBCircle->Signature));
	} while (0);

	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	memset(revBuf, 0x00, sizeof(revBuf));

	return ucRet;
}

//����Circle
unsigned int SENC_CMD_KeyManager_JoinCircle(SENCryptCard* IN sencDev,
											KeybagCircle IN KBOldCircle,
											uint32_t IN KBOldCircleLen,
											KeybagJoinCircleApprove IN KBJoinCircleApprove,
											uint32_t IN KBJoinCircleApproveLen,
											uint8_t* IN BindCodeVrfPkgCipher,
											uint32_t IN BindCodeVrfPkgCipherLen,
											uint32_t* OUT TimeStamp,
											KeybagCircle* OUT KBNewCircle,
											uint32_t* OUT KBNewCircleLen)
{
	unsigned int ucRet = SENC_SUCCESS;
	unsigned int retLen;
	unsigned int sendLen;
	unsigned int offset;
	unsigned char cmdBuf[SENC_BUFFER_SIZE] = { 0 };
	unsigned char revBuf[SENC_BUFFER_SIZE] = { 0 };

	//�������
	if (!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "CMD JoinCircle: Device Not Found");

	sendLen = 1 + KBOldCircleLen + KBJoinCircleApproveLen + BindCodeVrfPkgCipherLen + 6;
	//���
	cmdBuf[0] = SENC_CMD_KEY_MANAGEMENT;
	cmdBuf[1] = sendLen >> 8;
	cmdBuf[2] = sendLen & 0xff;
	cmdBuf[3] = KM_JOIN_CIRCLE;
	//OldCircle�����ȼ�����
	cmdBuf[4] = KBOldCircleLen >> 8;
	cmdBuf[5] = KBOldCircleLen & 0xff;
	offset = 6;
	memcpy(cmdBuf + offset, &KBOldCircle, 52);
	offset += 52;
	memcpy(cmdBuf + offset, KBOldCircle.kcPubKey, KBOldCircle.Count*sizeof(KeybagCirclePubkey));
	offset += KBOldCircle.Count*sizeof(KeybagCirclePubkey);
	memcpy(cmdBuf + offset, KBOldCircle.Signature, sizeof(KBOldCircle.Signature));
	offset += sizeof(KBOldCircle.Signature);
	//����Circle���������ȼ�����
	cmdBuf[offset] = KBJoinCircleApproveLen >> 8;
	cmdBuf[offset + 1] = KBJoinCircleApproveLen & 0xff;
	offset += 2;
	memcpy(cmdBuf + offset, &KBJoinCircleApprove, KBJoinCircleApproveLen);
	offset += KBJoinCircleApproveLen;
	//BindCodeУ������ĳ��ȼ�����
	cmdBuf[offset] = BindCodeVrfPkgCipherLen >> 8;
	cmdBuf[offset + 1] = BindCodeVrfPkgCipherLen & 0xff;
	offset += 2;
	memcpy(cmdBuf + offset, BindCodeVrfPkgCipher, BindCodeVrfPkgCipherLen);

	do{
		ucRet = SENC_CMD_Transfer(sencDev, SENC_PLAINTEXT_SIGN, SENC_BULK_ENDPOINT_WRITE_2K, SENC_BULK_ENDPOINT_READ_2K, cmdBuf, SENC_TRANSFER_LENGTH_2K, revBuf, SENC_TRANSFER_LENGTH_2K);
		if (ucRet != SENC_SUCCESS)
			break;

		ucRet = RetCheck(revBuf, &retLen, (((SENC_CMD_KEY_MANAGEMENT & 0xf) << 4) | KM_JOIN_CIRCLE));
		ERROR_LOG(ucRet, "CMD JoinCircle: Returned Error");
		if (ucRet != SENC_SUCCESS)
			break;

		//ʱ���
		offset = 6;
		memcpy(TimeStamp, revBuf + offset, 4);
		offset += 4;
		//Circle�����ȼ�����
		*KBNewCircleLen = (revBuf[offset] << 8) + revBuf[offset + 1];
		offset += 2;
		memcpy(KBNewCircle, revBuf + offset, 52);
		offset += 52;
		if (sizeof(KeybagCircle)+KBNewCircle->Count*sizeof(KeybagCirclePubkey)-sizeof(KBNewCircle->kcPubKey) > *KBNewCircleLen)
			return SENC_ERROR_PARAMETER_LENGTH_ERROR;
		memcpy(KBNewCircle->kcPubKey, revBuf + offset, KBNewCircle->Count*sizeof(KeybagCirclePubkey));
		offset += KBNewCircle->Count*sizeof(KeybagCirclePubkey);
		memcpy(KBNewCircle->Signature, revBuf + offset, sizeof(KBNewCircle->Signature));
	} while (0);

	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	memset(revBuf, 0x00, sizeof(revBuf));

	return ucRet;
}


#endif

