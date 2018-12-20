#ifndef LIBSENC_SENC_CMD_FRAME_H_
#define LIBSENC_SENC_CMD_FRAME_H_

#include "libsenc.h"
#include "senc_assist.h"


//�忨������
#define			SENC_CMD_KEY_EXCHANGE											0x00
#define			SENC_CMD_ENCRYPT_CARD_OPERATION									0x01
#define			SENC_CMD_MANAGEMENT												0x02
#define			SENC_CMD_DONGLE_OPERATION										0x03
#define			SENC_CMD_AES													0x04
#define			SENC_CMD_RSA													0x05
#define			SENC_CMD_KEY_OPERATION											0x06
#define			SENC_CMD_PRODUCTION												0x07
#define			SENC_CMD_PRO_TEST												0x08

#define			SENC_CMD_ALTERNATIVE_HASH										0xF0
#define			SENC_CMD_ALTERNATIVE_RSA										0xF1
#define			SENC_CMD_ALTERNATIVE_PBKDF2										0xF2
#define			SENC_CMD_DATA_PROTECTION										0xF3
#define			SENC_CMD_DOE_MANAGEMENT											0xF5
#define			SENC_CMD_KEY_MANAGEMENT											0xF6

#define			DP_SIGN_USER_PUB_KEY											0x01
#define			DP_GEN_WEB_KEY													0x02
#define			DP_SET_WEB_KEY_PERIOD											0x03
#define			DP_GEN_KEY_SEED_S1												0x04
#define			DP_ISSUE_LICENSE												0x05
#define			DP_CIPHER_CONVERT												0x06
#define			DP_GET_RTC_TIME													0x11
#define			DP_GET_SUPPORTED_ALGORITHM										0x12
#define			DP_SET_RTC_TIME													0x13

#define			DP_GET_CHIP_INIT_STATUS											0x01
#define			DP_GET_INIT_REQ													0x02
#define			DP_CHIP_INIT													0x03
#define			DP_GET_AUTH_PACKAGE												0x04

#define			KM_CREATE_KEY_CHAIN												0x01
#define			KM_SIGN_BIND_CODE												0x02
#define			KM_CREATE_CIRCLE												0x03
#define			KM_JOIN_CIRCLE													0x04

#define			DP_SET_CALC_KEY													0x10
#define			DP_SCK_MAC														0x01

#define			SENC_CMD_CONFIRM												0xff


#define			SENC_ECARD_GET_STAT												0x01
#define			SENC_ECARD_GET_ID												0x02
#define			SENC_ECARD_GET_VERSION											0x03


#define			SENC_MANAGE_ADDITION											0x01
#define			SENC_MANAGE_VERIFITION											0x02
#define			SENC_MANAGE_DELETION											0x03
#define			SENC_MANAGE_GET_ID												0x04
#define			SENC_MANAGE_BACKUP_KEY											0x05
#define			SENC_MANAGE_RECOVERY_KEY										0x06
#define			SENC_MANAGE_QUIT												0x07
#define			SENC_MANAGE_WORK_STANDBY										0x08


#define			SENC_DONGLE_ADDITION											0x01
#define			SENC_DONGLE_SET_KEY												0x02
#define			SENC_DONGLE_DELETION											0x03
#define			SENC_DONGLE_GET_VERIFITION_DATA									0x04
#define			SENC_DONGLE_VERIFITION											0x05
#define			SENC_DONGLE_GET_ID												0x06
#define			SENC_DONGLE_QUIT												0x07

#define			SENC_AES_ENCRYPTION												0x01
#define			SENC_AES_DECRYPTION												0x02

#define			SENC_CMD_AES_LENGTH_128											0x01
#define			SENC_CMD_AES_LENGTH_256											0x02
#define			SENC_CMD_AES_MODE_ECB											0x01
#define			SENC_CMD_AES_MODE_CBC											0x02
#define			SENC_CMD_SM4													0x03
// #define			SENC_CMD_RSA_LENGTH_1024										0x01
#define			SENC_CMD_RSA_LENGTH_2048										0x01


#define			SENC_RSA_SIGNATURE_EXTERNAL										0x01
#define			SENC_RSA_SIGNATURE_INTERNAL										0x02
#define			SENC_RSA_DECRYPT_EXTERNAL										0x03
#define			SENC_RSA_DECRYPT_INTERNAL										0x04

#define			SENC_KEYS_RSA_KEY_GENERATION_RETURN								0x01
#define			SENC_KEYS_RSA_KEY_GENERATION_INTERNAL_STORAGE					0x02
#define			SENC_KEYS_GET_RSA_PUBLIC_KEY									0x03
#define			SENC_KEYS_AES_KEY_GENERATION									0x04
#define			SENC_KEYS_IMPORT_KEY											0x05
#define			SENC_KEYS_DELETION												0x06
#define			SENC_KEYS_QUERY													0x07
#define			SENC_KEYS_BACKUP												0x08
#define			SENC_KEYS_RECOVERY												0x09

#define			SENC_PRODUCT_SET_ID												0x01
#define			SENC_PRODUCT_SET_VERSION										0x02
#define			SENC_PRODUCT_GENERATE_FLASH_KEY									0x03
#define			SENC_PRODUCT_SET_DH_PARAMETER									0x04
#define			SENC_PRODUCT_GENERATE_RSA_KEY									0x05
#define			SENC_PRODUCT_REQUEST_CSR										0x06
#define			SENC_PRODUCT_DOWNLOAD_CERT										0x07
#define			SENC_PRODUCT_SET_DONE											0x08

#define			SENC_PRO_TEST_RSA_SIGNATURE										0x01
#define			SENC_PRO_TEST_AES_ENCRYPTION									0x02
#define			SENC_PRO_TEST_GET_MASTER_CARD_ID								0x03
#define			SENC_PRO_TEST_WRITE_NO_PROTECT									0x04
#define			SENC_PRO_TEST_WRITE_EJECT_PROTECT								0x05
#define			SENC_PRO_TEST_READ												0x06
#define			SENC_PRO_TEST_FLASH_SWEEP										0x07

#define			SENC_ALTERNATIVE_RSA_KEY_PAIR_GENERATION						0x01
#define			SENC_ALTERNATIVE_RSA_SIGNATURE_EXTERNAL							0x02
#define			SENC_ALTERNATIVE_RSA_VIRIFY_EXTERNAL							0x03
#define			SENC_ALTERNATIVE_RSA_SIGNATURE_INTERNAL							0x04
#define			SENC_ALTERNATIVE_RSA_VIRIFY_INTERNAL							0x05

#define			SENC_CMD_LENGTH_DONGLE_ID										8
#define			SENC_CMD_LENGTH_DONGLE_KEY_DATA									16
#define			SENC_CMD_LENGTH_DONGLE_RAND										8



#define			SENC_ALG_AES_128												0x01
#define			SENC_ALG_AES_256												0x02
#define			SENC_ALG_SM4													0x03
#define			SENC_ALG_RSA_2048												0x04

#define			SENC_CARD_ID_LENGTH												16			//����ID����
#define			SENC_BAKCUP_KEYS_LENGTH											208			//������Կ����
#define			SENC_RSA_PRIVATE_KEY_LENGTH_IVM									SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_MAC_LENGTH+SENC_ENC_IV_LENGTH //1444
#define			SENC_RSA_PRIVATE_KEY_LENGTH										1412
#define			SENC_ENC_MAC_LENGTH												16
#define			SENC_ENC_IV_LENGTH												16
#define			SENC_RSA_PUBLIC_KEY_LENGTH										512




//*������SENC_CMD_KEX_KeyExchange()
//*���ܣ���Կ����||Key exchange;
//*������SENCryptCard*		sencDev					//���ܿ��豸handle
//		unsigned char*		pucCmpAttr,				//���͵ļ������A
//		unsigned char*		pucRecvCmpAttr,			//�յ��ļ������B
//		unsigned char*		pucRetPrivCommuKey)		//����ͨ����Կ
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_KEX_KeyExchange(SENCryptCard*		IN	sencDev,
									  unsigned char*	IN	pucCmpAttr,	
									  unsigned char*	OUT	pucRecvCmpAttr,
									  unsigned char*	OUT	pucRetPrivCommuKey);
//********************************************************************************************************//
//*������SENC_CMD_EC_GetState()
//*���ܣ���ȡ���ܿ�״̬||Get encrypt card's state; 
//*������SENCryptCard*		sencDev					//���ܿ��豸handle
//*������unsigned char*		pucRetState				//���صļ��ܿ�״̬
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_EC_GetState(SENCryptCard*		IN	sencDev,
								  unsigned char*	OUT	pucRetState);
//********************************************************************************************************//
//*������SENC_CMD_EC_GetID()
//*���ܣ���ȡ���ܿ�ID||Get encrypt card's ID;
//*������SENCryptCard*		sencDev,				//���ܿ��豸handle
//		unsigned char*		pucRetID				//����ID����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_EC_GetID(SENCryptCard*	IN	sencDev,		
							   unsigned char*	OUT	pucRetID);		
//********************************************************************************************************//
//*������SENC_CMD_EC_GetVersion()
//*���ܣ���ȡ���ܿ��汾||Get hardware and firmware version from encrypt card;
//*������SENCryptCard*		sencDev,				//���ܿ��豸handle
//		unsigned char*		pucRetHardwareVer		//����Ӳ���汾
//		unsigned char*		pucRetFirmwareVer		//���ع̼��汾
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_EC_GetVersion(SENCryptCard*	IN	sencDev,			
									unsigned char*	OUT	pucRetHardwareVer,	
									unsigned char*	OUT	pucRetFirmwareVer);	
//********************************************************************************************************//
//*������SENC_CMD_MC_NewMasterCard()
//*���ܣ�����¹���||Add a new master card;
//*������SENCryptCard*		sencDev,				//���ܿ��豸handle
//		unsigned char*		pucRetAddedCardId		//������ӿ�
//		unsigned char*		pucRetRestNums			//����ʣ�����ӿ�����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_NewMasterCard(SENCryptCard*	IN	sencDev,			
									   unsigned char*	OUT	pucRetAddedCardId,	
									   unsigned char*	OUT	pucRetRestNums);
//********************************************************************************************************//
//*������SENC_CMD_MC_VerifyMasterCard()
//*���ܣ���֤����||Verify a master card;
//*������SENCryptCard*		sencDev,				//���ܿ��豸handle
//		unsigned char*		pucRetVerifiedCardId	//���ر���֤��ID
//		unsigned char*		pucRetPermission		//���ؿ�Ȩ��
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_VerifyMasterCard(SENCryptCard*		IN	sencDev,
										  unsigned char*	OUT	pucRetVerifiedCardId,
										  unsigned char*	OUT	pucRetPermission);
//********************************************************************************************************//
//*������SENC_CMD_MC_DeleteMasterCard()
//*���ܣ�ɾ������||Delete a master card;
//*������SENCryptCard*		sencDev,				//���ܿ��豸handle
//		unsigned char*		pucDelCardId			//��ɾ����ID
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_DeleteMasterCard(SENCryptCard*		IN	sencDev,
										  unsigned char*	IN	pucDelCardId);
//********************************************************************************************************//
//*������SENC_CMD_MC_GetMasterCardId()
//*���ܣ���ȡ����ID|| Get all master cards' ID;
//*������SENCryptCard*		sencDev,				//���ܿ��豸handle
//		unsigned char*		pucRetData				//���ع�����Ϣ
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_GetMasterCardId(SENCryptCard*	IN	sencDev,
										 unsigned char*	OUT	pucRetData);
//********************************************************************************************************//
//*������SENC_CMD_MC_GetBackupKey()
//*���ܣ���ȡ������Կ|| Get backup key;
//*������SENCryptCard*		sencDev,				//���ܿ��豸handle
//		unsigned char*		pucRetEncryptSign		//���ؼ��ܱ�ʶ
//		unsigned char*		pucRetKeys				//���ؼ��ܱ�����Կ����
//*���ڣ�2016/10/25	
//by Wangjf
unsigned int SENC_CMD_MC_GetBackupKey(SENCryptCard*		IN	sencDev,
									  unsigned char*	OUT	pucRetEncryptSign,	
									  unsigned char*	OUT	pucRetKeys);
//********************************************************************************************************//
//*������SENC_CMD_MC_SetRecoveryKey()
//*���ܣ����ûָ�������Կ|| Set back-up keys for recovery;
//*������SENCryptCard*		sencDev,				//���ܿ��豸handle
//		unsigned char*		pucInKeys,				//��ָ��ļ��ܱ�����Կ����
//		unsigned char*		pucRetDecryptSign		//���ع������ܱ�ʶ
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_SetRecoveryKey(SENCryptCard*	IN	sencDev,
										unsigned char*	IN	pucInKeys,
										unsigned char*	OUT	pucRetDecryptSign);
//********************************************************************************************************//
//*������SENC_CMD_MC_MngQuit()
//*���ܣ��˳�����ģʽ|| Quit management state;
//*������SENCryptCard*		sencDev					//���ܿ��豸handle
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_MngQuit(SENCryptCard*	IN	sencDev);
//********************************************************************************************************//
//*������SENC_CMD_MC_WorkStandby()
//*���ܣ����빤��״̬|| Set to Standby state;
//*������SENCryptCard*		sencDev,							//���ܿ��豸handle
//*���ڣ�2016/11/04
//by Wangjf
unsigned int SENC_CMD_MC_WorkStandby(SENCryptCard* IN	sencDev);
//********************************************************************************************************//
//*������SENC_CMD_Dongle_NewDongle()
//*���ܣ��������|| Add a new key dongle;
//*������SENCryptCard*		sencDev,							//���ܿ��豸handle
//		unsigned char*		pucDongleId,						//��ID
//		unsigned char*		pucInKeyData,						//�ⲿ��֤��Կ
//		unsigned char*		pucPlaintextKey,					//����flash key
//*���ڣ�2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_NewDongle(SENCryptCard*	sencDev,			//���ܿ��豸handle
									   unsigned char*	pucDongleId,		//��ID
									   unsigned char	keyIdx1,
									   unsigned char	keyIdx2,
									   unsigned char*	pucInKeyData,		//�ⲿ��֤��Կ
									   unsigned char*	pucPlaintextKey);	//����flash key
//********************************************************************************************************//
//*������SENC_CMD_Dongle_SetEncryptedKey()
//*���ܣ���������key|| Set the encrypted key;
//*������SENCryptCard*		sencDev 							//���ܿ��豸handle
//		unsigned char*		pucEncKeyData						//����key
//*���ڣ�2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_SetEncryptedKey(SENCryptCard*	sencDev,			//���ܿ��豸handle
											 unsigned char*	pucEncKeyData);		//����key
//********************************************************************************************************//
//*������SENC_CMD_Dongle_Delete()
//*���ܣ�ɾ����|| Delete the bound key dongle;
//*������SENCryptCard*		sencDev				//���ܿ��豸handle
//		unsigned char*		KeyId,				//��ɾ����ID
//*���ڣ�2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_Delete(SENCryptCard*	sencDev,					//���ܿ��豸handle
									unsigned char*	KeyId);						//��ɾ����ID
//********************************************************************************************************//
//*������SENC_CMD_Dongle_GetVerifyRand()
//*���ܣ���ȡ��֤�����|| Get verification random number;
//*������SENCryptCard*		sencDev					//���ܿ��豸handle
//		unsigned char*		pucDongleId				//��ID
//		unsigned char*		pucRetRandNum			//������֤�����
//		unsigned char*		pucEncFlashKey			//����flash key
//*���ڣ�2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_GetVerifyRand(SENCryptCard*	sencDev,			//���ܿ��豸handle
										   unsigned char*	pucDongleId,		//��ID
										   unsigned char*	keyIdx1,
										   unsigned char*	keyIdx2,
										   unsigned char*	pucRetRandNum,		//������֤�����
										   unsigned char*	pucEncFlashKey);	//����flash key
//********************************************************************************************************//
//*������SENC_CMD_Dongle_Verify()
//*���ܣ���֤��|| Verify the inserted key dongle;
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char*		pucDongleId					//��ID
//		unsigned char*		pucInKeyVerifyData			//��֤��������
//		unsigned char*		pucDecFlashKey				//���ܺ�flash key
//*���ڣ�2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_Verify(SENCryptCard*	sencDev,				//���ܿ��豸handle
									unsigned char*	pucDongleId,			//��ID
									unsigned char*	pucInKeyVerifyData,		//��֤��������
									unsigned char*	pucDecFlashKey);		//���ܺ�flash key{
//********************************************************************************************************//
//*������SENC_CMD_Get_Dongle_ID()
//*���ܣ���ȡ��ID|| Get dongles ID which bound with senc card
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char*		pucRetData					//����ID����
//*���ڣ�2017/02/14
//by Wangjf
unsigned int SENC_CMD_Get_Dongle_ID(SENCryptCard*	sencDev,				//���ܿ��豸handle
									unsigned char*	pucRetData);			//����ID����
//********************************************************************************************************//
//*������SENC_CMD_Dongle_Quit()
//*���ܣ��˳�����ģʽ|| Quit from operation state;
//*������SENCryptCard*		sencDev					//���ܿ��豸handle
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Dongle_Quit(SENCryptCard*		IN	sencDev);
//********************************************************************************************************//
//*������SENC_CMD_AES_Encrypt()
//*���ܣ�AES����|| Encrypt in AES
//*������SENCryptCard*		sencDev					//���ܿ��豸handle
//		unsigned char*		CBCiv					//cbc��ʼ����
//		unsigned char*		pucInData				//����������
//		unsigned int		uiInDataLen				//���������ݳ���
//		unsigned char*		pucCipherData			//���ܷ�������
//		unsigned int*		uiCipherDataLen			//���������ݳ���
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_AES_Encrypt(SENCryptCard*		IN		sencDev,
								  EncryptAttr*		EncAttributes,
								  unsigned char*	IN		CBCiv,
								  unsigned char*	IN		pucInData,
								  unsigned int		IN		uiInDataLen,
								  unsigned char*	OUT		pucCipherData,
								  unsigned int*		OUT		uiCipherDataLen);
//********************************************************************************************************//
//*������SENC_CMD_AES_Decrypt()
//*���ܣ�AES����|| Decrypt in AES
//*������SENCryptCard*		sencDev					//���ܿ��豸handle
//		unsigned char*		CBCiv					//cbc��ʼ����
//		unsigned char*		pucInData				//����������
//		unsigned int		uiInDataLen				//���������ݳ���
//		unsigned char*		pucDecryptedData		//���ܷ�������
//		unsigned int*		uiDecryptedDataLen		//���������ݳ���
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_AES_Decrypt(SENCryptCard*		IN		sencDev,
								  EncryptAttr*		EncAttributes,
								  unsigned char*	IN		CBCiv,
								  unsigned char*	IN		pucInData,
								  unsigned int		IN		uiInDataLen,
								  unsigned char*	OUT		pucDecryptedData,
								  unsigned int*		OUT		uiDecryptedDataLen);
//********************************************************************************************************//
//*������SENC_CMD_RSA_Signature_External()
//*���ܣ��ⲿRSAǩ��|| Signature by RSA encryption
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucRsaKey						//ǩ����RSA��Կ����
//		unsigned char*		pucInData						//��ǩ������
//		unsigned char*		pucSignedData					//ǩ����������
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_RSA_Signature_External(SENCryptCard*	IN	sencDev,
											 EncryptAttr*		EncAttributes,
											 unsigned char* IN	pucIV,
											 unsigned char*	IN	pucMac,
											 unsigned char*	IN	pucRsaKey,
											 unsigned char*	IN	pucInData,
											 unsigned char*	OUT	pucSignedData);
//********************************************************************************************************//
//*������SENC_CMD_RSA_Signature_Internal()
//*���ܣ�RSA�ڲ���Կǩ��|| Signature by RSA encryption with internal key
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucInData						//��ǩ������
//		unsigned char*		pucSignedData					//��������
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_RSA_Signature_Internal(SENCryptCard*		IN	sencDev,
											 EncryptAttr*		EncAttributes,
											 unsigned char*		IN	pucInData,
											 unsigned char*		OUT	pucSignedData);
//********************************************************************************************************//
//*������SENC_CMD_RSA_Decrypt_External()
//*���ܣ��ⲿRSA����|| Decryption by RSA encryption
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucEncRsaPrivKey				//����RSA��Կ����
//		unsigned char*		pucInEncData					//����������
//		unsigned char*		pucOutDecData					//�����ѽ�������
//*���ڣ�2017/02/16
//by Wangjf
unsigned int SENC_CMD_RSA_Decrypt_External(SENCryptCard*	sencDev,
										   EncryptAttr*		EncAttributes,
										   unsigned char*	pucIV,
										   unsigned char*	pucMac,
										   unsigned char*	pucEncRsaPrivKey,
										   unsigned char*	pucInEncData,
										   unsigned char*	pucOutDecData);
//********************************************************************************************************//
//*������SENC_CMD_RSA_Decrypt_Internal()
//*���ܣ�RSA�ڲ���Կ����|| RSA Decryption with internal key
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucInEncData					//����������
//		unsigned char*		pucOutDecData					//�����ѽ�������
//*���ڣ�2017/02/16
//by Wangjf
unsigned int SENC_CMD_RSA_Decrypt_Internal(SENCryptCard*	sencDev,
										   EncryptAttr*		EncAttributes,
										   unsigned char*	pucInEncData,
										   unsigned char*	pucOutDecData);

//********************************************************************************************************//
//*������SENC_CMD_Key_RSA_Generate_Ret()
//*���ܣ�RSA��Կ���ɲ�����|| Generate an RSA key and export;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucRetRsaPrivKey				//�����Ѽ���˽Կ����
//		unsigned char*		pucRetRsaPubKey					//�����Ѽ��ܹ�Կ����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_RSA_Generate_Ret(SENCryptCard*	IN	sencDev,
										   EncryptAttr*		EncAttributes,
										   unsigned char*	IN	pucIV,
										   unsigned char*	OUT	pucMAC,
										   unsigned char*	OUT	pucRetRsaPrivKey,
										   unsigned char*	OUT	pucRetRsaPubKey);
//********************************************************************************************************//
//*������SENC_CMD_Key_RSA_Generate_Internal()
//*���ܣ�RSA��Կ���ɲ��洢����|| Generate an RSA key and storage in encrypt card;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char		EncryptLength					//���ܳ���1024|2048
//		unsigned char		RsaKeyIdx						//����RSA��Կ�洢����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_RSA_Generate_Internal(SENCryptCard*	IN	sencDev,
												unsigned char	IN	EncryptLength,
												unsigned char	IN	RsaKeyIdx);
//********************************************************************************************************//
//*������SENC_CMD_Key_RSA_GetPublicKey()
//*���ܣ���ȡĿ��RSA��Կ|| Get RSA public key;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char		EncryptLength					//���ܳ���1024|2048
//		unsigned char		KeyIndex						//Ŀ����Կ����
//		unsigned char*		pucRetRsaPubKey					//����RSA��Կ
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_RSA_GetPublicKey(SENCryptCard*	IN	sencDev,
										   unsigned char	IN	EncryptLength,
										   unsigned char	IN	KeyIndex,
										   unsigned char*	OUT	pucRetRsaPubKey);
//********************************************************************************************************//
//*������SENC_CMD_Key_Symmetric_Key_Generate()
//*���ܣ��Գ���Կ���ɲ��洢����|| Generate an symmetric key and storage in encrypt card;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char		EncryptLength					//���ܳ���128|256
//		unsigned char		InAesKeyIndex					//AES��Կ�洢����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Symmetric_Key_Generate(SENCryptCard*	IN	sencDev,		//���ܿ��豸handle
												 unsigned char	IN	EncryptLength,	//���ܳ���128|256
												 unsigned char	IN	InAesKeyIndex);	//AES��Կ�洢����
//********************************************************************************************************//
//*������SENC_CMD_Key_Import()
//*���ܣ���Կ����|| Import keys
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char		InAlgorithmType					//������Կ�㷨
//		unsigned char		InKeyIndex						//������ԿĿ������
//		unsigned char*		InKeyData						//������Կ����
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_Key_Import(SENCryptCard*	IN	sencDev,
								 unsigned char	IN	InAlgorithmType,
								 unsigned char	IN	InKeyIndex,
								 unsigned char*	IN	InKeyData);
//********************************************************************************************************//
//*������SENC_CMD_Key_Delete()
//*���ܣ���Կɾ��|| Delete a key;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char		EncryptLength					//ɾ����Կ����
//		unsigned char		ucDelKeyIndex					//ɾ����Կ����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Delete(SENCryptCard*	IN	sencDev,
								 unsigned char	IN	EncryptType,
								 unsigned char	IN	ucDelKeyIndex);
//********************************************************************************************************//
//*������SENC_CMD_Key_Query()
//*���ܣ���Կ��ѯ|| Query for keys;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucAES128State					//����AES128��Կ״̬��
//		unsigned char*		pucAES256State					//����AES256��Կ״̬��
// 		unsigned char*		pucSM4State						//����SM4��Կ״̬��
// 		unsigned char*		pucRSA2048State					//����RSA2048��Կ״̬��
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Query(SENCryptCard*	IN	sencDev,
								unsigned char*	OUT	pucAES128State,
								unsigned char*	OUT	pucAES256State,
								unsigned char*	OUT	pucSM4State,
								unsigned char*	OUT	pucRSA2048State);
//********************************************************************************************************//
//*������SENC_CMD_Key_Backup()
//*���ܣ���Կ����|| Backup a key;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char		EncryptType						//���ܷ�ʽ
//		unsigned char		ucBakKeyIndex					//������Կ����
//		unsigned char*		pucBakKeyData					//���ر�����Կ����
//		unsigned int*		pucBakKeyDataLength				//���ر�����Կ���ݳ���
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Backup(SENCryptCard*		IN	sencDev,
								 unsigned char		IN	EncryptType,
								 unsigned char		IN	ucBakKeyIndex,
								 unsigned char*		OUT	pucBakKeyData,
								 unsigned int*		OUT	pucBakKeyDataLength);
//********************************************************************************************************//
//*������SENC_CMD_Key_Recover()
//*���ܣ���Կ�ָ�|| Recover a key;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char		EncryptType						//���ܷ�ʽ
// 		unsigned char		ucBakKeyIndex					//����Ŀ����Կ����
// 		unsigned int		ucBakKeyDataLength				//����Ŀ����Կ���ݳ���
// 		unsigned char*		pucBakKeyData					//����Ŀ����Կ����
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Recover(SENCryptCard*		IN	sencDev,
								  unsigned char		IN	EncryptType,
								  unsigned char		IN	ucBakKeyIndex,
								  unsigned int		IN	ucBakKeyDataLength,
								  unsigned char*	IN	pucBakKeyData);
//********************************************************************************************************//
//*������SENC_CMD_Product_SetCardId()
//*���ܣ����ü��ܿ�ID|| Set the ID of encrypt card;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
// 		unsigned char*		pucEcardId						//���ü��ܿ�ID
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_SetCardId(SENCryptCard*	IN	sencDev,
										unsigned char*	IN	pucEcardId);
//********************************************************************************************************//
//*������SENC_CMD_Product_SetCardVersion()
//*���ܣ����ü��ܿ��汾��|| Set hardware and firmware version of encrypt card;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
// 		unsigned char*		pucEcardHardwareVer				//���ü��ܿ�Ӳ���汾
// 		unsigned char*		pucEcardFirmwareVer				//���ü��ܿ��̼��汾
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_SetCardVersion(SENCryptCard*		IN	sencDev,
											 unsigned char*		IN	pucEcardHardwareVer,
											 unsigned char*		IN	pucEcardFirmwareVer);
//********************************************************************************************************//
//*������SENC_CMD_Product_GenerateFlashKey()
//*���ܣ�����FLASH��Կ|| Generate FLASH key;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_GenerateFlashKey(SENCryptCard*	IN	sencDev);
//********************************************************************************************************//
//*������SENC_CMD_Product_SetDHAttributes()
//*���ܣ�����Diffie Hellman��Կ������P,G����|| Set P&G for Diffie-Hellman key exchange;
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
// 		unsigned char*		pucP						//DH��Կ��������P
// 		unsigned char*		pucG						//DH��Կ��������G
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_SetDHAttributes(SENCryptCard*		IN	sencDev,
											  unsigned char*	IN	pucP,
											  unsigned char*	IN	pucG);

//********************************************************************************************************//
//*������SENC_CMD_Product_SM2_Generate()
//*���ܣ����ɰ忨�豸��Կ��|| Generate Senc Card RSA Keys;
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
// 		 uint8_t			EncryptLength				//���ܳ���
// 		 uint8_t			RsaKeyIdx					//RSA��Կ�洢����
//*���ڣ�2018/11/1
//by Zhang Tao
unsigned int SENC_CMD_Product_SM2_Generate(SENCryptCard*	IN	sencDev,
										   uint8_t			IN	EncryptLength,
										   uint8_t			IN	RsaKeyIdx);
//********************************************************************************************************//
//*������SENC_CMD_Product_RequestCSR()
//*���ܣ����豸����CSR|| Request CSR From Device;
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
// 		 uint32_t*			CsrLen						//����CSR����
// 		 uint8_t*			Csr							//����CSR����
//*���ڣ�2018/11/1
//by Zhang Tao
unsigned int SENC_CMD_Product_RequestCSR(SENCryptCard*	IN	sencDev,
										 uint32_t*		OUT CsrLen,
										 uint8_t*		OUT Csr);
//********************************************************************************************************//
//*������SENC_CMD_Product_DownLoadCert()
//*���ܣ�����֤��|| Download Certification;
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
// 		 uint8_t			CertType					//֤������
// 		 uint32_t			CertLen						//֤�鳤��
// 		 uint8_t*			Cert						//֤������
//*���ڣ�2018/11/1
//by Zhang Tao
unsigned int SENC_CMD_Product_DownLoadCert(SENCryptCard*	IN	sencDev,
										   uint8_t			IN CertType,
										   uint32_t			IN CertLen,
										   uint8_t*			IN Cert);
//********************************************************************************************************//
//*������SENC_CMD_Product_SetDefault()
//*���ܣ�����Ϊ����״̬|| Set to default state;
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//*���ڣ�2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_SetDefault(SENCryptCard*	IN	sencDev);
//********************************************************************************************************//
//*������SENC_CMD_ProTest_RSA_Signature()
//*���ܣ���������RSAǩ��|| Signature by RSA in production
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		rsaKey							//rsa private key
//		unsigned char*		pucInData						//��ǩ������
//		unsigned char*		pucSignedData					//ǩ����������
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_RSA_Signature(SENCryptCard*	IN	sencDev,
											unsigned char*	IN	rsaKey,
											unsigned char*	IN	pucInData,
											unsigned char*	OUT	pucSignedData);	
//********************************************************************************************************//
//*������SENC_CMD_ProTest_AES_Encrypt()
//*���ܣ���������AES����(256 ECB)|| AES encryption test in production (256 ECB)
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pwkey							//AES key
//		unsigned char*		pucInData						//����������
//		unsigned char*		pucSignedData					//���ؼ�������(256 ECB)
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_AES_Encrypt(SENCryptCard*		IN	sencDev,
										  unsigned char*	IN	pwkey,
										  unsigned char*	IN	pucInData,
										  unsigned char*	OUT	pucSignedData);
//********************************************************************************************************//
//*������SENC_CMD_ProTest_Write_NoEP()
//*���ܣ�д���ݲ���(�˷���)|| data write test without eject-proof
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucInData						//д���������
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_Write_NoEP(SENCryptCard*	IN	sencDev,
										 unsigned char*	IN	pucInData);
//********************************************************************************************************//
//*������SENC_CMD_ProTest_Write_EP()
//*���ܣ�д���ݲ���(δ�˷���)|| data write test with eject-proof
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucInData						//д���������
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_Write_EP(SENCryptCard*	IN	sencDev,
									   unsigned char*	IN	pucInData);
//********************************************************************************************************//
//*������SENC_CMD_ProTest_Read()
//*���ܣ������ݲ���|| data read test
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//		unsigned char*		pucRetData						//���ض�ȡ����
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_Read(SENCryptCard*	IN	sencDev,
								   unsigned char*	OUT	pucRetData);
//********************************************************************************************************//
//*������SENC_CMD_ProTest_Flash_sweep()
//*���ܣ�FLASH���ݲ���|| flash memory sweeper
//*������SENCryptCard*		sencDev							//���ܿ��豸handle
//*���ڣ�2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_Flash_sweep(SENCryptCard*	IN	sencDev);
//********************************************************************************************************//
#if defined __ALTER_ON__

unsigned int SENC_CMD_Alternative_Hash(SENCryptCard*	sencDev,				//���ܿ��豸handle
									   unsigned char hashAlgo,
									   const unsigned char* inData,
									   unsigned int inDataLen,
									   unsigned char*	pucRetData,
									   unsigned int* pucRetDataLen)	;			//���ض�ȡ����

unsigned int SENC_CMD_Alternative_GenRsaKeyPair(SENCryptCard*	sencDev,				//���ܿ��豸handle
												unsigned char keyBits,
												unsigned char EncAlgo,
												unsigned char EncIdx,
												unsigned char*	pucIV,
												unsigned char*	pucMAC,
												unsigned char*	pucRetRsaPrivKey,		//�����Ѽ���˽Կ����
												unsigned char*	pucRetRsaPubKey);		//�����Ѽ��ܹ�Կ����

unsigned int SENC_CMD_Alternative_SignatureExternal(SENCryptCard*	sencDev,				//���ܿ��豸handle
													unsigned char keyBits,
													unsigned char EncAlgo,
													unsigned char EncIdx,
													unsigned char*	pucIV,
													unsigned char*	pucMAC,
													unsigned char*	pucRsaPrivKey,		//�����Ѽ���˽Կ����
													unsigned char*	inData,
													unsigned char* retSignedData);	//�����Ѽ��ܹ�Կ����

unsigned int SENC_CMD_Alternative_VerifyExternal(SENCryptCard*	sencDev,				//���ܿ��豸handle
												 unsigned char keyBits,
												 unsigned char*	pucRsaPubKey,		//�����Ѽ���˽Կ����
												 unsigned char*	inSignedData,
												 unsigned char* retDecrypto);		//�����Ѽ��ܹ�Կ����


unsigned int SENC_CMD_Alternative_SignatureInternal(SENCryptCard*	sencDev,				//���ܿ��豸handle
													unsigned char keyBits,
													unsigned char KeyIdx,
													unsigned char*	inData,
													unsigned char* retSignedData);	//�����Ѽ��ܹ�Կ����

unsigned int SENC_CMD_Alternative_VerifyInternal(SENCryptCard*	sencDev,				//���ܿ��豸handle
												 unsigned char keyBits,
												 unsigned char KeyIdx,
												 unsigned char* inSignedData,
												 unsigned char* retDecrypto);		//�����Ѽ��ܹ�Կ����


unsigned int SENC_CMD_Alternative_PBKDF2Encrypt(SENCryptCard*	sencDev,				//���ܿ��豸handle
												unsigned char hashAlgo,
												unsigned char hashSaltAttr,
												unsigned int iteration,
												unsigned int outputKeyLen,
												unsigned char* inSaltData,
												unsigned int inSaltLen,
												unsigned char* inKeyData,
												unsigned int inKeyLen,
												unsigned char* outputKey);		//�����Ѽ��ܹ�Կ����

#endif

#if defined __DATA_PROTECTOR_ON__
//ǩ���û���Կ
unsigned int SENC_CMD_DataProtector_SignUserPubKey(SENCryptCard* IN	sencDev,
												   UserPubKey* IN  userkey,
												   UserPubKey* OUT userkey_new);
//�����ƶ���Կ
unsigned int SENC_CMD_DataProtector_GenWebKey(SENCryptCard*	IN sencDev,
											  KeyRecordRequest* IN req, 
											  UserPubKey* IN userPubKey,
											  KeyRecord* OUT key);
//�����ƶ���Կ��Ч��
unsigned int SENC_CMD_DataProtector_SetWebKeyPeriod(SENCryptCard* IN sencDev,
													KeyRecord* IN key,
													UserPubKey*	IN userPubKey,
													KeyPeriod*	IN keyPeriod,
													KeyRecord*	OUT key_new);
//������Կ����S1
unsigned int SENC_CMD_DataProtector_GenS1(SENCryptCard*	IN sencDev,
										  KeyRecord* IN key, 
										  UserPubKey* IN userkey,
										  License* IN license,
										  S1Cipher* OUT S1_E_Kc,
										  S1Cipher* OUT S1_E_Ku,
										  License* OUT license_new);
//ǩ�����
unsigned int SENC_CMD_DataProtector_IssueLicense(SENCryptCard* IN sencDev,
												 KeyRecord* IN key, 
												 UserPubKey* IN userkey,
												 uint8_t* IN LicID,
												 License* IN fatherLic,
												 LicenseRequest* IN LicReq,
												 License* OUT Lic);
//ת������
unsigned int SENC_CMD_DataProtector_CipherConvert(SENCryptCard*	IN sencDev,
												  KeyRecord* IN key,
												  UserPubKey* IN userkey,
												  License* IN Lic,
												  S1Cipher* IN S1_E_Kc,
												  S1Cipher* IN S1_E_Ku,
												  License* OUT Lic_new);

unsigned int SENC_CMD_DataProtector_SetMacCalculateKey(SENCryptCard* IN sencDev,
													   uint8_t* data, 
													   uint32_t datalen);

unsigned int SENC_CMD_DataProtector_GetRTCTime(SENCryptCard* IN sencDev,
											   uint64_t* OUT RTCTime);

unsigned int SENC_CMD_DataProtector_GetSupportedAlgorithm(SENCryptCard*	IN sencDev,
														  uint8_t* OUT supportedAlgorithm);

unsigned int SENC_CMD_DataProtector_SetRTCTime(SENCryptCard* IN sencDev,
											   uint8_t* IN PinCode,
											   uint64_t* IN TimeStamp);


//��ȡ�忨��ʼ��״̬
unsigned int SENC_CMD_DataProtector_GetChipInitStatus(SENCryptCard* IN sencDev,
													  unsigned char*	OUT	pucRetState);

//�Ӱ忨��ȡ��ʼ�������
unsigned int SENC_CMD_DataProtector_GetInitReq(SENCryptCard* IN sencDev,
											   ChipInitRequest* OUT Req,
											   uint8_t* OUT CaCert,
											   uint32_t* OUT CaCertLen,
											   uint8_t* OUT Cert,
											   uint32_t* OUT CertLen,
											   uint8_t* OUT Pri,
											   uint8_t* OUT Pub);

//�忨ִ�г�ʼ�������
unsigned int SENC_CMD_DataProtector_ChipInit(SENCryptCard* IN sencDev,
											 ChipInitCommand IN Cmd,
											 uint8_t * IN CaCert,
											 uint32_t IN CaCertLen,
											 uint8_t * IN Cert,
											 uint32_t IN CertLen);
//�Ӱ忨��ȡ��֤����Ա�����ݰ�
unsigned int SENC_CMD_DataProtector_GetAuthPackage(SENCryptCard* IN sencDev,
												   AuthAdminKey* OUT pkg);
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
												uint32_t* OUT KCCreateCodeLen);

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
										  uint32_t* OUT BindCodeCipherLen);

//����Circle
unsigned int SENC_CMD_KeyManager_CreateCircle(SENCryptCard* IN sencDev,
											  uint8_t* IN circle_id,
											  KeybagCreateCircleReq IN KBCreateCircleReq,
											  uint32_t IN KBCreateCircleReqLen,
											  uint8_t* IN BindCodeVrfPkgCipher,
											  uint32_t IN BindCodeVrfPkgCipherLen,
											  uint32_t* OUT TimeStamp,
											  KeybagCircle* OUT KBCircle,
											  uint32_t* OUT KBCircleLen);

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
											uint32_t* OUT KBNewCircleLen);


#endif
#endif //LIBSENC_SENC_CMD_FRAME_H_