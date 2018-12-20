#ifndef LIBSENC_SENC_AES_H_
#define LIBSENC_SENC_AES_H_
#include "senc_assist.h"

#define			SENC_AES_128														128
#define			SENC_AES_256														256
#define			SENC_AES_BLOCK_SIZE													16


//********************************************************************************************************//
//*������SENC_AES_Dispersion()
//*���ܣ���Կ��ɢ�������Ự��Կ||Key dispersion and generate session key
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char*		RandNum						//��ʾ�����
//*���ڣ�2016/10/27
//by Wangjf
unsigned int SENC_AES_Dispersion(SENCryptCard* sencDev,			//���ܿ��豸handle
								 unsigned char* RandNum);		//��ʾ�����
//********************************************************************************************************//
//*������SENC_AES_CmdDataEncrypt()
//*���ܣ������ݽ���AES����||Encrypt input data by AES
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char*		pucCmdData					//�������������
//		unsigned char*		pucCryptograph				//�������
//		unsigned int*		DataLength					//���ܺ��������
//*���ڣ�2016/10/28
//by Wangjf
unsigned int SENC_AES_CmdDataEncrypt(SENCryptCard* sencDev,			//���ܿ��豸handle
									 unsigned char* pucCmdData,		//�������������
									 unsigned char* pucCryptograph,	//�������
									 unsigned int* DataLength);		//���ܺ��������
//********************************************************************************************************//
//*������SENC_AES_CmdDataDecrypt()
//*���ܣ������ݽ���AES����||Decrypt input data by AES
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char*		pucCryptograph				//�������������
//		unsigned char*		pucDecryptedData			//�������
//		unsigned int*		DataLength					//���ܺ��������
//*���ڣ�2016/10/28
//by Wangjf
unsigned int SENC_AES_CmdDataDecrypt(SENCryptCard* sencDev,				//���ܿ��豸handle
									 unsigned char* pucCryptograph,		//�������������
									 unsigned char* pucDecryptedData,	//�������
									 unsigned int DataLength);			//���볤��
//********************************************************************************************************//
//*������SENC_AES_DHPrivCal()
//*���ܣ�����ͨ����Կ||Calculate Communication Key
//*������SENCryptCard*		sencDev						//���ܿ��豸handle
//		unsigned char*		ucInEncKey					//����ͨ����Կ
//*���ڣ�2016/10/27
//by Wangjf
unsigned int SENC_AES_DHPrivCal(SENCryptCard* sencDev,				//���ܿ��豸handle
								unsigned char* ucInEncKey);			//����ͨ����Կ
//********************************************************************************************************//
//********************************************************************************************************//
//********************************************************************************************************//

#endif //LIBSENC_SENC_AES_H_