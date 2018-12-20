#ifndef LIBSENC_SENC_INTERNALAPI_H_
#define LIBSENC_SENC_INTERNALAPI_H_

#include "libsenc.h"

#define			SENC_CMD_HEAD													0x55
#define			SENC_PLAINTEXT_SIGN												0x00
#define			SENC_CIPHER_SIGN												0x11

//*������SENC_CMD_Transfer()
//*���ܣ�SENC���ܿ����ݴ���||Data transfer
//*������SENCryptCard		sencDev,				//���ܿ��豸handle
//		unsigned char	EncryptType					//��������
//		unsigned char	WriteEndPoint				//���Ͷ˿�
//		unsigned char	ReadEndPoint				//���ն˿�
// 		unsigned char*	pucSendData					//��������
//		unsigned int	uiSendLength				//�������ݳ���
// 		unsigned char*	pucReadData					//��������
//		unsigned int	uiReadLength				//�������ݳ���
//*���ڣ�2016/10/24
//by Wangjf
unsigned int SENC_CMD_Transfer(SENCryptCard*			sencDev,
							   unsigned char			EncryptType,
							   unsigned char			WriteEndPoint,
							   unsigned char			ReadEndPoint,
							   unsigned char*			pucSendData,	
							   unsigned int				uiSendLength,	
							   unsigned char*			pucReadData,
							   unsigned int				uiReadLength);


#endif //LIBSENC_SENC_INTERNALAPI_H_