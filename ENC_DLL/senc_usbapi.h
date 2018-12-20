#ifndef LIBSENC_SENC_USBAPI_H_
#define LIBSENC_SENC_USBAPI_H_

#include "libsenc.h"
#include "senc_assist.h"


#define			SENC_ERROR_USB_IO												0x00000101
#define			SENC_ERROR_USB_INVALID_PARAM									0x00000102
#define			SENC_ERROR_USB_ACCESS_DENY										0x00000103
#define			SENC_ERROR_USB_NO_DEVICE										0x00000104
#define			SENC_ERROR_USB_NOT_FOUND										0x00000105
#define			SENC_ERROR_USB_BUSY												0x00000106
#define			SENC_ERROR_USB_TIMEOUT											0x00000107
#define			SENC_ERROR_USB_OVERFLOW											0x00000108
#define			SENC_ERROR_USB_PIPE												0x00000109
#define			SENC_ERROR_USB_INTERRUPTED										0x0000010A
#define			SENC_ERROR_USB_NO_MEMORY										0x0000010B
#define			SENC_ERROR_USB_NOT_SUPPORTED									0x0000010C
#define			SENC_ERROR_USB_UNKNOWN											0x000001FF

//USB��ʱʱ��(ms)��0���޳�ʱ
#define			SENC_BULK_TIME_OUT												500000
#define			LIBUSB_TRANSFER_SUCCESS											0

#define			SENC_SS_PID														0x0452
#define			SENC_SS_VID														0x1BC0

//********************************************************************************************************//
//*������USB_GetDevList()
//*���ܣ���ȡ���ܿ��豸�б�||Get encrypt cards list;
//*������SENCryptCardList*		senclist						//���ܿ��豸�б�
//*���ڣ�2016/09/29 by Wangjf
unsigned int USB_GetDevList(SENCryptCardList*	OUT	senclist);
//********************************************************************************************************//
//*������SENC_Open()
//*���ܣ������豸||Open device
//*������SENCryptCard*	SencDev					//���ܿ��豸handle
//*���ڣ�2016/09/29 by Wangjf
unsigned int USB_Open(SENCryptCard*	IN	SencDev);
//********************************************************************************************************//
//*������SENC_Close()
//*���ܣ��ر��豸||Close device
//*������SENCryptCard*		sencDev,						//���ܿ��豸handle
//*���ڣ�2016/09/29 by Wangjf
unsigned int USB_Close(SENCryptCard*	IN	sencDev);
//********************************************************************************************************//
//*������SENC_Init()
//*���ܣ���ʼ���豸�ռ�||Initial device
//*������SENCryptCard*		sencDev,						//���ܿ��豸handle
//*���ڣ�2016/09/29 by Wangjf
unsigned int USB_Init(SENCryptCard*	IN	sencDev);
//********************************************************************************************************//
//*������SENC_Bulk_Write()
//*���ܣ�USB BULK_ONLYģʽд����||Data write-in in USB BulkOnly mode
//*������SENCryptCard*	sencDev,					//���ܿ��豸handle
//		unsigned int	EndPoint					//EndPoint д
//		unsigned char*	pucSendData					//����������
// 		unsigned int	uiSendLength				//���������ݳ���
//*���ڣ�2016/09/29 by Wangjf
unsigned int SENC_Bulk_Write(SENCryptCard*	IN	 sencDev,			//���ܿ��豸handle
							 unsigned char	IN	 EndPoint,			//EndPoint д
							 unsigned char*	IN	 pucSendData,		//����������
							 unsigned int	IN	 uiSendLength);		//���������ݳ���
//********************************************************************************************************//
//*������SENC_Bulk_Read()
//*���ܣ�USB BULK_ONLYģʽ������||Data read-in in USB BulkOnly mode
///*������SENCryptCard*	sencDev,					//���ܿ��豸handle
//		unsigned int	EndPoint					//EndPoint ��
// 		unsigned char*	pucReadData					//��������
//		unsigned int	uiReadLength				//�������ݳ���
//*���ڣ�2016/09/29 by Wangjf
unsigned int SENC_Bulk_Read(SENCryptCard*	IN	sencDev,			//���ܿ��豸handle
							unsigned char	IN	EndPoint,			//EndPoint ��
							unsigned char*	OUT	pucReadData,		//��������
							unsigned int	IN	uiReadLength);		//�������ݳ���
//********************************************************************************************************//
//*������sencdev_New()
//*���ܣ������豸ָ��ռ�||malloc memory for device pointer
//*������SENCryptCard		sencDev,						//���ܿ��豸handle
//*���ڣ�	2016/10/18
//by Wangjf
unsigned int sencdev_New(SENCryptCard** IN	sencDev);
//********************************************************************************************************//
//*������sencdev_Free()
//*���ܣ��ͷ��豸ָ��ռ�||free device pointer
//*������SENCryptCard		sencDev,						//���ܿ��豸handle
//*���ڣ�	2016/10/18
//by Wangjf
unsigned int sencdev_Free(SENCryptCard*	IN sencDev);
//********************************************************************************************************//

//*������sencdev_Init()
//*���ܣ���ʼ���豸ָ��ռ�||initialize device pointer memory
//*������SENCryptCard		sencDev,						//���ܿ��豸handle
//*���ڣ�	2016/10/18
//by Wangjf
unsigned int sencdev_Init(SENCryptCard*	IN sencDev);


//*������USB_NewCtx()
//*���ܣ���ʼ���豸�б�libusb����||Initialize libusb context of devices list;
//*������SENCryptCardList*		senclist						//���ܿ��豸�б�
//*���ڣ�2017/03/22
//by Wangjf
unsigned int USB_NewCtx(SENCryptCardList* senclist);

//*������USB_FreeCtx()
//*���ܣ��ͷ��豸�б�libusb����||Free libusb context of devices list;
//*������SENCryptCardList*		senclist						//���ܿ��豸�б�
//*���ڣ�2017/03/22
//by Wangjf
unsigned int USB_FreeCtx(SENCryptCardList* senclist);



#endif //LIBSENC_SENC_USBAPI_H_
