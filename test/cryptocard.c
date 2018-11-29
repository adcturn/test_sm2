#include "cryptocard.h"
#include <stdint.h>
#include <libusb/libusb.h>

#define success		0x00
#define error		0x01

libusb_device_handle *device_handle;
libusb_device **devs;

uint8_t SendBuf[2048];
uint32_t SendLen;
uint8_t RecvBuf[2048];
uint32_t RecvLen;

//#define PRINT_COMMAND

void DisMsg(void* pstr, uint8_t *inDat, uint32_t inLen)
{
	uint8_t *pMsg = (uint8_t *)pstr;
	printf("%s", pMsg);
	for (uint32_t i = 0; i < inLen; i++)
	{
		printf("%02X", inDat[i]);
	}
	printf("\n");
}

int OpenDevice(void)
{
#define DEVICE_VID	0x1BC0
#define DEVICE_PID  0x0452
	int wRet, cnt;

	if (device_handle != NULL)
		return error;
	//Init libusb
	wRet = libusb_init(NULL);
	if (wRet < 0)
	{
		printf("*************   Init Failed！   *************\n");
		return error;
	}

	//Get device list
	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt < 0)
	{
		printf("*************   Get List Failed！   *************\n");
		return error;
	}

	// open device with vid&pid
	device_handle = libusb_open_device_with_vid_pid(NULL, DEVICE_VID, DEVICE_PID);
	if (device_handle == NULL)
	{
		printf("*************   Open Failed！   *************\n");
		return error;
	}

	// claim the interface 
	libusb_set_auto_detach_kernel_driver(device_handle, 1);
	wRet = libusb_claim_interface(device_handle, 0);
	if (wRet != 0)
	{
		printf("*************   Claim Failed！   *************\n");
		return error;
	}

	return success;
}

int CloseDevice(void)
{
	if (device_handle == NULL)
	{
		printf("设备未打开！\n");
		return error;
	}

	libusb_close(device_handle);
	libusb_free_device_list(devs, 1);
	libusb_exit(NULL);

	device_handle = NULL;

	return success;
}

int Communication(uint8_t *inBuf, uint32_t inLen, uint8_t *outBuf, uint32_t *outLen)
{
	uint32_t wRet;
	int sizelen;
	char tmpChar[65535];

	wRet = libusb_bulk_transfer(device_handle, 0x01, inBuf, inLen, &sizelen, 0);
	if (wRet != 0x00)
	{
		printf("\n");
		printf("*************   Send error！   *************\n\n");
		return error;
	}

	wRet = libusb_bulk_transfer(device_handle, 0x81, outBuf, 2048, &sizelen, 0);
	if (wRet != 0x00)
	{
		printf("\n");
		printf("*************   Receive error！   *************\n\n");
		return error;
	}

	if ((outBuf[0] != 0xFF) && (outBuf[0] != 0x55))
	{
		printf("*************   指令格式错误！   *************\n");
		return error;
	}

	if (outBuf[0] == 0xFF)
	{
		*outLen = (outBuf[1] << 8) | outBuf[2];
		*outLen += 3;
	}
	else
	{
		*outLen = 17;
	}

}

// 1.	签发用户公钥
int SignUserPubKey(USER_PUB_KEY *userkey)
{
	SendLen = 4;

	// IN 
	memcpy(SendBuf + SendLen, userkey, sizeof(USER_PUB_KEY));
	SendLen += sizeof(USER_PUB_KEY);

	// Instruction Header
	SendBuf[0] = 0xF3;
	SendBuf[1] = (SendLen - 3) / 256;
	SendBuf[2] = (SendLen - 3) % 256;
	SendBuf[3] = 0x01;

	// 指令交互
	Communication(SendBuf, SendLen, RecvBuf, &RecvLen);

#ifdef PRINT_COMMAND
	DisMsg("SignuserPubKey Send\t", SendBuf, SendLen);
	DisMsg("SignuserPubKey Recv\t", RecvBuf, RecvLen);
	printf("\n");
#endif

	// OUT
	if (RecvBuf[0] == 0xFF)
	{
		memcpy(userkey, RecvBuf + 6, sizeof(USER_PUB_KEY));
		return 0;
	}
	else
		return(RecvBuf[15] << 8 | RecvBuf[16]);
}

// 2.	生成云端密钥
int GenerateKeyCloud(KEY_REC_REQ *req, USER_PUB_KEY *userkey, KEY_REC *key)
{
	SendLen = 4;

	// IN
	memcpy(SendBuf + SendLen, req, sizeof(KEY_REC_REQ));
	SendLen += sizeof(KEY_REC_REQ);
	memcpy(SendBuf + SendLen, userkey, sizeof(USER_PUB_KEY));
	SendLen += sizeof(USER_PUB_KEY);

	// Instruction Header
	SendBuf[0] = 0xF3;
	SendBuf[1] = (SendLen - 3) / 256;
	SendBuf[2] = (SendLen - 3) % 256;
	SendBuf[3] = 0x02;

	// 指令交互
	Communication(SendBuf, SendLen, RecvBuf, &RecvLen);

#ifdef PRINT_COMMAND
	DisMsg("SignuserPubKey Send\t", SendBuf, SendLen);
	DisMsg("SignuserPubKey Recv\t", RecvBuf, RecvLen);
	printf("\n");
#endif

	// OUT
	if (RecvBuf[0] == 0xFF)
	{
		memcpy(key, RecvBuf + 6, sizeof(KEY_REC));
		return 0;
	}
	else
		return(RecvBuf[15] << 8 | RecvBuf[16]);
}

// 3.	设置云端密钥有效期
int SetKeyCloudPeriod(KEY_REC *key, USER_PUB_KEY *userkey, KEY_PERIOD *keyPeriod, KEY_REC *key_New)
{
	SendLen = 4;

	// IN
	memcpy(SendBuf + SendLen, key, sizeof(KEY_REC));
	SendLen += sizeof(KEY_REC);
	memcpy(SendBuf + SendLen, userkey, sizeof(USER_PUB_KEY));
	SendLen += sizeof(USER_PUB_KEY);
	memcpy(SendBuf + SendLen, keyPeriod, sizeof(KEY_PERIOD));
	SendLen += sizeof(KEY_PERIOD);

	// Instruction Header
	SendBuf[0] = 0xF3;
	SendBuf[1] = (SendLen - 3) / 256;
	SendBuf[2] = (SendLen - 3) % 256;
	SendBuf[3] = 0x03;

	// 指令交互
	Communication(SendBuf, SendLen, RecvBuf, &RecvLen);

#ifdef PRINT_COMMAND
	DisMsg("SignuserPubKey Send\t", SendBuf, SendLen);
	DisMsg("SignuserPubKey Recv\t", RecvBuf, RecvLen);
	printf("\n");
#endif

	// OUT

	if (RecvBuf[0] == 0xFF)
	{
		memcpy(key_New, RecvBuf + 6, sizeof(KEY_REC));
		return 0;
	}
	else
		return(RecvBuf[15] << 8 | RecvBuf[16]);
}

// 4.	生成密钥种子S1
int GenerateS1(KEY_REC *key, USER_PUB_KEY *userkey, LICENSE *lic, S1_CIPHER *S1_E_Kc, S1_CIPHER *S1_E_Ku, LICENSE *lic_New)
{
	SendLen = 4;

	// IN
	memcpy(SendBuf + SendLen, key, sizeof(KEY_REC));
	SendLen += sizeof(KEY_REC);
	memcpy(SendBuf + SendLen, userkey, sizeof(USER_PUB_KEY));
	SendLen += sizeof(USER_PUB_KEY);
	if (lic != NULL)
	{// lic一般不能为0
		memcpy(SendBuf + SendLen, lic, sizeof(LICENSE));
		SendLen += sizeof(LICENSE);
	}

	// Instruction Header
	SendBuf[0] = 0xF3;
	SendBuf[1] = (SendLen - 3) / 256;
	SendBuf[2] = (SendLen - 3) % 256;
	SendBuf[3] = 0x04;

	// 指令交互
	Communication(SendBuf, SendLen, RecvBuf, &RecvLen);

#ifdef PRINT_COMMAND
	DisMsg("SignuserPubKey Send\t", SendBuf, SendLen);
	DisMsg("SignuserPubKey Recv\t", RecvBuf, RecvLen);
	printf("\n");
#endif

	// OUT
	if (RecvBuf[0] == 0xFF)
	{
		uint32_t wOffset = 6;
		memcpy(S1_E_Kc, RecvBuf + wOffset, sizeof(S1_CIPHER));
		wOffset += sizeof(S1_CIPHER);
		memcpy(S1_E_Ku, RecvBuf + wOffset, sizeof(S1_CIPHER));
		wOffset += sizeof(S1_CIPHER);
		if (lic_New != NULL)
		{
			memcpy(lic_New, RecvBuf + wOffset, sizeof(LICENSE));
			wOffset += sizeof(LICENSE);
		}

		return 0;
	}
	else
		return(RecvBuf[15] << 8 | RecvBuf[16]);
}

// 5.	签发许可
int issueLicense(KEY_REC *key, USER_PUB_KEY *userkey, uint8 *licID, LICENSE *fartherLic, LIC_REQ *licReq, LICENSE *lic)
{
	SendLen = 4;

	// IN
	memcpy(SendBuf + SendLen, key, sizeof(KEY_REC));
	SendLen += sizeof(KEY_REC);
	memcpy(SendBuf + SendLen, userkey, sizeof(USER_PUB_KEY));
	SendLen += sizeof(USER_PUB_KEY);
	memcpy(SendBuf + SendLen, licID, 16);
	SendLen += 16;
	if (fartherLic != NULL)
	{
		memcpy(SendBuf + SendLen, fartherLic, sizeof(LICENSE));
		SendLen += sizeof(LICENSE);
	}
	memcpy(SendBuf + SendLen, licReq, sizeof(LIC_REQ));
	SendLen += sizeof(LIC_REQ);

	// Instruction Header
	SendBuf[0] = 0xF3;
	SendBuf[1] = (SendLen - 3) / 256;
	SendBuf[2] = (SendLen - 3) % 256;
	SendBuf[3] = 0x05;

	// 指令交互
	Communication(SendBuf, SendLen, RecvBuf, &RecvLen);

#ifdef PRINT_COMMAND
	DisMsg("SignuserPubKey Send\t", SendBuf, SendLen);
	DisMsg("SignuserPubKey Recv\t", RecvBuf, RecvLen);
	printf("\n");
#endif

	// OUT

	if (RecvBuf[0] == 0xFF)
	{
		memcpy(lic, RecvBuf + 6, sizeof(LICENSE));
		return 0;
	}
	else
		return(RecvBuf[15] << 8 | RecvBuf[16]);
}

// 6.	转换密文
int convertCipher(KEY_REC *key, USER_PUB_KEY *userkey, LICENSE *lic, S1_CIPHER *S1_E_Kc, S1_CIPHER *S1_E_Ku, LICENSE *Lic_new)
{
	SendLen = 4;

	// IN
	memcpy(SendBuf + SendLen, key, sizeof(KEY_REC));
	SendLen += sizeof(KEY_REC);
	memcpy(SendBuf + SendLen, userkey, sizeof(USER_PUB_KEY));
	SendLen += sizeof(USER_PUB_KEY);
	if (lic != NULL)
	{
		memcpy(SendBuf + SendLen, lic, sizeof(LICENSE));
		SendLen += sizeof(LICENSE);
	}
	memcpy(SendBuf + SendLen, S1_E_Kc, sizeof(S1_CIPHER));
	SendLen += sizeof(S1_CIPHER);

	// Instruction Header
	SendBuf[0] = 0xF3;
	SendBuf[1] = (SendLen - 3) / 256;
	SendBuf[2] = (SendLen - 3) % 256;
	SendBuf[3] = 0x06;

	// 指令交互
	Communication(SendBuf, SendLen, RecvBuf, &RecvLen);

#ifdef PRINT_COMMAND
	DisMsg("SignuserPubKey Send\t", SendBuf, SendLen);
	DisMsg("SignuserPubKey Recv\t", RecvBuf, RecvLen);
	printf("\n");
#endif

	// OUT
	if (RecvBuf[0] == 0xFF)
	{
		uint32_t wOffset = 6;
		memcpy(S1_E_Ku, RecvBuf + wOffset, sizeof(S1_CIPHER));
		wOffset += sizeof(S1_CIPHER);
		if (Lic_new != NULL)
		{
			memcpy(Lic_new, RecvBuf + wOffset, sizeof(LICENSE));
			wOffset += sizeof(LICENSE);
		}

		return 0;
	}
	else
		return(RecvBuf[15] << 8 | RecvBuf[16]);
}
