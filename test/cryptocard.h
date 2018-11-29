#ifndef _HEADER_CRYPTOCARD_H_
#define _HEADER_CRYPTOCARD_H_

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned __int64 uint64;
typedef __int64 int64;

#define VERSION_CURRENT_VERSION            0x10001001

typedef struct tagKEY_REC_REQ
{
	uint32 Version;                           // �汾��
	uint32 Reserved;                          // �����֣����ڽṹ�����
	uint8  KeyID[16];                         // ��ԿID
	uint8  OwnerUserID[16];                   // ��Կ������ID
	uint8  OwnerKeyFingerprint[32];           // ��Կ�����ߵ���ԿID���û���Կ��ָ��
	uint8  DevlpID[8];                        // APP������ID
	uint8  AppID[8];                          // APP ID
	int64 timeStamp;                 // ��Կ�������ɵ�ʱ�䣬5����֮��ʧЧ
	uint32 AlgoID;                            // ��Կ���ͣ��㷨
	uint32 KeyBits;                           // ��Կbit����
	int64 BeginTime;                          // ��Կ��Ч��ʼʱ��
	int64 EndTime;                            // ��Կ��Ч����ʱ��
	uint8 Signature[256];                     // �û�ǩ����SS�����ɣ�Ӳ����֤
}KEY_REC_REQ;

#define ALGID_AES      0x00000001             // AES��Կ
#define ALGID_RSA_PUB  0x00010100             // RSA��Կ
#define ALGID_RSA_PRI  0x00020100             // RSA˽Կ
#define ALGID_SM2_PUB  0x00010200             // SM2��Կ
#define ALGID_SM2_PRI  0x00020200             // SM2˽Կ

typedef struct tagKEY_REC
{
	uint32 Version;                           // �汾��
	uint32 Reserved;                          // �����֣����ڽṹ���ֶ�����
	uint8  KeyID[16];			              // ��ԿID
	uint8  OwnerUserID[16];                   // ��Կ������ID
	uint8  OwnerKeyFingerprint[32];           // ��Կ�����ߵ���ԿID,�û���Կ��ָ��
	uint8  DevlpID[8];                        // APP������ID
	uint8  AppID[8];                          // APP ID
	int64 BeginTime;                          // ��Կ��Ч��ʼʱ��
	int64 EndTime;                            // ��Կ��Ч����ʱ��
	uint32 AlgoID;                            // ��Կ���ͣ��㷨
	uint32 KeyBits;                           // ��Կbit����
	uint8  Key_C_enc[40];		              // ���ڲ���Կ���ܵ��ƶ���Կ
	uint8  MAC[32];                           // ��Կ��¼��У���룬��Ӳ�����㣬Ӳ����֤
}KEY_REC;

typedef struct tagUSER_PUB_KEY
{
	uint32 Version;                           // �汾��
	uint8  OwnerUserID[16];                   // ��Կ������ID
	uint32 Reserved;                          // �����֣����ڽṹ�����
	int64 TimeStamp;                          // ��Կ����ʱ��
	uint32 AlgoID;                            // ��Կ���ͣ��㷨
	uint32 KeyBits;                           // ��Կbit����
	uint32 KeyLen;                            // keyValue�е���Ч��Կ����
	uint8  KeyValue[300];                     // ��Կ���ͣ��㷨
	uint8  Mac[32];                           // �û���Կ��У���룬��Ӳ�����㣬Ӳ����֤
}USER_PUB_KEY;

typedef struct tagLIC_LIMITED
{
	uint32 Version;                           // �汾��
	uint32 Validity;                          // ��־λ����ʶ�����������Ч��
	int64 BeginTime;                          // ��ʼʱ��
	int64 EndTime;                            // ����ʱ��
	int64 FirstTime;                          // ��һ��ʹ��ʱ��
	int64 SpanTime;                           // ����ʱ���
	int64 Times;                              // ���ô˴���
	uint32 Policy;                            // ���ԣ���ʶ����д����ӡ���̳�
	uint32 Reserved;                          // �����֣����ڽṹ�����
}LIC_LIMITED;

// flag���壺
#define FLAG_START_TIME    0x00000001
#define FLAG_END_TIME      0x00000002
#define FLAG_SPAN_TIME	    0x00000004
#define FLAG_TIMES          0x00000008

// Policy���壺
#define POLICY_INHERIT     0x00000001         // ����̳�
#define POLICY_DECRYPT	   0x00000002         // �������
#define POLICY_ENCRYPT	   0x00000004         // �������
#define POLICY_PRINT       0x00001000         // �����ӡ
#define POLICY_EXPORT      0x00002000         // ����������
#define POLICY_UNREVOKABLE 0x00004000         // ���ɳ�����

typedef struct tagLICENSE
{
	uint32 Version;                           // �汾��
	uint8  LicID[16];                         // ���ID
	uint8  FartherLicID[16];                  // �����ID
	uint8  IssuerUserID[16];                  // ���ǩ����ID
	uint8  OwnerUserID[16];                   // ���������ID
	uint8  UserKeyFingerprint[32];            // �����������ԿID���û���Կ��ָ��
	uint8  KeyID[16];                         // ����Ȩ����ԿID
	uint32 Reserved;                          // �����֣����ڽṹ���ֶ�����
	LIC_LIMITED licLimited;                   // �������
	uint8  Mac[32];                           // �����ϢУ���룬��Ӳ�����㣬Ӳ����֤
}LICENSE;

typedef struct tagLIC_REQ
{
	uint32 Version;                           // �汾��
	uint8  FartherLicID[16];                  // �����ID
	uint8  OwnerUserID[16];                   // ���������ID
	uint8  UserKeyFingerprint[32];            // �����������ԿID
	uint8  KeyID[16];                         // ����Ȩ����ԿID
	uint32 Reserved;                          // �����֣����ڽṹ���ֶ�����
	int64 TimeStamp;                          // ����������ɵ�ʱ������ʱ�䣬5����֮��ʧЧ
	LIC_LIMITED licLimited;                   // �������
	uint8  Signature[256];                    // �û�ǩ����SS�����ɣ�Ӳ����֤
}LIC_REQ;

typedef struct tagS1_CIPHER
{
	uint32 Version;                           // �汾��
	uint32 Len;                               // ���ĳ���
	uint8  Cipher[256];                       // ��������
}S1_CIPHER;

typedef struct tagKEY_PERIOD
{
	uint32 Version;                           // �汾��
	uint8  KeyID[16];                         // ��ԿID
	uint32 Reserved;                          // �����֣����ڽṹ���ֶ�����
	int64 TimeStamp;                          // ��Ч����������ʱ�䣬5����֮��ʧЧ
	int64 BeginTime;                          // ��ʼʱ��
	int64 EndTime;                            // ����ʱ��
	uint8  Signature[256];                    // �û�ǩ����SS�����ɣ�Ӳ����֤
}KEY_PERIOD;

// �����붨��
#define CC_ERROR_SUCCESS                     0
#define CC_ERROR_GENERAL_ERROR               1

// 1.	ǩ���û���Կ
int SignUserPubKey(USER_PUB_KEY *userkey);

// ���ܣ�ǩ���û���Կ
// ˵���������userkey�ṹ���У���Mac֮�����������ݾ��Ѿ�ready�����ӿڼ����userkey��Macֵ������ýṹ���Mac��Աλ�ã��������userkey�ṹ�塣
// MAC���㷽ʽ��userkey��Mac���֣�����AES_MAC

// 2.	�����ƶ���Կ
int GenerateKeyCloud(KEY_REC_REQ *req, USER_PUB_KEY *userkey, KEY_REC *key);

// ���ܣ������ƶ���Կ
// ˵����������������󴴽�һ���ƶ���Կ�������ƶ���Կ�ṹ�塣���������req�еĳ�Աֵ�����ýṹ��Key�еĶ�Ӧֵ���������һ��req��Աflagָ�����㷨����Կ����ʹ�ü��ܿ���Ԥ���AES��Կ���ܣ������ı�����Key�ĳ�ԱKey_C_enc�У�������Key�г�Mac��Ա��������г�Ա��AES_MACֵ���뵽key��Mac��Ա�С�

// 3.	�����ƶ���Կ��Ч��
int SetKeyCloudPeriod(KEY_REC *key, USER_PUB_KEY *userkey, KEY_PERIOD *keyPeriod, KEY_REC *key_New);

// ���ܣ������ƶ���Կ����Ч��
// ˵���������û�ǩ������Կ��Ч���������ݣ������ƶ���Կ����Ч�ڡ���֤Key��userkey��Macֵ����֤key��userkey�еĳ�ԱownerIDOwnerUserID��ֵ��ȣ���֤key�е�OwnerKeyIDFingerprint��Ա��ֵ����userkey�ṹ���hashֵ��SHA256�������KeyPeriod�е�timeStamp������ȷ��KeyPeriod�ṹ������Ч�ġ����KeyPeriod�е�KeyID��key��KeyID��ȡ�
// ʹ��userkey��֤KeyPeriod�е��û�ǩ����
// ����Key���������period�е�stTime��endTime��Ա������Key�е�stTime��endTime��Ա�����¼���Key��Macֵ��

// 4.	������Կ����S1
int GenerateS1(KEY_REC *key, USER_PUB_KEY *userkey, LICENSE *lic, S1_CIPHER *S1_E_Kc, S1_CIPHER *S1_E_Ku, LICENSE *lic_New);

// ���ܣ�����S1
// ˵������֤Key��userkey��Macֵ����֤key��userkey�еĳ�ԱownerID��ֵ��ȣ���֤key�е�OwnerKeyID��Ա��ֵ����userkey�ṹ���hashֵ��SHA256�����������S1����ʹ�������key��userkey�ֱ��S1���ܺ󷵻أ�ע��ʹ��key��S1���ܣ�������ʹ�ü��ܿ���Ԥ���AES��Կ��key�еĳ�ԱKey_C_enc���ܣ��õ���Կֵ��Ȼ��ʹ��key�ṹ���е�flag��ָ�����㷨��S1����

// 5.	ǩ�����
int issueLicense(KEY_REC *key, USER_PUB_KEY *userkey, uint8 *licID, LICENSE *fartherLic, LIC_REQ *licReq, LICENSE *lic);

// ���ܣ�ǩ�����
// ˵������֤Key��userkey��Macֵ��
// ���fartherLicΪ0����֤key��userkey�еĳ�ԱownerID��ֵ��ȣ���֤key�е�OwnerKeyID��Ա��ֵ����userkey�ṹ���hashֵ��SHA256����
// ���fartherLic��Ϊ0����֤fartherLic��Macֵ����֤fartherLic�ĳ�ԱUserID��userkey�еĳ�ԱownerID��ֵ��ȣ���֤fartherLic�е�UserKeyID��Ա��ֵ����userkey�ṹ���hashֵ��SHA256����
// ��֤ʹ��userkey��֤LicReq�е��û�ǩ����
// ���fartherLicΪ0�����������licreq����һ��license��������License�ṹ��Macֵ�����¹�����license�ṹ�塣
// ���fartherLic��Ϊ0�����fartherLic�е�policy�ֶΣ����Ƿ�֧�ּ̳У������֧�ּ̳У��򱨴����֧�ּ̳У�����licreq�е������Ƿ񳬳�fartherLic�е��������ƣ����������������license��������Mac�����¹�����license�ṹ��


// 6.	ת������
int convertCipher(KEY_REC *key, USER_PUB_KEY *userkey, LICENSE *lic, S1_CIPHER *S1_E_Kc, S1_CIPHER *S1_E_Ku, LICENSE *Lic_new);
// ���ܣ�ת�����ģ��ѱ�key���ܵ�S1��ת���ɱ�userkey���ܵ�S1
// ˵������֤Key��userkey��Macֵ��
// ���LicΪ0����֤key��userkey�еĳ�ԱownerID��ֵ��ȣ���֤key�е�OwnerKeyID��Ա��ֵ����userkey�ṹ���hashֵ��SHA256����
// ���Lic��Ϊ0����֤Lic��Macֵ����֤Lic�ĳ�ԱUserID��userkey�еĳ�ԱownerID��ֵ��ȣ���֤Lic�е�UserKeyID��Ա��ֵ����userkey�ṹ���hashֵ��SHA256�������lic->licLimited������Ƿ���Ч���Ƿ��н���Ȩ�ޣ������ɹ��ڻ���ʧЧ������ʹ��key���������S1_E_Kc�õ�S1��Ȼ��ʹ��userkey����S1�õ�S1_E_Ku���鿴Lic���������д���������Ҫ����һ�Σ������ʱ�����Ȩ���ҵ�һ��ʹ�ø���Ȩ����Ҫ������Ȩ��ʧЧʱ�䣬���½���lic��Macֵ������S1_E_Ku���µ���ɽṹ��lic_new


#endif // _HEADER_CRYPTOCARD_H_
