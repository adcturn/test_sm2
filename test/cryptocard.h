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
	uint32 Version;                           // 版本号
	uint32 Reserved;                          // 保留字，用于结构体对齐
	uint8  KeyID[16];                         // 密钥ID
	uint8  OwnerUserID[16];                   // 密钥所有者ID
	uint8  OwnerKeyFingerprint[32];           // 密钥所有者的密钥ID，用户公钥的指纹
	uint8  DevlpID[8];                        // APP开发商ID
	uint8  AppID[8];                          // APP ID
	int64 timeStamp;                 // 密钥请求生成的时间，5分钟之后失效
	uint32 AlgoID;                            // 密钥类型，算法
	uint32 KeyBits;                           // 密钥bit长度
	int64 BeginTime;                          // 密钥有效开始时间
	int64 EndTime;                            // 密钥有效结束时间
	uint8 Signature[256];                     // 用户签名，SS端生成，硬件验证
}KEY_REC_REQ;

#define ALGID_AES      0x00000001             // AES密钥
#define ALGID_RSA_PUB  0x00010100             // RSA公钥
#define ALGID_RSA_PRI  0x00020100             // RSA私钥
#define ALGID_SM2_PUB  0x00010200             // SM2公钥
#define ALGID_SM2_PRI  0x00020200             // SM2私钥

typedef struct tagKEY_REC
{
	uint32 Version;                           // 版本号
	uint32 Reserved;                          // 保留字，用于结构体手动对齐
	uint8  KeyID[16];			              // 密钥ID
	uint8  OwnerUserID[16];                   // 密钥所有者ID
	uint8  OwnerKeyFingerprint[32];           // 密钥所有者的密钥ID,用户公钥的指纹
	uint8  DevlpID[8];                        // APP开发商ID
	uint8  AppID[8];                          // APP ID
	int64 BeginTime;                          // 密钥有效开始时间
	int64 EndTime;                            // 密钥有效结束时间
	uint32 AlgoID;                            // 密钥类型，算法
	uint32 KeyBits;                           // 密钥bit长度
	uint8  Key_C_enc[40];		              // 卡内部密钥加密的云端密钥
	uint8  MAC[32];                           // 密钥记录的校验码，由硬件计算，硬件验证
}KEY_REC;

typedef struct tagUSER_PUB_KEY
{
	uint32 Version;                           // 版本号
	uint8  OwnerUserID[16];                   // 密钥所有者ID
	uint32 Reserved;                          // 保留字，用于结构体对齐
	int64 TimeStamp;                          // 密钥生成时间
	uint32 AlgoID;                            // 密钥类型，算法
	uint32 KeyBits;                           // 密钥bit长度
	uint32 KeyLen;                            // keyValue中的有效密钥长度
	uint8  KeyValue[300];                     // 密钥类型，算法
	uint8  Mac[32];                           // 用户公钥的校验码，由硬件计算，硬件验证
}USER_PUB_KEY;

typedef struct tagLIC_LIMITED
{
	uint32 Version;                           // 版本号
	uint32 Validity;                          // 标志位，标识后续条款的有效性
	int64 BeginTime;                          // 起始时间
	int64 EndTime;                            // 结束时间
	int64 FirstTime;                          // 第一次使用时间
	int64 SpanTime;                           // 可用时间段
	int64 Times;                              // 可用此次数
	uint32 Policy;                            // 策略，标识读，写，打印，继承
	uint32 Reserved;                          // 保留字，用于结构体对齐
}LIC_LIMITED;

// flag定义：
#define FLAG_START_TIME    0x00000001
#define FLAG_END_TIME      0x00000002
#define FLAG_SPAN_TIME	    0x00000004
#define FLAG_TIMES          0x00000008

// Policy定义：
#define POLICY_INHERIT     0x00000001         // 允许继承
#define POLICY_DECRYPT	   0x00000002         // 允许解密
#define POLICY_ENCRYPT	   0x00000004         // 允许加密
#define POLICY_PRINT       0x00001000         // 允许打印
#define POLICY_EXPORT      0x00002000         // 允许导出明文
#define POLICY_UNREVOKABLE 0x00004000         // 不可撤销的

typedef struct tagLICENSE
{
	uint32 Version;                           // 版本号
	uint8  LicID[16];                         // 许可ID
	uint8  FartherLicID[16];                  // 父许可ID
	uint8  IssuerUserID[16];                  // 许可签发者ID
	uint8  OwnerUserID[16];                   // 许可所有者ID
	uint8  UserKeyFingerprint[32];            // 许可所有者密钥ID，用户公钥的指纹
	uint8  KeyID[16];                         // 被授权的密钥ID
	uint32 Reserved;                          // 保留字，用于结构体手动对齐
	LIC_LIMITED licLimited;                   // 许可条款
	uint8  Mac[32];                           // 许可信息校验码，由硬件计算，硬件验证
}LICENSE;

typedef struct tagLIC_REQ
{
	uint32 Version;                           // 版本号
	uint8  FartherLicID[16];                  // 父许可ID
	uint8  OwnerUserID[16];                   // 许可所有者ID
	uint8  UserKeyFingerprint[32];            // 许可所有者密钥ID
	uint8  KeyID[16];                         // 被授权的密钥ID
	uint32 Reserved;                          // 保留字，用于结构体手动对齐
	int64 TimeStamp;                          // 许可请求生成的时间生成时间，5分钟之后失效
	LIC_LIMITED licLimited;                   // 许可条款
	uint8  Signature[256];                    // 用户签名，SS端生成，硬件验证
}LIC_REQ;

typedef struct tagS1_CIPHER
{
	uint32 Version;                           // 版本号
	uint32 Len;                               // 密文长度
	uint8  Cipher[256];                       // 密文内容
}S1_CIPHER;

typedef struct tagKEY_PERIOD
{
	uint32 Version;                           // 版本号
	uint8  KeyID[16];                         // 密钥ID
	uint32 Reserved;                          // 保留字，用于结构体手动对齐
	int64 TimeStamp;                          // 有效期数据生成时间，5分钟之后失效
	int64 BeginTime;                          // 起始时间
	int64 EndTime;                            // 结束时间
	uint8  Signature[256];                    // 用户签名，SS端生成，硬件验证
}KEY_PERIOD;

// 错误码定义
#define CC_ERROR_SUCCESS                     0
#define CC_ERROR_GENERAL_ERROR               1

// 1.	签发用户公钥
int SignUserPubKey(USER_PUB_KEY *userkey);

// 功能：签发用户公钥
// 说明：输入的userkey结构体中，除Mac之外其他的数据均已经ready，本接口计算该userkey的Mac值，并填到该结构体的Mac成员位置，返回这个userkey结构体。
// MAC计算方式对userkey除Mac部分，计算AES_MAC

// 2.	生成云端密钥
int GenerateKeyCloud(KEY_REC_REQ *req, USER_PUB_KEY *userkey, KEY_REC *key);

// 功能：生成云端密钥
// 说明：根据输入的请求创建一个云端密钥，返回云端密钥结构体。根据输入的req中的成员值，设置结构体Key中的对应值，随机生成一个req成员flag指定的算法的密钥，并使用加密卡内预设的AES密钥加密，把密文保存在Key的成员Key_C_enc中，并计算Key中除Mac成员以外的所有成员的AES_MAC值填入到key的Mac成员中。

// 3.	设置云端密钥有效期
int SetKeyCloudPeriod(KEY_REC *key, USER_PUB_KEY *userkey, KEY_PERIOD *keyPeriod, KEY_REC *key_New);

// 功能：设置云端密钥的有效期
// 说明：根据用户签发的密钥有效期设置数据，设置云端密钥的有效期。验证Key和userkey的Mac值，验证key和userkey中的成员ownerIDOwnerUserID的值相等，验证key中的OwnerKeyIDFingerprint成员的值等于userkey结构体的hash值（SHA256），检查KeyPeriod中的timeStamp参数，确保KeyPeriod结构体是有效的。检查KeyPeriod中的KeyID和key中KeyID相等。
// 使用userkey验证KeyPeriod中的用户签名。
// 设置Key根据输入的period中的stTime和endTime成员，设置Key中的stTime和endTime成员，重新计算Key的Mac值。

// 4.	生成密钥种子S1
int GenerateS1(KEY_REC *key, USER_PUB_KEY *userkey, LICENSE *lic, S1_CIPHER *S1_E_Kc, S1_CIPHER *S1_E_Ku, LICENSE *lic_New);

// 功能：生成S1
// 说明：验证Key和userkey的Mac值，验证key和userkey中的成员ownerID的值相等，验证key中的OwnerKeyID成员的值等于userkey结构体的hash值（SHA256），随机生成S1，并使用输入的key和userkey分别对S1加密后返回，注：使用key对S1加密，必须先使用加密卡内预设的AES密钥对key中的成员Key_C_enc解密，得到密钥值，然后使用key结构体中的flag中指定的算法对S1加密

// 5.	签发许可
int issueLicense(KEY_REC *key, USER_PUB_KEY *userkey, uint8 *licID, LICENSE *fartherLic, LIC_REQ *licReq, LICENSE *lic);

// 功能：签发许可
// 说明：验证Key和userkey的Mac值，
// 如果fartherLic为0，验证key和userkey中的成员ownerID的值相等，验证key中的OwnerKeyID成员的值等于userkey结构体的hash值（SHA256），
// 如果fartherLic不为0，验证fartherLic的Mac值，验证fartherLic的成员UserID和userkey中的成员ownerID的值相等，验证fartherLic中的UserKeyID成员的值等于userkey结构体的hash值（SHA256），
// 验证使用userkey验证LicReq中的用户签名。
// 如果fartherLic为0，根据输入的licreq构建一个license，并计算License结构的Mac值返回新构建的license结构体。
// 如果fartherLic不为0，检查fartherLic中的policy字段，看是否支持继承，如果不支持继承，则报错，如果支持继承，则检查licreq中的条款是否超出fartherLic中的条款限制，如果超出报错，构建license，并计算Mac返回新构建的license结构体


// 6.	转换密文
int convertCipher(KEY_REC *key, USER_PUB_KEY *userkey, LICENSE *lic, S1_CIPHER *S1_E_Kc, S1_CIPHER *S1_E_Ku, LICENSE *Lic_new);
// 功能：转换密文，把被key加密的S1，转换成被userkey加密的S1
// 说明：验证Key和userkey的Mac值，
// 如果Lic为0，验证key和userkey中的成员ownerID的值相等，验证key中的OwnerKeyID成员的值等于userkey结构体的hash值（SHA256），
// 如果Lic不为0，验证Lic的Mac值，验证Lic的成员UserID和userkey中的成员ownerID的值相等，验证Lic中的UserKeyID成员的值等于userkey结构体的hash值（SHA256）。检查lic->licLimited看许可是否有效，是否有解密权限，如果许可过期或者失效，报错。使用key解密输入的S1_E_Kc得到S1，然后使用userkey加密S1得到S1_E_Ku。查看Lic的条款，如果有次数限制需要减掉一次，如果是时间段授权并且第一次使用该授权，需要设置授权的失效时间，重新结算lic的Mac值，返回S1_E_Ku和新的许可结构体lic_new


#endif // _HEADER_CRYPTOCARD_H_
