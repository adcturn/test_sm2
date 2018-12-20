#include <stdio.h>
#include <string.h>
#include <time.h>
#include <Windows.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "libsenc.h"
#include "sm2.h"


/***********************************国密-密钥管理-**********************************/
/***********************************国密-密钥管理-**********************************/

#define RTC_TIME_PIN_CODE					"\x00\x11\x22\x33\x44\x55\x66\x77" //PIN码
#define RTC_TIME_PIN_CODE_LEN				8								   //PIN码长度
#define DEFAULT_SM2_SIGN_USER_ID			"1234567812345678"				   //默认SM2用户ID
#define DEFAULT_SM2_SIGN_USER_ID_LEN		16								   //默认SM2用户ID长度
#define cc_error printf

#define FLAG								0x00000001				//国密-密钥管理新增数据结构标志位，测试用不到
#define SM2_PUBKEY_LEN						64						//SM2公钥长度
#define SM2_PRIKEY_LEN						32						//SM2私钥长度

//证书路径
#define	ROOT_CERT_PATH						"./证书/root.cer"		//根证书
#define	ROOT_PRIKEY_PATH					"./证书/root.pri"		//根私钥
#define	CA_CERT_PATH						"./证书/ca.cer"			//中级CA证书
#define	CA_PRIKEY_PATH						"./证书/ca.pri"			//中级CA私钥
#define	FIRMAIL_CERT_PATH					"./证书/firmail.cer"		//Firmail服务器设备证书
#define	KEYBAG1_CERT_PATH					"./证书/keybag1.cer"		//keybag1服务器设备证书 对应Dog
#define	KEYBAG2_CERT_PATH					"./证书/keybag2.cer"		//keybag2服务器设备证书 对应Cat

SENCryptCardList gDevList;											//板卡列表
HANDLE dHandle;														//板卡句柄
EC_GROUP *group = NULL;												//SM2签名验签加密用到的变量
EC_KEY	*eckey = NULL;												//SM2签名验签加密用到的变量

//证书缓存及长度
uint8_t cacert[2048] = { 0 };
uint8_t firmailcert[2048] = { 0 };
uint8_t keybagDogcert[2048] = { 0 };
uint8_t keybagCatcert[2048] = { 0 };
uint32_t ca_certlen = 0;
uint32_t firmail_certlen = 0;
uint32_t keybagDog_certlen = 0;
uint32_t keybagCat_certlen = 0;

//测试数据			在userkey.c中定义
extern uint8_t pubkey_dog[65];					//keybag_dog SM2公钥
extern uint8_t prikey_dog[32];					//keybag_dog SM2私钥

extern uint8_t pubkey_cat[65];					//keybag_cat SM2公钥
extern uint8_t prikey_cat[32];					//keybag_cat SM2私钥

extern uint8_t pubkey_firmail[65];				//firmail SM2公钥
extern uint8_t prikey_firmail[32];				//firmail SM2私钥

extern uint8_t pubkey_jmj[65];					//加密机 SM2公钥
extern uint8_t prikey_jmj[32];					//加密机 SM2私钥

extern uint8_t pubkey_AccessCode[65];			//AccessCode SM2公钥  填充作用
extern uint8_t prikey_AccessCode[32];			//AccessCode SM2私钥  填充作用

uint8_t KEY_BAG_ID_NULL[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
uint8_t KEY_BAG_ID_DOG[8] = { 0, 0, 0, 0, 0, 0, 0, 1 };
uint8_t KEY_BAG_ID_CAT[8] = { 0, 0, 0, 0, 0, 0, 0, 2 };

uint8_t KEY_CHAIN_ID_NULL[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
uint8_t KEY_CHAIN_ID_DOG[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
uint8_t KEY_CHAIN_ID_CAT[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

uint8_t PHONE_NUMBER_NULL[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
uint8_t PHONE_NUMBER_DOG[16] = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
uint8_t PHONE_NUMBER_CAT[16] = { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

uint8_t BIND_CODE_NULL[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
uint8_t BIND_CODE_DOG[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
uint8_t BIND_CODE_CAT[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

uint8_t CIRCLE_ID_NULL[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
uint8_t CIRCLE_ID_DOG[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
uint8_t CIRCLE_ID_CAT[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };


void bn2hex(uint8_t *bin, uint32_t len, char *hex)
{
	uint32_t i;

	for (i = 0; i < len; i++)
	{
		sprintf(hex, "%02X", bin[i]);
		hex += 2;
	}

}

//sm2签名编解码使用
const UINT8 TAG_CLASS_CONTEXT = 0xA0;
const UINT8 TAG_INTEGER = 0x02;
const UINT8 TAG_BIT_STRING = 0x03;
const UINT8 TAG_OCTET_STRING = 0x04;
const UINT8 TAG_OID = 0x06;
const UINT8 TAG_SEQUENCE = 0x30;

//*函数：eccDerEncodeSignature
//*功能：sm2签名Der编码
//*参数：无
//*日期：2018/12/14  by ZhangTao
UINT16 eccDerEncodeSignature(UINT8 *pu8Sig, UINT16 u16SigLen, UINT8 *pu8DerSig, UINT16 *pu16DerSigLen)
{
	UINT16 u16Index;
	UINT16 u16DerSigLen;
	UINT16 u16RLen, u16SLen;
	UINT16 i;

	u16RLen = u16SLen = u16SigLen / 2;

	if (pu8Sig[0] & 0x80)
		u16RLen++;

	i = 0;
	while ((pu8Sig[i++] == 0) && !(pu8Sig[i] & 0x80))
		u16RLen--;

	if (pu8Sig[u16SigLen / 2] & 0x80)
		u16SLen++;

	i = u16SigLen / 2;
	while ((pu8Sig[i++] == 0) && !(pu8Sig[i] & 0x80))
		u16SLen--;

	u16DerSigLen = u16RLen + u16SLen + 6;

	if (*pu16DerSigLen < u16DerSigLen)
	{
		*pu16DerSigLen = u16DerSigLen;
		return 1;
	}

	*pu16DerSigLen = u16DerSigLen;

	// sequence
	pu8DerSig[0] = TAG_SEQUENCE;
	pu8DerSig[1] = u16DerSigLen - 2;

	// integer r
	pu8DerSig[2] = TAG_INTEGER;
	pu8DerSig[3] = (UINT8)u16RLen;

	u16Index = 4;

	if (pu8Sig[0] & 0x80)
	{
		pu8DerSig[4] = 0;
		u16Index++;
	}

	memcpy(pu8DerSig + u16Index,
		pu8Sig + (u16SigLen / 2 > u16RLen ? u16SigLen / 2 - u16RLen : 0),
		u16SigLen / 2 < u16RLen ? u16SigLen / 2 : u16RLen);

	u16Index += u16SigLen / 2 < u16RLen ? u16SigLen / 2 : u16RLen;

	// integer s
	pu8DerSig[u16Index] = TAG_INTEGER;
	pu8DerSig[u16Index + 1] = (UINT8)u16SLen;

	if (pu8Sig[u16SigLen / 2] & 0x80)
	{
		pu8DerSig[u16Index + 2] = 0;
		u16Index++;
	}

	u16Index += 2;

	memcpy(pu8DerSig + u16Index,
		pu8Sig + u16SigLen / 2 + (u16SigLen / 2 > u16SLen ? u16SigLen / 2 - u16SLen : 0),
		u16SigLen / 2 < u16SLen ? u16SigLen / 2 : u16SLen);

	return 0;
}

//*函数：eccDerDecodeSignature
//*功能：sm2签名Der解码
//*参数：无
//*日期：2018/12/13  by ZhangTao
UINT16 eccDerDecodeSignature(UINT8 *pu8DerSig, UINT16 u16DerSigLen, UINT8 *pu8Sig, UINT16 u16SigLen)
{
	UINT16 u16Index = 0;
	UINT16 u16Slen = 0;

	// check outer sequence
	if (pu8DerSig[0] != TAG_SEQUENCE)
		return 1;

	if ((pu8DerSig[1] != u16DerSigLen - 2)
		|| (pu8DerSig[1] != 4 + pu8DerSig[3] + pu8DerSig[4 + pu8DerSig[3] + 1]))
		return 1;

	// check integer r
	if (pu8DerSig[2] != TAG_INTEGER)
		return 1;

	if ((pu8DerSig[4] != 0) && (pu8DerSig[3] > u16SigLen / 2))
		return 1;

	u16Index = 4;

	if (pu8DerSig[3] == u16SigLen / 2 + 1)
		u16Index++;

	if (pu8DerSig[3] < u16SigLen / 2)
	{
		memset(pu8Sig, 0, u16SigLen / 2 - pu8DerSig[3]);
		memcpy(pu8Sig + u16SigLen / 2 - pu8DerSig[3], pu8DerSig + u16Index, pu8DerSig[3]);

		u16Index += pu8DerSig[3];
	}
	else
	{
		memcpy(pu8Sig, pu8DerSig + u16Index, u16SigLen / 2);

		u16Index += u16SigLen / 2;
	}

	// check integer s
	if (pu8DerSig[u16Index] != TAG_INTEGER)
		return 1;

	u16Slen = pu8DerSig[u16Index + 1];
	if ((pu8DerSig[u16Index + 2] != 0) && (u16Slen > u16SigLen / 2))
		return 1;

	if (u16Slen == u16SigLen / 2 + 1)
		u16Index++;

	u16Index += 2;

	if (u16Slen < u16SigLen / 2)
	{
		memset(pu8Sig + u16SigLen / 2, 0, u16SigLen / 2 - u16Slen);
		memcpy(pu8Sig + u16SigLen - u16Slen, pu8DerSig + u16Index, u16Slen);
	}
	else
	{
		memcpy(pu8Sig + u16SigLen / 2, pu8DerSig + u16Index, u16SigLen / 2);
	}

	return 0;
}

//*函数：sm2SignMsg
//*功能：sm2签名
//*参数：prikey		私钥
//		 prikeylen	私钥长度
//		 pubkey		公钥
//		 pubkeylen	公钥长度
//		 msg		消息明文
//		 msglen		消息明文长度
//		 sig		签名	 
//*日期：2018/12/13  by ZhangTao
int sm2SignMsg(
	uint8_t *prikey,
	uint32_t prikeylen,
	uint8_t *pubkey,
	uint32_t pubkeylen,
	void *msg,
	uint32_t msglen,
	uint8_t *sig)
{
	int ret;
	BIGNUM *bnPrikey = NULL;
	EC_POINT *ecPubkey = NULL;
	char vkey[65];
	char pkey[131];
	unsigned char digest[32];
	unsigned char dersig[256];
	unsigned int digestlen, dersiglen;

	bn2hex(prikey, prikeylen, vkey);
	bn2hex(pubkey, pubkeylen, pkey);

	BN_hex2bn(&bnPrikey, vkey);
	EC_KEY_set_private_key(eckey, bnPrikey);
	ecPubkey = EC_POINT_hex2point(group, pkey, ecPubkey, NULL);
	EC_KEY_set_public_key(eckey, ecPubkey);

	//公钥计算摘要
	digestlen = sizeof(digest);
	ret = SM2_digest(
		DEFAULT_SM2_SIGN_USER_ID,
		DEFAULT_SM2_SIGN_USER_ID_LEN,
		msg,
		msglen,
		digest,
		&digestlen,
		eckey);
	if (ret != 1)
	{
		cc_error("SM2_digest Failed:0x%08X,Line:%d\n", ret,__LINE__);
		return 1;
	}

	//私钥签名
	dersiglen = 256;
	ret = SM2_sign(1, digest, sizeof(digest), dersig, &dersiglen, eckey);
	if (ret != 1)
	{
		cc_error("SM2_sign Failed:0x%08X,Line:%d\n", ret,__LINE__);
		return 1;
	}

	ret = eccDerDecodeSignature(dersig, dersiglen, sig, 64);

	//ret = SM2_verify(1, digest, digestlen, dersig, dersiglen, eckey);
	//if (ret != 1)
	//{
	//	cc_error("SM2_verify Failed:0x%08X,Line:%d\n", ret, __LINE__);
	//	return 1;
	//}

	return 0;
}

//*函数：sm2Verify
//*功能：sm2验签
//*参数：pubkey		公钥
//		 pubkeylen	公钥长度
//		 msg		消息明文
//		 msglen		消息明文长度
//		 sig		签名	 
//*日期：2018/12/14  by ZhangTao
int sm2Verify(
	uint8_t *pubkey,
	uint32_t pubkeylen,
	void *msg,
	uint32_t msglen,
	uint8_t *sig)
{
	int ret;
	EC_POINT *ecPubkey = NULL;
	char pkey[131];
	unsigned char digest[32];
	unsigned char dersig[256];
	unsigned int digestlen, dersiglen;

	//公钥byte数组转hex字符串
	bn2hex(pubkey, pubkeylen, pkey);
	//公钥hex字符串转EC_POINT				group是全局变量EC_GROUP
	ecPubkey = EC_POINT_hex2point(group, pkey, ecPubkey, NULL);
	//通过EC_POINT设置EC_KEY的公钥          eckey是全局变量EC_KEY
	EC_KEY_set_public_key(eckey, ecPubkey);

	//计算明文摘要
	digestlen = sizeof(digest);
	ret = SM2_digest(
		DEFAULT_SM2_SIGN_USER_ID,
		DEFAULT_SM2_SIGN_USER_ID_LEN,
		msg,
		msglen,
		digest,
		&digestlen,
		eckey);
	if (ret != 1)
	{
		cc_error("SM2_digest Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//sm2签名der编码，验签接口用的是der编码后的签名
	dersiglen = sizeof(dersig);
	eccDerEncodeSignature(sig, 64, dersig, (UINT16*)&dersiglen);
	//验签，返回1成功，返回0失败,第一个参数为类型
	ret = SM2_verify(1, digest, digestlen, dersig, dersiglen, eckey);
	if (ret != 1)
	{
		cc_error("SM2_verify Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	return 0;
}

//*函数：sm2EncMsg
//*功能：sm加密
//*参数：pubkey		公钥
//		 pubkeylen	公钥长度
//		 msg		消息（明文）
//		 msglen		消息（明文）长度
//		 cipher		密文
//*日期：2018/12/13  by ZhangTao
int sm2EncMsg(
	uint8_t *pubkey,
	uint32_t pubkeylen,
	void *msg,
	uint32_t msglen,
	uint8_t *cipher)
{
	int ret;
	char pkey[131];
	EC_POINT *ecPubkey = NULL;
	uint32_t cipherlen;

	//公钥byte数组转hex字符串
	bn2hex(pubkey, pubkeylen, pkey);
	//公钥hex字符串转EC_POINT				group是全局变量EC_GROUP
	ecPubkey = EC_POINT_hex2point(group, pkey, ecPubkey, NULL);
	//通过EC_POINT设置EC_KEY的公钥          eckey是全局变量EC_KEY
	EC_KEY_set_public_key(eckey, ecPubkey); 

	//SM2加密
	ret = SM2_encrypt_with_recommended(cipher, &cipherlen, msg, msglen, eckey);
	if (ret != 1)
	{
		cc_error("SM2_encrypt_with_recommended Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	return 0;
}

//*函数：constructKeyChainReq
//*功能：构造创建keychain请求包
//*参数：req			keychain创建请求包
//		 KeyChainID	keychain ID
//		 ACpubkey	access code 公钥
//		 ACpubkeylen	access code 公钥长度
//		 prikey		firmail服务器私钥
//		 prikeylen	firmail服务器私钥长度
//		 pubkey		firmail服务器公钥
//		 pubkeylen	firmail服务器公钥长度
//*日期：2018/12/13  by ZhangTao
int constructKeyChainReq(
	KeychainCreateReq *req,
	uint8_t *KeyChainID,
	uint8_t *ACpubkey,
	uint32_t ACpubkeylen,
	uint8_t *prikey,
	uint32_t prikeylen,
	uint8_t *pubkey,
	uint32_t pubkeylen)
{
	req->Magic = MAGIC_DATA;
	req->Version = VERSION_CURRENT_VERSION;
	req->Flags = FLAG;//不是加密算法Flag,与加密机无关，随意赋值
	req->TimeStamp = (uint32_t)time(NULL);
	memcpy(req->ID, KeyChainID, KEYCHAIN_ID_LEN);
	memset(req->KeyBagID, 0, KEYBAG_ID_LEN);
	memcpy(req->AccessCodePubKey, ACpubkey, ACpubkeylen);

	return sm2SignMsg(prikey, prikeylen, pubkey, pubkeylen, req, sizeof(KeychainCreateReq)-256, req->Signature);
}

//*函数：constructBindCode
//*功能：构造绑定验证码数据包
//*参数：BindCode		绑定验证码数据包
//		 KeyBagID		keybag ID
//		 PhoneNumber	电话号码
//		 BindCode_Plain	绑定验证码明文
//		 jmjpubkey		机密机公钥
//		 jmjpubkeylen	机密机公钥长度
//		 kbprikey		keybag私钥
//		 kbprikeylen	keybag私钥长度
//		 kbpubkey		keybag公钥
//		 kbpubkeylen	keybag公钥长度
//*日期：2018/12/13  by ZhangTao
int constructBindCode(
	KeybagBindCode *BindCode,
	uint8_t *KeyBagID,
	uint8_t *PhoneNumber,
	uint8_t *BindCode_Plain,
	uint8_t *jmjpubkey,
	uint32_t jmjpubkeylen,
	uint8_t *kbprikey,
	uint32_t kbprikeylen,
	uint8_t *kbpubkey,
	uint32_t kbpubkeylen)
{
	BindCode->Magic = MAGIC_DATA;
	BindCode->Version = VERSION_CURRENT_VERSION;
	BindCode->Flags = FLAG;//不是加密算法Flag,与加密机无关，随意赋值
	BindCode->TimeStamp = (uint32_t)time(NULL);
	memcpy(BindCode->KeyBagID, KeyBagID, BINDCODE_PLAIN_LEN);
	memcpy(BindCode->PhoneNumber, PhoneNumber, PHONE_NUMBER_LEN);

	if (sm2EncMsg(jmjpubkey, jmjpubkeylen, BindCode_Plain, BINDCODE_PLAIN_LEN, BindCode->BindCode))
		return 1;
	if (sm2SignMsg(kbprikey, kbprikeylen, kbpubkey, kbpubkeylen, BindCode, sizeof(KeybagBindCode)-256, BindCode->Signature))
		return 1;

	return 0;
}

//*函数：constructCircleReq
//*功能：构造Circle请求包
//*参数：req				Circle请求包
//		 KeyBagID		keybag ID
//		 PhoneNumber	电话号码
//		 BindCode_Plain	绑定验证码明文
//		 jmjpubkey		机密机公钥
//		 jmjpubkeylen	机密机公钥长度
//		 tbprikey		同步私钥	（keybag)
//		 tbprikeylen	同步私钥长度（keybag)
//		 tbpubkey		同步公钥	（keybag)
//		 tbpubkeylen	同步公钥长度（keybag)
//*日期：2018/12/13  by ZhangTao
int constructCircleReq(
	KeybagCreateCircleReq* req,
	uint8_t *KeyBagID,
	uint8_t *PhoneNumber,
	uint8_t *BindCode_Plain,
	uint8_t *jmjpubkey,
	uint32_t jmjpubkeylen,
	uint8_t *tbprikey,
	uint32_t tbprikeylen,
	uint8_t *tbpubkey,
	uint32_t tbpubkeylen)
{
	req->Magic = MAGIC_DATA;
	req->Version = VERSION_CURRENT_VERSION;
	req->Flags = FLAG;//不是加密算法Flag,与加密机无关，随意赋值
	req->TimeStamp = (uint32_t)time(NULL);
	memcpy(req->KeyBagID, KeyBagID, KEYBAG_ID_LEN);
	memcpy(req->PhoneNumber, PhoneNumber, PHONE_NUMBER_LEN);
	memcpy(req->SyncPubKey, tbpubkey+1, SM2_PUBKEY_LEN);
	if (sm2EncMsg(jmjpubkey, jmjpubkeylen, BindCode_Plain, BINDCODE_PLAIN_LEN, req->BindCode))
		return 1;
	if (sm2SignMsg(tbprikey, tbprikeylen, tbpubkey, tbpubkeylen, req, 
		sizeof(KeybagCreateCircleReq)-sizeof(req->Signature), req->Signature))
		return 1;

	return 0;
}

//*函数：constructCircleReq
//*功能：构造Circle请求包
//*参数：JCApprove		加入Circle审批包
//		 KeyBagID		keybag ID
//		 PhoneNumber	电话号码
//		 uuid			全球唯一标识符
//		 BindCode_Plain	绑定验证码明文
//		 KeyBagIDApprover	审批者keybag ID
//		 newpubkey		新同步公钥（加入的keybag）
//		 newpubkeylen	新同步公钥长度（加入的keybag）
//		 jmjpubkey		机密机公钥
//		 jmjpubkeylen	机密机公钥长度
//		 Approverprikey		审批者keybag私钥	（keybag)
//		 Approverprikeylen	审批者keybag私钥长度（keybag)
//		 Approverpubkey		审批者keybag公钥	（keybag)
//		 Approverpubkeylen	审批者keybag公钥长度（keybag)
//*日期：2018/12/13  by ZhangTao
int constructJoinCircle(
	KeybagJoinCircleApprove *JCApprove,
	uint8_t *KeyBagID,
	uint8_t *PhoneNumber,
	uint8_t *uuid,
	uint8_t *BindCode_Plain,
	uint8_t *KeyBagIDApprover,
	uint8_t *newpubkey,
	uint32_t newpubkeylen,
	uint8_t *jmjpubkey,
	uint32_t jmjpubkeylen,
	uint8_t *Approverprikey,
	uint32_t Approverprikeylen,
	uint8_t *Approverpubkey,
	uint32_t Approverpubkeylen)
{
	JCApprove->Magic = MAGIC_DATA;
	JCApprove->Version = VERSION_CURRENT_VERSION;
	JCApprove->Flags = FLAG;//不是加密算法Flag,与加密机无关，随意赋值
	JCApprove->TimeStamp = (uint32_t)time(NULL);
	memcpy(JCApprove->KeyBagID, KeyBagID, KEYBAG_ID_LEN);
	memcpy(JCApprove->PhoneNumber, PhoneNumber, PHONE_NUMBER_LEN);
	memcpy(JCApprove->Uuid, uuid, UUID_LEN);
	memcpy(JCApprove->SyncPubKey, newpubkey, newpubkeylen);
	memcpy(JCApprove->KeyBagIDApprover, KeyBagIDApprover, KEYBAG_ID_LEN);

	if (sm2EncMsg(jmjpubkey, jmjpubkeylen, BindCode_Plain, BINDCODE_PLAIN_LEN, JCApprove->BindCode))
		return 1;
	if (sm2SignMsg(Approverprikey, Approverprikeylen, Approverpubkey, Approverpubkeylen, JCApprove, 
		sizeof(KeybagJoinCircleApprove)-sizeof(JCApprove->Signature), JCApprove->Signature))
		return 1;

	return 0;
}


//*函数：readcert
//*功能：读取CA证书，Firmail服务器设备证书
//		 keybag1证书,keybag2证书
//*参数：无
//*日期：2018/12/13  by ZhangTao
int readcert()
{
	FILE *fp = NULL;
	//读取CA证书
	fp = fopen(CA_CERT_PATH, "rb");
	if (!fp){
		printf("打开CA证书失败，Line:%d\n", __LINE__);
		return 1;
	}
	ca_certlen = fread(cacert, sizeof(uint8_t), sizeof(cacert), fp);
	if (!ca_certlen){
		printf("读取CA证书失败，Line:%d\n", __LINE__);
		return 1;
	}
	fclose(fp);
	//读取FIRMAIL证书
	fp = fopen(FIRMAIL_CERT_PATH, "rb");
	if (!fp){
		printf("打开FIRMAIL证书失败，Line:%d\n", __LINE__);
		return 1;
	}
	firmail_certlen = fread(firmailcert, sizeof(uint8_t), sizeof(firmailcert), fp);
	if (!firmail_certlen){
		printf("读取FIRMAIL证书失败，Line:%d\n", __LINE__);
		return 1;
	}
	fclose(fp);
	//读取keybag1证书
	fp = fopen(KEYBAG1_CERT_PATH, "rb");
	if (!fp){
		printf("打开KEYBAG1证书失败，Line:%d\n", __LINE__);
		return 1;
	}
	keybagDog_certlen = fread(keybagDogcert, sizeof(uint8_t), sizeof(keybagDogcert), fp);
	if (!keybagDog_certlen){
		printf("读取KEYBAG1证书失败，Line:%d\n", __LINE__);
		return 1;
	}
	fclose(fp);
	//读取keybag1证书
	fp = fopen(KEYBAG2_CERT_PATH, "rb");
	if (!fp){
		printf("打开KEYBAG2证书失败，Line:%d\n", __LINE__);
		return 1;
	}
	keybagCat_certlen = fread(keybagCatcert, sizeof(uint8_t), sizeof(keybagCatcert), fp);
	if (!keybagCat_certlen){
		printf("读取KEYBAG2证书失败，Line:%d\n", __LINE__);
		return 1;
	}
	fclose(fp);
	
	return 0;
}

//*函数：test_init
//*功能：测试初始化函数
//*参数：无
//*日期：2018/12/18  by ZhangTao
int test_init()
{
	int flag;

	group = SM2_Init();
	if (group == NULL)
	{
		printf("SM2_Init Failed!\n");
		goto end;
	}

	eckey = EC_KEY_new();
	if (eckey == NULL)
	{
		printf("EC_KEY_new Failed!\n");
		goto end;
	}

	if (EC_KEY_set_group(eckey, group) == 0)
	{
		printf("EC_KEY_set_group Failed!\n");
		goto end;
	}

	//获取设备列表
	SENC_NewDevList(&gDevList);
	flag = SENC_GetDevList(&gDevList);
	if (gDevList.DevNums == 0){
		printf("未发现加密板卡，Line:%d\n", __LINE__);
		SENC_FreeDevList(&gDevList);
		goto end;
	}

	//打开设备
	flag = SENC_Open(gDevList.devs[0], &dHandle);
	if (flag != SENC_SUCCESS){
		printf("开启加密板卡失败，错误码为：0x%.8x，Line:%d\n", flag, __LINE__);
		SENC_FreeDevList(&gDevList);
		goto end;
	}

	//设置时间
	uint64_t rtcTime = time(NULL);
	flag = SENC_DataProtector_SetRTCTime(dHandle, (uint8_t*)RTC_TIME_PIN_CODE, RTC_TIME_PIN_CODE_LEN, &rtcTime);
	if (flag != SENC_SUCCESS){
		printf("设置RTC时间失败，错误码为：0x%.8x，Line:%d\n", flag, __LINE__);
		SENC_FreeDevList(&gDevList);
		goto end;
	}

	//获取时间
	rtcTime = time(NULL);
	uint64_t rtcTime2 = 0;
	flag = SENC_DataProtector_GetRTCTime(dHandle, &rtcTime2);
	if (flag != SENC_SUCCESS){
		printf("获取RTC时间失败，错误码为：0x%.8x，Line:%d\n", flag, __LINE__);
		SENC_FreeDevList(&gDevList);
		goto end;
	}

	//读取证书
	if (readcert()){
		printf("读取证书失败！\n");
		goto end;
	}
	printf("读取证书成功！\n");

	return 0;

end:
	return 1;
}

//*函数：test_keymanage_all
//*功能：密钥管理新增业务接口整体流程测试
//*参数：无
//*日期：2018/12/17  by ZhangTao
int test_keymanage_all()
{
	int ret;
	KeychainCreateReq KCCreateReq_Dog;
	KeychainCreateCode KCCreateCode_Dog;
	KeybagBindCode  KBBindCode_Dog, KBBindCode_Cat;
	uint8_t bindcode_plain_Dog[BINDCODE_PLAIN_LEN], bindcode_plain_Cat[BINDCODE_PLAIN_LEN];
	uint8_t phonenum_Dog[PHONE_NUMBER_LEN], phonenum_Cat[PHONE_NUMBER_LEN];
	uint8_t bindcodeVeriCipher_Dog[256], bindcodeVeriCipher_Cat[256];
	KeybagCreateCircleReq KBCreateCirReq_Dog;
	KeybagCircle KBCircle_Dog, KBCircle_Cat, KBCircleCommon;
	KeybagJoinCircleApprove KBJoinCir_DogApproveCat;
	uint32_t len1;
	uint32_t Dogverilen, Catverilen;
	uint32_t DogCirclelen;
	uint32_t timestamp1, timestamp2;

	KBCircle_Dog.kcPubKey = malloc(sizeof(KeybagCirclePubkey)* 3);
	KBCircle_Cat.kcPubKey = malloc(sizeof(KeybagCirclePubkey)* 3);
	KBCircleCommon.kcPubKey = malloc(sizeof(KeybagCirclePubkey)* 3);

	//1 创建KeyChain
	//构造KeyChain创建请求
	constructKeyChainReq(&KCCreateReq_Dog, KEY_CHAIN_ID_DOG, pubkey_AccessCode + 1, SM2_PUBKEY_LEN, prikey_firmail, 
						  SM2_PRIKEY_LEN, pubkey_firmail, SM2_PUBKEY_LEN + 1);
	//创建KeyChain
	ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReq_Dog, sizeof(KCCreateReq_Dog), cacert, ca_certlen, firmailcert, 
										 firmail_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
	if (ret != SENC_SUCCESS){//预期KeyChain创建成功
		cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//验签KeyChainCreateCode
	ret = sm2Verify(pubkey_jmj, SM2_PUBKEY_LEN + 1, &KCCreateCode_Dog, 
		sizeof(KCCreateCode_Dog)-sizeof(KCCreateCode_Dog.Signature), KCCreateCode_Dog.Signature);
	if (ret){
		cc_error("KeyChainCreateCode SM2_Verify Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	
	//2 创建Circle
	//构造绑定验证码    Dog创建Circle的绑定验证码
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1, 
						prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert, 
								   keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//预期签发绑定验证码成功
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//检查绑定验证码中的电话号码与返回的电话号码是否一致
	if (memcmp(PHONE_NUMBER_DOG, phonenum_Dog, PHONE_NUMBER_LEN)){
		cc_error("PhoneNumber Error,Line:%d\n",__LINE__);
		return 1;
	}
	//检查绑定验证码中的绑定验证码明文与返回的绑定验证码明文是否一致
	if (memcmp(BIND_CODE_DOG, bindcode_plain_Dog, BINDCODE_PLAIN_LEN)){
		cc_error("BindCodePlain Error,Line:%d\n", __LINE__);
		return 1;
	}

	//构造创建Circle请求包
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
						pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog), bindcodeVeriCipher_Dog, 
									   Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//预期创建Circle成功
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//验签Circle
	uint8_t msg[256] = { 0 };
	uint32_t msglen = 0;
	memcpy(msg, &KBCircle_Dog, 52);
	msglen += 52;
	memcpy(msg + msglen, KBCircle_Dog.kcPubKey, sizeof(KeybagCirclePubkey));
	msglen += sizeof(KeybagCirclePubkey);
	ret = sm2Verify(pubkey_jmj, SM2_PUBKEY_LEN + 1, msg, msglen, KBCircle_Dog.Signature);
	if (ret){
		cc_error("KeyChainCreateCode SM2_Verify Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//检查Circle请求包中的电话号码与Circle包中的电话号码是否一致
	if (memcmp(PHONE_NUMBER_DOG, KBCircle_Dog.PhoneNumber, PHONE_NUMBER_LEN)){
		cc_error("PhoneNumber Error,Line:%d\n", __LINE__);
		return 1;
	}
	//检查Circle包的KeyBag公钥数组中是否只有一个KeyBag的公钥信息
	if (KBCircle_Dog.Count != 1){
		cc_error("KeyBag PubKey Count Error,Line:%d\n", __LINE__);
		return 1;
	}
	//判断Circle包的公钥数组中仅有的一个公钥信息中的KeyBagID是否与KeyBagDog的ID相等
	if (memcmp(KEY_BAG_ID_DOG, KBCircle_Dog.kcPubKey[0].KeyBagID, KEYBAG_ID_LEN)){
		cc_error("KeyBag ID Error,Line:%d\n", __LINE__);
		return 1;
	}
	//判断公钥数组中仅有的一个公钥信息中的同步公钥是否与KeyBagDog的同步公钥相等
	if (memcmp(pubkey_dog + 1, KBCircle_Dog.kcPubKey[0].SyncPubKey, SM2_PUBKEY_LEN)){
		cc_error("SyncPubKey Error,Line:%d\n", __LINE__);
		return 1;
	}
	//判断公钥数据中仅有的一个公钥信息中的Seq是否为1
	if (KBCircle_Dog.kcPubKey[0].KeyBagSeq != 1){
		cc_error("KeyBagSeq Error,Line:%d\n", __LINE__);
		return 1;
	}

	//加入Circle
	//构造绑定验证码    Cat加入Dog的Circle的绑定验证码
	constructBindCode(&KBBindCode_Cat, KEY_BAG_ID_CAT, PHONE_NUMBER_CAT, BIND_CODE_CAT, pubkey_jmj, SM2_PUBKEY_LEN + 1, 
						prikey_cat, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Cat, sizeof(KBBindCode_Cat), cacert, ca_certlen, keybagCatcert, 
								   keybagCat_certlen, bindcode_plain_Cat, phonenum_Cat, bindcodeVeriCipher_Cat, &Catverilen);
	if (ret != SENC_SUCCESS){//预期签发绑定验证码成功
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//构造加入Circle审批包
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat, 
	KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1,prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//加入Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat), 
									 bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//预期加入Circle成功
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//检查加入Circle请求包中的电话号码与新的Circle包中的电话号码是否一致
	if (memcmp(PHONE_NUMBER_DOG, KBCircle_Dog.PhoneNumber, PHONE_NUMBER_LEN)){
		cc_error("PhoneNumber Error,Line:%d\n", __LINE__);
		return 1;
	}
	//检查新的Circle包的KeyBag公钥数组中是否有2个KeyBag的公钥信息
	if (KBCircle_Dog.Count != 2){
		cc_error("KeyBag PubKey Count Error,Line:%d\n", __LINE__);
		return 1;
	}
	//判断新的Circle包的公钥数组第一个公钥信息中的KeyBagID是否与KeyBagDog的ID相等
	if (memcmp(KEY_BAG_ID_DOG, KBCircle_Dog.kcPubKey[0].KeyBagID, KEYBAG_ID_LEN)){
		cc_error("KeyBag ID Error,Line:%d\n", __LINE__);
		return 1;
	}
	//判断新的Circle包的公钥数组第一个公钥信息中的同步公钥是否与KeyBagDog的同步公钥相等
	if (memcmp(pubkey_dog + 1, KBCircle_Dog.kcPubKey[0].SyncPubKey, SM2_PUBKEY_LEN)){
		cc_error("SyncPubKey Error,Line:%d\n", __LINE__);
		return 1;
	}
	//判断新的Circle包的公钥数组第一个公钥信息中的Seq是否为1
	if (KBCircle_Dog.kcPubKey[0].KeyBagSeq != 1){
		cc_error("KeyBagSeq Error,Line:%d\n", __LINE__);
		return 1;
	}
	//判断新的Circle包的公钥数组第一个公钥信息中的KeyBagID是否与KeyBagDog的ID相等
	if (memcmp(KEY_BAG_ID_CAT, KBCircle_Dog.kcPubKey[1].KeyBagID, KEYBAG_ID_LEN)){
		cc_error("KeyBag ID Error,Line:%d\n", __LINE__);
		return 1;
	}
	//判断新的Circle包的公钥数组第一个公钥信息中的同步公钥是否与KeyBagDog的同步公钥相等
	if (memcmp(pubkey_cat + 1, KBCircle_Dog.kcPubKey[1].SyncPubKey, SM2_PUBKEY_LEN)){
		cc_error("SyncPubKey Error,Line:%d\n", __LINE__);
		return 1;
	}
	//判断新的Circle包的公钥数组第一个公钥信息中的Seq是否为1
	if (KBCircle_Dog.kcPubKey[1].KeyBagSeq != 2){
		cc_error("KeyBagSeq Error,Line:%d\n", __LINE__);
		return 1;
	}

	free(KBCircle_Dog.kcPubKey);
	free(KBCircle_Cat.kcPubKey);
	free(KBCircleCommon.kcPubKey);
	return 0;
}

//*函数：test_keymanage_positive
//*功能：密钥管理新增业务接口积极测试
//*参数：无
//*日期：2018/12/14  by ZhangTao
int test_keymanage_positive()
{
	int ret;
	KeychainCreateReq KCCreateReq_Dog;
	KeychainCreateCode KCCreateCode_Dog;
	KeybagBindCode  KBBindCode_Dog, KBBindCode_Cat;
	uint8_t bindcode_plain_Dog[BINDCODE_PLAIN_LEN], bindcode_plain_Cat[BINDCODE_PLAIN_LEN];
	uint8_t phonenum_Dog[PHONE_NUMBER_LEN], phonenum_Cat[PHONE_NUMBER_LEN];
	uint8_t bindcodeVeriCipher_Dog[256], bindcodeVeriCipher_Cat[256];
	KeybagCreateCircleReq KBCreateCirReq_Dog;
	KeybagCircle KBCircle_Dog, KBCircle_Cat, KBCircleCommon;
	KeybagJoinCircleApprove KBJoinCir_DogApproveCat;
	uint32_t len1;
	uint32_t Dogverilen, Catverilen;
	uint32_t DogCirclelen;
	uint32_t timestamp1, timestamp2;

	KBCircle_Dog.kcPubKey = malloc(sizeof(KeybagCirclePubkey)* 3);
	KBCircle_Cat.kcPubKey = malloc(sizeof(KeybagCirclePubkey)* 3);
	KBCircleCommon.kcPubKey = malloc(sizeof(KeybagCirclePubkey)* 3);

	////////////////////////////////////////////////////////////////////////
	////// 测试 创建KeyChain
	////////////////////////////////////////////////////////////////////////
#pragma region
	//1 正确的KeyChain创建请求
	//构造KeyChain创建请求
	constructKeyChainReq(&KCCreateReq_Dog, KEY_CHAIN_ID_DOG, pubkey_AccessCode + 1, SM2_PUBKEY_LEN, prikey_firmail,
		SM2_PRIKEY_LEN, pubkey_firmail, SM2_PUBKEY_LEN + 1);
	//创建KeyChain
	int lentemp = sizeof(KCCreateReq_Dog);
	ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReq_Dog, sizeof(KCCreateReq_Dog), cacert, ca_certlen,
		firmailcert, firmail_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
	if (ret != SENC_SUCCESS){//预期KeyChain创建成功
		cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//2 使用错误的firmail服务器私钥签名KeyChain创建请求包
	//构造KeyChain创建请求
	constructKeyChainReq(&KCCreateReq_Dog, KEY_CHAIN_ID_DOG, pubkey_AccessCode + 1, SM2_PUBKEY_LEN, prikey_jmj,
		SM2_PRIKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1);
	//创建KeyChain
	ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReq_Dog, sizeof(KCCreateReq_Dog), cacert, ca_certlen,
		firmailcert, firmail_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
	if (ret == SENC_SUCCESS){//预期KeyChain创建失败
		cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//3 错误的firmail服务器证书
	//构造KeyChain创建请求
	constructKeyChainReq(&KCCreateReq_Dog, KEY_CHAIN_ID_DOG, pubkey_AccessCode + 1, SM2_PUBKEY_LEN, prikey_firmail,
		SM2_PRIKEY_LEN, pubkey_firmail, SM2_PUBKEY_LEN + 1);
	//创建KeyChain
	ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReq_Dog, sizeof(KCCreateReq_Dog), cacert, ca_certlen,
		keybagDogcert, keybagDog_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
	if (ret == SENC_SUCCESS){//预期KeyChain创建失败
		cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
#pragma endregion

	////////////////////////////////////////////////////////////////////////
	////// 测试 签发绑定验证码
	////////////////////////////////////////////////////////////////////////
#pragma region
	//4 正确地签发BindCode
	//构造绑定验证码
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//预期签发绑定验证码成功
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//5 使用错误的电话号码签发KeyBind
	//构造绑定验证码                                   错误的电话号码
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_CAT, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//预期签发绑定验证码成功
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//6 使用错误的加密板卡证书加密BindCode明文
	//构造绑定验证码																	错误的加密板卡证书
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_firmail, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret == SENC_SUCCESS){//预期签发绑定验证码失败
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//7 使用错误的keybag私钥签名
	//构造绑定验证码
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_cat, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);//错误的keybag私钥
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret == SENC_SUCCESS){//预期签发绑定验证码失败
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//8 使用错误的keybag证书
	//构造绑定验证码
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码																					错误的keybag证书
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagCatcert,
		keybagCat_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret == SENC_SUCCESS){//预期签发绑定验证码失败
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
#pragma endregion

	////////////////////////////////////////////////////////////////////////
	////// 测试 创建Circle
	////////////////////////////////////////////////////////////////////////
#pragma region
	//9 正确地创建Circle
	//构造绑定验证码
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//预期签发绑定验证码成功
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//构造创建Circle请求包
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//预期创建Circle成功
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//10 使用错误的验证码
	//构造创建Circle请求包													  错误的绑定验证码
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_CAT,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期创建Circle失败
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//11 使用错误的keybag公钥
	//构造创建Circle请求包													  
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);//错误的keybag公钥
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期创建Circle失败
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//12 使用错误的keybag私钥签名
	//构造创建Circle请求包													  
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_cat, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);//错误的keybag私钥
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期创建Circle失败
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//13 使用错误的电话号码
	//构造创建Circle请求包									错误的电话号码
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_CAT, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//预期创建Circle成功
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//14 使用错误的keybagID
	//构造创建Circle请求包					错误的keybagID
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_CAT, PHONE_NUMBER_CAT, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//预期创建Circle成功
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
#pragma endregion

	////////////////////////////////////////////////////////////////////////
	////// 测试 加入Circle
	////////////////////////////////////////////////////////////////////////
#pragma region
	//15 正确地加入Circle    Cat加入Dog的Circle
	//构造绑定验证码    Dog创建Circle的绑定验证码
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//预期签发绑定验证码成功
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//构造创建Circle请求包
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog), bindcodeVeriCipher_Dog,
		Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//预期创建Circle成功
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//构造绑定验证码    Cat加入Dog的Circle的绑定验证码
	constructBindCode(&KBBindCode_Cat, KEY_BAG_ID_CAT, PHONE_NUMBER_CAT, BIND_CODE_CAT, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_cat, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Cat, sizeof(KBBindCode_Cat), cacert, ca_certlen, keybagCatcert,
		keybagCat_certlen, bindcode_plain_Cat, phonenum_Cat, bindcodeVeriCipher_Cat, &Catverilen);
	if (ret != SENC_SUCCESS){//预期签发绑定验证码成功
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//构造加入Circle审批包
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//加入Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//预期加入Circle成功
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//16 使用错误的验证码
	//构造加入Circle审批包																			   错误的绑定验证码
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, BIND_CODE_NULL,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//加入Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期加入Circle失败
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//17 Cat伪造Dog的电话号码
	//构造加入Circle审批包										  错误的电话号码
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_CAT, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//加入Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期加入Circle失败
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//18 Cat伪造Dog的KeyBagID
	//构造加入Circle审批包										  
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_CAT, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1,//错误的KeyBagID
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//加入Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期加入Circle失败
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//19 Cat伪造Dog的私钥进行签名
	//构造加入Circle审批包										  
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_cat, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);//错误的私钥
	//加入Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期加入Circle失败
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//20 创建Circle预留KeyBagID错误对加入Circle的影响
	//构造创建Circle请求包
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_NULL, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog), bindcodeVeriCipher_Dog,
		Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//预期创建Circle成功
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//构造加入Circle审批包
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//加入Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期加入Circle失败
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//21 创建Circle预留电话错误对加入Circle的影响
	//构造创建Circle请求包
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_NULL, PHONE_NUMBER_NULL, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog), bindcodeVeriCipher_Dog,
		Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//预期创建Circle成功
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//构造加入Circle审批包
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//加入Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期加入Circle失败
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

#pragma endregion

	free(KBCircle_Dog.kcPubKey);
	free(KBCircle_Cat.kcPubKey);
	free(KBCircleCommon.kcPubKey);
	return 0;
}

//*函数：test_keymanage_negative
//*功能：密钥管理新增业务接口消极测试
//*参数：无
//*日期：2018/12/13  by ZhangTao
int test_keymanage_negative()
{
	int ret, i;
	KeychainCreateReq KCCreateReq_Dog, KCCreateReqCommon;
	KeychainCreateCode KCCreateCode_Dog;
	KeybagBindCode  KBBindCode_Dog, KBBindCode_Cat, KBBindCodeCommon;
	uint8_t bindcode_plain_Dog[BINDCODE_PLAIN_LEN], bindcode_plain_Cat[BINDCODE_PLAIN_LEN];
	uint8_t phonenum_Dog[PHONE_NUMBER_LEN], phonenum_Cat[PHONE_NUMBER_LEN];
	uint8_t bindcodeVeriCipher_Dog[256], bindcodeVeriCipher_Cat[256];
	KeybagCreateCircleReq KBCreateCirReq_Dog,KBCreateCirReqCommon;
	KeybagCircle KBCircle_Dog, KBCircle_Cat, KBCircleCommon;
	KeybagJoinCircleApprove KBJoinCir_DogApproveCat, KBJoinCirApproveCommon;
	uint32_t len1;
	uint32_t Dogverilen, Catverilen;
	uint32_t DogCirclelen;
	uint32_t timestamp1, timestamp2;

	KBCircle_Dog.kcPubKey = malloc(sizeof(KeybagCirclePubkey)* 3);
	KBCircle_Cat.kcPubKey = malloc(sizeof(KeybagCirclePubkey)* 3);
	KBCircleCommon.kcPubKey = malloc(sizeof(KeybagCirclePubkey)* 3);

#pragma region 测试创建KeyChain
	//A.测试创建KeyChain
	//1 bad version
	//构造KeyChain创建请求，使用错误的版本号
	KCCreateReq_Dog.Magic = MAGIC_DATA;
	KCCreateReq_Dog.Version = VERSION_CURRENT_VERSION + 1;//错误的版本号
	KCCreateReq_Dog.Flags = FLAG;//不是加密算法Flag,与加密机无关，随意赋值
	KCCreateReq_Dog.TimeStamp = (uint32_t)time(NULL);
	memcpy(KCCreateReq_Dog.ID, KEY_CHAIN_ID_DOG, KEYCHAIN_ID_LEN);
	memset(KCCreateReq_Dog.KeyBagID, 0, KEYBAG_ID_LEN);
	memcpy(KCCreateReq_Dog.AccessCodePubKey, pubkey_AccessCode + 1, SM2_PUBKEY_LEN);

	//firmail服务器私钥签名
	ret = sm2SignMsg(prikey_firmail, SM2_PRIKEY_LEN, pubkey_firmail, SM2_PUBKEY_LEN + 1, &KCCreateReq_Dog,
		sizeof(KeychainCreateReq)-256, KCCreateReq_Dog.Signature);
	if (ret != 0){
		cc_error("SM2签名失败，Line:%d\n", __LINE__);
		return 1;
	}
	//创建KeyChain
	ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReq_Dog, sizeof(KCCreateReq_Dog), cacert, ca_certlen,
		firmailcert, firmail_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
	if (ret == SENC_SUCCESS){//预期KeyChain创建失败
		cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//2 bad signature
	//构造KeyChain创建请求
	constructKeyChainReq(&KCCreateReq_Dog, KEY_CHAIN_ID_DOG, pubkey_AccessCode + 1, SM2_PUBKEY_LEN, prikey_firmail,
		SM2_PRIKEY_LEN, pubkey_firmail, SM2_PUBKEY_LEN + 1);
	//篡改签名
	memset(KCCreateReq_Dog.Signature, 0, sizeof(KCCreateReq_Dog.Signature));
	//创建KeyChain
	ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReq_Dog, sizeof(KCCreateReq_Dog), cacert, ca_certlen,
		firmailcert, firmail_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
	if (ret == SENC_SUCCESS){//预期KeyChain创建失败
		cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//3 bad keychain req packet
	//构造KeyChain创建请求
	constructKeyChainReq(&KCCreateReq_Dog, KEY_CHAIN_ID_DOG, pubkey_AccessCode + 1, SM2_PUBKEY_LEN, prikey_firmail,
		SM2_PRIKEY_LEN, pubkey_firmail, SM2_PUBKEY_LEN + 1);
	//篡改签名的请求包的任一字节
	for (i = 0; i < (sizeof(KCCreateReq_Dog)-sizeof(KCCreateReq_Dog.Signature) + 64); i++)
	{
		memcpy(&KCCreateReqCommon, &KCCreateReq_Dog, sizeof(KCCreateReq_Dog));
		((uint8_t *)&KCCreateReqCommon)[i] ++;

		//创建KeyChain
		ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReqCommon, sizeof(KCCreateReqCommon), cacert, ca_certlen,
			firmailcert, firmail_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
		if (ret == SENC_SUCCESS){//预期KeyChain创建失败
			cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
			return 1;
		}
	}
#pragma endregion

#pragma region 测试签发绑定验证码
	//B 测试签发绑定验证码
	//4 bad version
	//构造绑定验证码，使用错误的版本号
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	KBBindCode_Dog.Version = VERSION_CURRENT_VERSION + 1;
	//dog私钥重新签名
	ret = sm2SignMsg(prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1, &KBBindCode_Dog,
		sizeof(KBBindCode_Dog)-256, KBBindCode_Dog.Signature);
	if (ret != 0){
		cc_error("SM2签名失败，Line:%d\n", __LINE__);
		return 1;
	}
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret == SENC_SUCCESS){//预期签发绑定验证码失败
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//5 bad signature
	//构造绑定验证码
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//篡改签名
	memset(KBBindCode_Dog.Signature, 0, sizeof(KBBindCode_Dog.Signature));
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret == SENC_SUCCESS){//预期签发绑定验证码失败
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//6 bad bindcode packet
	//构造绑定验证码
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//篡改绑定验证码包的任一字节
	for (i = 0; i < (sizeof(KBBindCode_Dog)-sizeof(KBBindCode_Dog.Signature) + 64); i++)
	{
		memcpy(&KBBindCodeCommon, &KBBindCode_Dog, sizeof(KBBindCode_Dog));
		((uint8_t *)&KBBindCodeCommon)[i] ++;

		//签发绑定验证码
		ret = SENC_KeyManager_BindCode(dHandle, KBBindCodeCommon, sizeof(KBBindCodeCommon), cacert, ca_certlen, keybagDogcert,
			keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
		if (ret == SENC_SUCCESS){//预期签发绑定验证码失败
			cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
			return 1;
		}
	}
#pragma endregion 

#pragma region  测试创建Circle
	//C 测试创建Circle
	//7 bad version
	//构造绑定验证码
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//预期签发绑定验证码成功
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//构造创建Circle请求包   错误的版本号
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	KBCreateCirReq_Dog.Version = VERSION_CURRENT_VERSION + 1;

	//dog私钥重新签名
	ret = sm2SignMsg(prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1, &KBCreateCirReq_Dog,
		sizeof(KBCreateCirReq_Dog)-256, KBCreateCirReq_Dog.Signature);
	if (ret != 0){
		cc_error("SM2签名失败，Line:%d\n", __LINE__);
		return 1;
	}
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期创建Circle失败
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//8 bad bindcode
	//构造创建Circle请求包,错误的绑定验证码，							应该为bindcode_plain_Dog
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Cat,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期创建Circle失败
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//9 bad signature
	//构造创建Circle请求包,错误的签名
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	memset(KBCreateCirReq_Dog.Signature, 0, sizeof(KBCreateCirReq_Dog.Signature));
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期创建Circle失败
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//10 bad circle req packet
	//构造创建Circle请求包
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//篡改Circle请求包的任一字节
	for (i = 0; i < (sizeof(KBCreateCirReq_Dog)-sizeof(KBCreateCirReq_Dog.Signature) + 64); i++)
	{
		memcpy(&KBCreateCirReqCommon, &KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog));
		((uint8_t *)&KBCreateCirReqCommon)[i] ++;

		//创建Circle
		ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReqCommon, sizeof(KBCreateCirReqCommon),
			bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
		if (ret == SENC_SUCCESS){//预期创建Circle失败
			cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
			return 1;
		}
	}
#pragma endregion

#pragma region  测试加入Circle
	//D 测试加入Circle
	//11 bad version
	//构造绑定验证码    Dog创建Circle的绑定验证码
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//预期签发绑定验证码成功
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//构造创建Circle请求包
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog), bindcodeVeriCipher_Dog,
		Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//预期创建Circle成功
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//构造绑定验证码    Cat加入Dog的Circle的绑定验证码
	constructBindCode(&KBBindCode_Cat, KEY_BAG_ID_CAT, PHONE_NUMBER_CAT, BIND_CODE_CAT, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_cat, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Cat, sizeof(KBBindCode_Cat), cacert, ca_certlen, keybagCatcert,
		keybagCat_certlen, bindcode_plain_Cat, phonenum_Cat, bindcodeVeriCipher_Cat, &Catverilen);
	if (ret != SENC_SUCCESS){//预期签发绑定验证码成功
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//构造加入Circle审批包
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//错误的版本号 
	KBJoinCir_DogApproveCat.Version += 1;
	//KeyBagDog的私钥重新签名JoinCircle请求包
	ret = sm2SignMsg(prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1, &KBJoinCir_DogApproveCat,
		sizeof(KBJoinCir_DogApproveCat)-256, KBJoinCir_DogApproveCat.Signature);
	if (ret != 0){
		cc_error("SM2签名失败，Line:%d\n", __LINE__);
		return 1;
	}
	//加入Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期加入Circle失败
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//12 bad phonenumber
	//构造加入Circle审批包
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//错误的电话号码
	memcpy(KBJoinCir_DogApproveCat.PhoneNumber, PHONE_NUMBER_CAT, PHONE_NUMBER_LEN);
	//KeyBagDog的私钥重新签名JoinCircle请求包
	ret = sm2SignMsg(prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1, &KBJoinCir_DogApproveCat,
		sizeof(KBJoinCir_DogApproveCat)-256, KBJoinCir_DogApproveCat.Signature);
	if (ret != 0){
		cc_error("SM2签名失败，Line:%d\n", __LINE__);
		return 1;
	}
	//加入Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期加入Circle失败
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//13 bad Approver ID
	//构造加入Circle审批包
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//错误的审批者ID
	memcpy(KBJoinCir_DogApproveCat.KeyBagIDApprover, KEY_BAG_ID_CAT, KEYBAG_ID_LEN);
	//KeyBagDog的私钥重新签名JoinCircle请求包
	ret = sm2SignMsg(prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1, &KBJoinCir_DogApproveCat,
		sizeof(KBJoinCir_DogApproveCat)-256, KBJoinCir_DogApproveCat.Signature);
	if (ret != 0){
		cc_error("SM2签名失败，Line:%d\n", __LINE__);
		return 1;
	}
	//加入Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期加入Circle失败
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//14 bad signature
	//构造加入Circle审批包
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//错误的签名
	memset(KBJoinCir_DogApproveCat.Signature, 0, sizeof(KBJoinCir_DogApproveCat.Signature));
	//加入Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//预期加入Circle失败
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//15 bad join circle packet
	//构造加入Circle审批包
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//篡改Circle请求包的任一字节
	for (i = 0; i < (sizeof(KBJoinCir_DogApproveCat)-sizeof(KBJoinCir_DogApproveCat.Signature) + 64); i++)
	{
		memcpy(&KBJoinCirApproveCommon, &KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat));
		((uint8_t *)&KBJoinCirApproveCommon)[i] ++;

		//加入Circle
		ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCirApproveCommon, sizeof(KBJoinCirApproveCommon),
			bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
		if (ret == SENC_SUCCESS){//预期加入Circle失败
			cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
			return 1;
		}
	}
#pragma endregion

	free(KBCircle_Dog.kcPubKey);
	free(KBCircle_Cat.kcPubKey);
	free(KBCircleCommon.kcPubKey);
	return 0;
}

//*函数：test_keymanage_joincircle
//*功能：密钥管理加入circle测试
//*参数：无
//*日期：2018/12/18  by ZhangTao
int test_keymanage_joincircle()
{
	int ret, i;
	KeybagBindCode  KBBindCode_Dog, KBBindCode_Cat;
	uint8_t bindcode_plain_Dog[BINDCODE_PLAIN_LEN], bindcode_plain_Cat[BINDCODE_PLAIN_LEN];
	uint8_t phonenum_Dog[PHONE_NUMBER_LEN], phonenum_Cat[PHONE_NUMBER_LEN];
	uint8_t bindcodeVeriCipher_Dog[256], bindcodeVeriCipher_Cat[256];
	KeybagCreateCircleReq KBCreateCirReq_Dog;
	KeybagCircle KBCircle_Dog, KBCircle_Cat, KBCircleCommon;
	KeybagJoinCircleApprove KBJoinCir_DogApproveCat;
	uint32_t Dogverilen, Catverilen;
	uint32_t DogCirclelen;
	uint32_t timestamp1, timestamp2;

	KBCircle_Dog.kcPubKey = malloc(sizeof(KeybagCirclePubkey)* 20);
	KBCircle_Cat.kcPubKey = malloc(sizeof(KeybagCirclePubkey)* 20);
	KBCircleCommon.kcPubKey = malloc(sizeof(KeybagCirclePubkey)* 20);

	uint8_t KEY_BAG_ID_COMMON[14][8] = { 0 };//Circle最多加入14个

	//15 正确地加入Circle    Cat加入Dog的Circle
	//构造绑定验证码    Dog创建Circle的绑定验证码
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//签发绑定验证码
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//预期签发绑定验证码成功
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//构造创建Circle请求包
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//创建Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog), bindcodeVeriCipher_Dog,
		Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//预期创建Circle成功
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	for (i = 0; i < 14; i++)
	{
		KEY_BAG_ID_COMMON[i][7] = i + 2;

		//构造绑定验证码    Cat加入Dog的Circle的绑定验证码
		constructBindCode(&KBBindCode_Cat, KEY_BAG_ID_COMMON[i], PHONE_NUMBER_CAT, BIND_CODE_CAT, pubkey_jmj, SM2_PUBKEY_LEN + 1,
			prikey_cat, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);
		//签发绑定验证码
		ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Cat, sizeof(KBBindCode_Cat), cacert, ca_certlen, keybagCatcert,
			keybagCat_certlen, bindcode_plain_Cat, phonenum_Cat, bindcodeVeriCipher_Cat, &Catverilen);
		if (ret != SENC_SUCCESS){//预期签发绑定验证码成功
			cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
			return 1;
		}
		//构造加入Circle审批包
		constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_COMMON[i], PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
			KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
		//加入Circle
		ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
			bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
		if (ret != SENC_SUCCESS){//预期加入Circle成功
			cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
			return 1;
		}

	}


	free(KBCircle_Dog.kcPubKey);
	free(KBCircle_Cat.kcPubKey);
	free(KBCircleCommon.kcPubKey);
	return 0;
}

int main()
{
	//测试初始化
	if (test_init()){
		printf("测试初始化失败！\n");
		goto end;
	}
	printf("测试初始化成功！\n");
	getchar();

	//全流程测试
	if (test_keymanage_all()){
		printf("密钥管理全流程测试失败！\n");
		goto end;
	}
	printf("密钥管理全流程测试成功！\n");
	getchar();


	//消极测试
	if (test_keymanage_positive()){
		printf("密钥管理积极测试失败！\n");
		goto end;
	}
	printf("密钥管理积极测试成功！\n");
	getchar();

	//积极测试
	if (test_keymanage_negative()){
		printf("密钥管理消极测试失败！\n");
		goto end;
	}
	printf("密钥管理消极测试成功！\n");
	getchar();

	//加入Circle测试
	if (test_keymanage_joincircle()){
		printf("加入Circle测试失败！\n");
		goto end;
	}
	printf("加入Circle测试成功！\n");

	//关闭设备，释放设备列表
	SENC_Close(dHandle);
	SENC_FreeDevList(&gDevList);

	printf("测试完成！\n");
	getchar();

end:
	if (eckey)
		EC_KEY_free(eckey);

	if (group)
		SM2_Cleanup(group);
	
	getchar();
	return 0;
}
