#include <stdio.h>
#include <string.h>
#include <time.h>
#include <Windows.h>
#include "cryptocard.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include "sm2.h"
#include "sha256.h"
#include "sm3.h"

// #pragma comment (lib, "sm2lib.lib")

extern uint8 userpubkey_alice[65];
extern uint8 userprikey_alice[32];

extern uint8 userpubkey_bob[65];
extern uint8 userprikey_bob[32];

extern uint8 userpubkey_carol[65];
extern uint8 userprikey_carol[32];

extern uint8 userpubkey_eve[65];
extern uint8 userprikey_eve[32];

uint8 USER_ID_NULL[16]  = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
uint8 USER_ID_ALICE[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
uint8 USER_ID_BOB[16]   = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
uint8 USER_ID_CAROL[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
uint8 USER_ID_EVE[16]   = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 };

uint8 DEVLP_ID_ALI[8]     = { 0, 0, 0, 0, 0, 0, 0, 0 };
uint8 DEVLP_ID_TENCENT[8] = { 0, 0, 0, 0, 0, 0, 0, 1 };

uint8 APP_ID_TAOBAO[8]  = { 0, 0, 0, 0, 0, 0, 0, 0 };
uint8 APP_ID_QQ[8]      = { 0, 0, 0, 0, 0, 0, 0, 1 };
uint8 APP_ID_WEBCHAT[8] = { 0, 0, 0, 0, 0, 0, 0, 2 };

uint8 KEY_ID_COMMON[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
uint8 KEY_ID_OTHER[16]  = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

uint8 LIC_ID_ALICE_TO_BOB[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
uint8 LIC_ID_ALICE_TO_BOB_TO_CAROL[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
uint8 LIC_ID_ALICE_TO_CAROL[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

#define cc_error printf

EC_GROUP *group = NULL;
EC_KEY	*eckey = NULL;

#define DEFAULT_SM2_SIGN_USER_ID			"1234567812345678"
#define DEFAULT_SM2_SIGN_USER_ID_LEN		16

typedef uint8 SLC_BYTE;

void SlcSm3(uint8 *msg, uint32 msglen, uint8 *digest, uint32 digestbufflen, uint32 *digestlen)
{
	sm3_ex(msg, msglen, digest);
	*digestlen = SM3_HASH_SIZE;
}

void bn2hex(uint8 *bin, uint32 len, char *hex)
{
	uint32 i;

	for (i = 0; i < len; i++)
	{
		sprintf(hex, "%02X", bin[i]);
		hex += 2;
	}

}

const UINT8 TAG_CLASS_CONTEXT = 0xA0;
const UINT8 TAG_INTEGER = 0x02;
const UINT8 TAG_BIT_STRING = 0x03;
const UINT8 TAG_OCTET_STRING = 0x04;
const UINT8 TAG_OID = 0x06;
const UINT8 TAG_SEQUENCE = 0x30;

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

int sm2SignMsg(
	uint8 *prikey,
	uint32 prikeylen,
	uint8 *pubkey,
	uint32 pubkeylen,
	void *msg,
	uint32 msglen,
	uint8 *sig)
{
	int ret;
	BIGNUM *bnPrikey = NULL;
	EC_POINT *ecPubkey = NULL;
	char vkey[65];
	char pkey[131];
	unsigned char digest[32];
	unsigned char dersig[256];
	unsigned int digestlen, dersiglen, siglen;

	bn2hex(prikey, prikeylen, vkey);
	bn2hex(pubkey, pubkeylen, pkey);

	BN_hex2bn(&bnPrikey, vkey);
	EC_KEY_set_private_key(eckey, bnPrikey);
	ecPubkey = EC_POINT_hex2point(group, pkey, ecPubkey, NULL);
	EC_KEY_set_public_key(eckey, ecPubkey);

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
		cc_error("SM2_digest Failed:0x%08X\n", ret);
		return 1;
	}

	dersiglen = 256;
	ret = SM2_sign(1, digest, sizeof(digest), dersig, &dersiglen, eckey);
	if (ret != 1)
	{
		cc_error("SM2_digest Failed:0x%08X\n", ret);
		return 1;
	}

	ret = eccDerDecodeSignature(dersig, dersiglen, sig, 64);
	return 0;
}

int constructUserKey(USER_PUB_KEY *userKey, const uint8 *OwnerID, const uint8 *userpubkey)
{
	userKey->Version = VERSION_CURRENT_VERSION;
	memcpy(userKey->OwnerUserID, OwnerID, 16);
	userKey->TimeStamp = 0;
	userKey->AlgoID = ALGID_SM2_PUB;
	userKey->KeyBits = 256;
	userKey->KeyLen = 65;
	memcpy(userKey->KeyValue, userpubkey, 65);

	return 0;
}

int constructKeyReq(
	KEY_REC_REQ *req,
	const uint8 *KeyID,
	const uint8 *OwnerID,
	const uint8 *OwnerKeyID,
	const uint8 *DevlpID,
	const uint8 *AppID,
	int64 timestamp,
	int64 BeginTime,
	int64 EndTime,
	uint8 *prikey,
	uint32 prikeylen,
	uint8 *pubkey,
	uint32 pubkeylen)
{
	req->Version = VERSION_CURRENT_VERSION;
	memcpy(req->KeyID, KeyID, 16);
	memcpy(req->OwnerUserID, OwnerID, 16);
	memcpy(req->OwnerKeyFingerprint, OwnerKeyID, 32);
	memcpy(req->DevlpID, DevlpID, 8);
	memcpy(req->AppID, AppID, 8);
	req->timeStamp = timestamp;
	req->AlgoID = ALGID_SM4;
	req->KeyBits = 128;
	req->BeginTime = BeginTime;
	req->EndTime = EndTime;

	return sm2SignMsg(prikey, prikeylen, pubkey, pubkeylen, req, sizeof(KEY_REC_REQ) - 256, req->Signature);
}

int constructKeyPeriod(
	KEY_PERIOD *period,
	const uint8 *KeyID,
	int64 TimeStamp,
	int64 BeginTime,
	int64 EndTime,
	uint8 *prikey,
	uint32 prikeylen,
	uint8 *pubkey,
	uint32 pubkeylen)
{
	period->Version = VERSION_CURRENT_VERSION;
	memcpy(period->KeyID, KeyID, 16);
	period->TimeStamp = TimeStamp;
	period->BeginTime = BeginTime;
	period->EndTime = EndTime;

	return sm2SignMsg(prikey, prikeylen, pubkey, pubkeylen, period, sizeof(KEY_PERIOD) - 256, period->Signature);
}

int constructLicLim(
	LIC_LIMITED *licLim,
	uint32 Validity,
	int64 BeginTime,
	int64 EndTime,
	int64 SpanTime,
	int64 Times,
	uint32 Policy)
{
	licLim->Version = VERSION_CURRENT_VERSION;
	licLim->Validity = Validity;
	licLim->BeginTime = BeginTime;
	licLim->EndTime = EndTime;
	licLim->FirstTime = 0;
	licLim->SpanTime = SpanTime;
	licLim->Times = Times;
	licLim->Policy = Policy;

	return 0;
}

int constructLicReq(
	LIC_REQ *req,
	uint8 *FartherID,
	uint8 *UserID,
	uint8 *UserKeyID,
	uint8 *KeyID,
	uint8 *prikey,
	uint32 prikeylen,
	uint8 *pubkey,
	uint32 pubkeylen
)
{
	req->Version = VERSION_CURRENT_VERSION;
	if (FartherID)
		memcpy(req->FartherLicID, FartherID, 16);
	else
		memset(req->FartherLicID, 0, 16);
	memcpy(req->OwnerUserID, UserID, 16);
	memcpy(req->UserKeyFingerprint, UserKeyID, 32);
	memcpy(req->KeyID, KeyID, 16);
	req->TimeStamp = time(NULL);

	return sm2SignMsg(prikey, prikeylen, pubkey, pubkeylen, req, sizeof(LIC_REQ) - 256, req->Signature);
}

int initUser(
	USER_PUB_KEY *userKey,
	uint8 *userID,
	uint8 *userPubKey,
	KEY_REC *cKey,
	uint8 *KeyID,
	uint8 *DevlpID,
	uint8 *AppID,
	S1_CIPHER *s1_Kc,
	S1_CIPHER *s1_Ku,
	uint8 *prikey,
	uint32 prikeylen,
	uint8 *pubkey,
	uint32 pubkeylen
)
{
	int ret;
	uint32 outlen;
	uint8 fingerprint[32];
	KEY_REC_REQ keyReq;
	uint64 timeStamp;
	uint8 FatherlicID[16] = { 0 };
	uint8 licID[16] = { 1 };
	LIC_REQ licReq;
	LICENSE lic;

	// 构建公钥结构
	constructUserKey(userKey, userID, userPubKey);

	// 对公钥结构签名（MAC）
	ret = SignUserPubKey(userKey);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("SignUserPubKey Failed:0x%08X\n", ret);
		return 1;
	}

	// 计算公钥结构指纹
	SlcSm3((SLC_BYTE *)userKey, sizeof(USER_PUB_KEY), fingerprint, sizeof(fingerprint), &outlen);

	timeStamp = time(NULL);
	// 构建云端密钥请求
	constructKeyReq(&keyReq, KeyID, userID, fingerprint, DevlpID, AppID, timeStamp, timeStamp - 3600, timeStamp + 3600, prikey, prikeylen, pubkey, pubkeylen);

	// 生成云端密钥
	ret = GenerateKeyCloud(&keyReq, userKey, cKey);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("GenerateKeyCloud Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, timeStamp - 3600, 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_ENCRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构建许可请求
	ret = constructLicReq(&licReq, FatherlicID, userID, fingerprint, KeyID, prikey, prikeylen, pubkey, pubkeylen);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("constructLicReq Failed:0x%08X\n", ret);
		return 1;
	}

	// 为自己颁发许可
	ret = issueLicense(cKey, userKey, licID, 0, &licReq, &lic);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 生成S1
	ret = GenerateS1(cKey, userKey, &lic, s1_Kc, s1_Ku, &lic);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("GenerateS1 Failed:0x%08X\n", ret);
		return 1;
	}

	return 0;
}

int test_positive()
{
	int ret;
	USER_PUB_KEY userKey_Alice, userKey_Bob, userKey_Carol, userKey_Alice_new;
	KEY_REC key_Alice, key_Bob, key_Carol, key_Alice_new;
	S1_CIPHER s1_Kc_Alice, s1_Ku_Alice, s1_Kc_Bob, s1_Ku_Bob, s1_Kc_Carol, s1_Ku_Carol, s1_Kc_Alice_by_Bob;
	S1_CIPHER s1_Ku_Alice_to_Bob, s1_Ku_Alice_to_Bob_to_Carol;
	LIC_REQ licReq;
	LICENSE licA2B, licA2B2C;
	uint32 outlen;
	uint8 fingerprint[32];
	KEY_REC_REQ keyReq;
	KEY_PERIOD keyPeriod;
	uint64 timeStamp;

	// 初始化Alice的另一个公钥、云端密钥、S1
	ret = initUser(
		&userKey_Alice_new,
		USER_ID_ALICE,
		userpubkey_bob,
		&key_Alice,
		KEY_ID_COMMON,
		DEVLP_ID_ALI,
		APP_ID_TAOBAO,
		&s1_Kc_Alice,
		&s1_Ku_Alice,
		userprikey_bob,
		sizeof(userprikey_bob),
		userpubkey_bob,
		sizeof(userpubkey_bob)
	);
	if (ret != 0)
		return ret;

	// 初始化Alice的公钥、云端密钥、S1
	ret = initUser(
		&userKey_Alice,
		USER_ID_ALICE,
		userpubkey_alice,
		&key_Alice,
		KEY_ID_COMMON,
		DEVLP_ID_ALI,
		APP_ID_TAOBAO,
		&s1_Kc_Alice,
		&s1_Ku_Alice,
		userprikey_alice,
		sizeof(userprikey_alice),
		userpubkey_alice,
		sizeof(userpubkey_alice)
	);
	if (ret != 0)
		return ret;

	// 初始化Bob的公钥、云端密钥、S1
	ret = initUser(
		&userKey_Bob,
		USER_ID_BOB,
		userpubkey_bob,
		&key_Bob,
		KEY_ID_COMMON,
		DEVLP_ID_ALI,
		APP_ID_TAOBAO,
		&s1_Kc_Bob,
		&s1_Ku_Bob,
		userprikey_bob,
		sizeof(userprikey_bob),
		userpubkey_bob,
		sizeof(userpubkey_bob)
	);
	if (ret != 0)
		return ret;

	// 初始化Carol的公钥、云端密钥、S1
	ret = initUser(
		&userKey_Carol,
		USER_ID_CAROL,
		userpubkey_carol,
		&key_Carol,
		KEY_ID_COMMON,
		DEVLP_ID_ALI,
		APP_ID_TAOBAO,
		&s1_Kc_Carol,
		&s1_Ku_Carol,
		userprikey_carol,
		sizeof(userprikey_carol),
		userpubkey_carol,
		sizeof(userpubkey_carol)
	);
	if (ret != 0)
		return ret;

	////////////////////////////////////////////////////////////////////////
	////// 测试 GenerateKeyCloud
	////////////////////////////////////////////////////////////////////////

	timeStamp = time(NULL);
	// 计算公钥结构指纹
	SlcSm3((SLC_BYTE *)&userKey_Bob, sizeof(USER_PUB_KEY), fingerprint, sizeof(fingerprint), &outlen);

	// 构建云端密钥请求
	constructKeyReq(&keyReq, KEY_ID_COMMON, USER_ID_ALICE, fingerprint, DEVLP_ID_ALI, APP_ID_TAOBAO, timeStamp, timeStamp - 3600, timeStamp + 3600, userprikey_bob, sizeof(userprikey_bob), userpubkey_bob, sizeof(userpubkey_bob));

	// Bob不能生成Alice的云端密钥
	ret = GenerateKeyCloud(&keyReq, &userKey_Bob, &key_Alice_new);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateKeyCloud Failed:0x%08X\n", ret);
		return 1;
	}

	// 错误的公钥结构指纹
	memset(fingerprint, 0, sizeof(fingerprint));

	timeStamp = time(NULL);
	// 构建云端密钥请求
	constructKeyReq(&keyReq, KEY_ID_COMMON, USER_ID_ALICE, fingerprint, DEVLP_ID_ALI, APP_ID_TAOBAO, timeStamp, timeStamp - 3600, timeStamp + 3600, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// Bob不能生成Alice的云端密钥
	ret = GenerateKeyCloud(&keyReq, &userKey_Alice, &key_Alice_new);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateKeyCloud Failed:0x%08X\n", ret);
		return 1;
	}
#if 1
	////////////////////////////////////////////////////////////////////////
	////// 测试 SetKeyCloudPeriod
	////////////////////////////////////////////////////////////////////////

	timeStamp = time(NULL);
	// 构建密钥有效期
	constructKeyPeriod(&keyPeriod, KEY_ID_OTHER, timeStamp, timeStamp - 3600, timeStamp + 3600, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// KeyID不匹配
	ret = SetKeyCloudPeriod(&key_Alice, &userKey_Alice, &keyPeriod, &key_Alice_new);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("SetKeyCloudPeriod Failed:0x%08X\n", ret);
		return 1;
	}

	timeStamp = time(NULL);
	// 构建密钥有效期
	constructKeyPeriod(&keyPeriod, KEY_ID_COMMON, timeStamp-300, timeStamp - 3600, timeStamp + 3600, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	//  错误的有效期
	ret = SetKeyCloudPeriod(&key_Alice, &userKey_Alice, &keyPeriod, &key_Alice_new);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("SetKeyCloudPeriod Failed:0x%08X\n", ret);
		return 1;
	}

	timeStamp = time(NULL);
	// 构建密钥有效期
	constructKeyPeriod(&keyPeriod, KEY_ID_COMMON, timeStamp+2, timeStamp - 3600, timeStamp + 3600, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	//  正确的有效期
	ret = SetKeyCloudPeriod(&key_Alice, &userKey_Alice, &keyPeriod, &key_Alice_new);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("SetKeyCloudPeriod Failed:0x%08X\n", ret);
		return 1;
	}

	timeStamp = time(NULL);
	// 构建密钥有效期
	constructKeyPeriod(&keyPeriod, KEY_ID_COMMON, timeStamp, timeStamp - 3600, timeStamp + 3600, userprikey_bob, sizeof(userprikey_bob), userpubkey_bob, sizeof(userpubkey_bob));

	//  Bob不能改Alice的密钥有效期
	ret = SetKeyCloudPeriod(&key_Alice, &userKey_Bob, &keyPeriod, &key_Alice_new);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("SetKeyCloudPeriod Failed:0x%08X\n", ret);
		return 1;
	}

	timeStamp = time(NULL);
	// 构建密钥有效期
	constructKeyPeriod(&keyPeriod, KEY_ID_COMMON, timeStamp, timeStamp - 3600, timeStamp + 3600, userprikey_bob, sizeof(userprikey_bob), userpubkey_bob, sizeof(userpubkey_bob));

	//  Alice的另一个公钥也不能改Alice的密钥有效期
	ret = SetKeyCloudPeriod(&key_Alice, &userKey_Alice_new, &keyPeriod, &key_Alice_new);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("SetKeyCloudPeriod Failed:0x%08X\n", ret);
		return 1;
	}
#endif
	/////////////////////////////////////////////////////////
	////// 测试密钥有效期对GenerateS1和convertCipher的影响

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_ENCRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对自己授权
	constructLicReq(&licReq, NULL, USER_ID_ALICE, key_Alice.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

#if 1 // 记录：设置密钥有效期时，可设置将来生效的密钥
	timeStamp = time(NULL);
	// 构建密钥有效期
	constructKeyPeriod(&keyPeriod, KEY_ID_COMMON, timeStamp, timeStamp + 600, timeStamp + 3600, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	//  构建密钥有效期
	ret = SetKeyCloudPeriod(&key_Alice, &userKey_Alice, &keyPeriod, &key_Alice_new);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("SetKeyCloudPeriod Failed:0x%08X\n", ret);
		return 1;
	}

	//  密钥还没有生效
	ret = GenerateS1(&key_Alice_new, &userKey_Alice, &licA2B, &s1_Kc_Alice_by_Bob, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateS1 Failed:0x%08X\n", ret);
		return 1;
	}

	// 密钥还没有生效
	ret = convertCipher(&key_Alice_new, &userKey_Alice, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}
#endif
	timeStamp = time(NULL);
	// 构建密钥有效期
	constructKeyPeriod(&keyPeriod, KEY_ID_COMMON, timeStamp, timeStamp - 3600, timeStamp - 60, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	//  密钥已过期
	ret = SetKeyCloudPeriod(&key_Alice, &userKey_Alice, &keyPeriod, &key_Alice_new);
	if (ret != CC_ERROR_SUCCESS)//==改为!=
	{
		cc_error("SetKeyCloudPeriod Failed:0x%08X\n", ret);
		return 1;
	}

#if 1	// 记录：前面设置有效期时，未设置成功，密钥有效期为原始有效期，即密钥是有效的，能正确通过。
	//  密钥已过期
	ret = GenerateS1(&key_Alice_new, &userKey_Alice, &licA2B, &s1_Kc_Alice_by_Bob, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateS1 Failed:0x%08X\n", ret);
		return 1;
	}

	// 密钥已过期
	ret = convertCipher(&key_Alice_new, &userKey_Alice, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}
#endif
	////////////////////////////////////////////////////////////////////////
	////// 测试 GenerateS1
	////////////////////////////////////////////////////////////////////////

	// 没有许可Alice不可以生成自己的S1
	ret = GenerateS1(&key_Alice, &userKey_Alice, NULL, &s1_Kc_Alice_by_Bob, &s1_Ku_Alice_to_Bob, NULL);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateS1 Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款，次数
	constructLicLim(&licReq.licLimited, FLAG_TIMES, 0, 0, 0, 1, POLICY_INHERIT | POLICY_DECRYPT | POLICY_ENCRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对自己授权
	constructLicReq(&licReq, NULL, USER_ID_ALICE, key_Alice.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	if (licA2B.licLimited.Times != 1)
	{
		cc_error("licA2B.licLimited.Times != 1");
		return 1;
	}

	// 生成自己的S1
	ret = GenerateS1(&key_Alice, &userKey_Alice, &licA2B, &s1_Kc_Alice_by_Bob, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)//==改为！=
	{
		cc_error("GenerateS1 Failed:0x%08X\n", ret);
		return 1;
	}

	if (licA2B.licLimited.Times != 0)
	{
		cc_error("licA2B.licLimited.Times != 1");
		return 1;
	}

	// 构建许可条款，有效期
	constructLicLim(&licReq.licLimited, FLAG_SPAN_TIME, 0, 0, 3600, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_ENCRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对自己授权
	constructLicReq(&licReq, NULL, USER_ID_ALICE, key_Alice.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	if (licA2B.licLimited.SpanTime != 3600)  //0改为3600
	{
		cc_error("licA2B.licLimited.SpanTime != 3600");
		return 1;
	}

	// 生成自己的S1
	ret = GenerateS1(&key_Alice, &userKey_Alice, &licA2B, &s1_Kc_Alice_by_Bob, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)//==改为!=
	{
		cc_error("GenerateS1 Failed:0x%08X\n", ret);
		return 1;
	}

#if 0
	timeStamp = time(NULL);
	if (licA2B.licLimited.SpanTime != timeStamp-1 && licA2B.licLimited.SpanTime != timeStamp)
	{
		cc_error("licA2B.licLimited.Times != 1");
		return 1;
	}
#endif
	////////////////////////////////////////////////////////////////////////
	////// 测试 issueLicense
	////////////////////////////////////////////////////////////////////////

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 请求时间戳过期
	licReq.TimeStamp -= 300;

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 请求时间戳未到
	licReq.TimeStamp += 302;

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款,不支持加密
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// Bob不可以生成Alice的S1
	ret = GenerateS1(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice_by_Bob, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateS1 Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_ENCRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// issuerID应为Key的OwnerUserID
	if (memcmp(licA2B.IssuerUserID, key_Alice.OwnerUserID, 16) != 0)
	{
		cc_error("licA2B.IssuerID != key_Alice.OwnerID\n");
		return 1;
	}

	// FatherLicID应为0
	if (memcmp(licA2B.FartherLicID, USER_ID_NULL, 16) != 0)
	{
		cc_error("licA2B.FartherLicID != USER_ID_NULL\n");
		return 1;
	}

	// Bob可以生成Alice的S1了
	ret = GenerateS1(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice_by_Bob, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("GenerateS1 Failed:0x%08X\n", ret);
		return 1;
	}

	// Alice不可以用给Bob的许可生成S1
	ret = GenerateS1(&key_Alice, &userKey_Alice, &licA2B, &s1_Kc_Alice_by_Bob, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateS1 Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// Alice给Bob的许可不能用于转换给Carol
	ret = convertCipher(&key_Alice, &userKey_Carol, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob_to_Carol, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// Bob使用Alice的许可给Carol授权
	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_ENCRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Bob使用Alice的许可对Carol授权
	constructLicReq(&licReq, licA2B.LicID, USER_ID_CAROL, key_Carol.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_bob, sizeof(userprikey_bob), userpubkey_bob, sizeof(userpubkey_bob));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Bob, LIC_ID_ALICE_TO_BOB_TO_CAROL, &licA2B, &licReq, &licA2B2C);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// issuerID应为FatherLic中的UserID
	if (memcmp(licA2B2C.IssuerUserID, licA2B.OwnerUserID, 16) != 0)
	{
		cc_error("licA2B2C.IssuerUserID != licA2B.OwnerUserID\n");
		return 1;
	}

	// FatherLicID应为FatherLic中的UserID
	if (memcmp(licA2B2C.FartherLicID, licA2B.LicID, 16) != 0)
	{
		cc_error("licA2B2C.FartherLicID != licA2B.LicID\n");
		return 1;
	}

	//  使用Bob转给Carol的许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Carol, &licA2B2C, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob_to_Carol, &licA2B2C);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款，不可继承的许可
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// Bob使用Alice的许可给Carol授权
	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Bob使用Alice的许可对Carol授权
	constructLicReq(&licReq, licA2B.LicID, USER_ID_CAROL, key_Carol.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_bob, sizeof(userprikey_bob), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Bob, LIC_ID_ALICE_TO_BOB_TO_CAROL, &licA2B, &licReq, &licA2B2C);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款，不可继承的许可，不可解密的许可
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款，不可继承的许可，次数许可
	constructLicLim(&licReq.licLimited, FLAG_TIMES, 0, 0, 0, 1, POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	if (licA2B.licLimited.Times != 0)
	{
		cc_error("licA2B.licLimited.Times Wrong\n");
		return 1;
	}

	// 使用许可转换Alice的S1，没有可用次数了
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款，不可继承的许可，开始时间未到
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL)+3600, 0, 0, 0, POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款，不可继承的许可，正常的结束时间
	constructLicLim(&licReq.licLimited, FLAG_END_TIME, 0, time(NULL) + 3600, 0, 0, POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款，不可继承的许可，结束时间已过
	constructLicLim(&licReq.licLimited, FLAG_END_TIME, 0, time(NULL) - 3600, 0, 0, POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款，不可继承的许可，正常的可用时间
	constructLicLim(&licReq.licLimited, FLAG_SPAN_TIME, 0, 0, 10, 0, POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	if (licA2B.licLimited.FirstTime != 0)
	{
		cc_error("licA2B.licLimited.FirstTime != 0\n");
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	if (licA2B.licLimited.FirstTime == 0)
	{
		cc_error("licA2B.licLimited.FirstTime == 0\n");
		return 1;
	}

	Sleep(13000);//13改为13000

	// 使用许可转换Alice的S1，许可已失效
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款，不可继承的许可，正常的开始时间和结束时间
	constructLicLim(&licReq.licLimited, FLAG_START_TIME | FLAG_END_TIME, time(NULL), time(NULL)+3600, 0, 0, POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款，不可继承的许可，正常的开始时间和结束时间，但次数为0
	constructLicLim(&licReq.licLimited, FLAG_START_TIME | FLAG_END_TIME | FLAG_TIMES, time(NULL), time(NULL) + 3600, 0, 0, POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款，不可继承的许可，正常的开始时间和结束时间，但可用时间为0
	constructLicLim(&licReq.licLimited, FLAG_START_TIME | FLAG_END_TIME | FLAG_SPAN_TIME, time(NULL), time(NULL) + 3600, 0, 0, POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款，不可继承的许可，4种条件都正常
	constructLicLim(&licReq.licLimited, FLAG_START_TIME | FLAG_END_TIME | FLAG_SPAN_TIME | FLAG_TIMES, time(NULL), time(NULL) + 3600, 1000, 1, POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1，次数用完了
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对自己授权
	constructLicReq(&licReq, NULL, USER_ID_ALICE, key_Alice.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Alice, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// Alice没有许可不能转换自己的S1
	ret = convertCipher(&key_Alice, &userKey_Alice, NULL, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, NULL);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可，错误的公钥
	ret = issueLicense(&key_Alice, &userKey_Bob, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权，由Bob签名
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_bob, sizeof(userprikey_bob), userpubkey_bob, sizeof(userpubkey_bob));

	// 签发许可，非密钥所有者不能直接签发
	ret = issueLicense(&key_Alice, &userKey_Bob, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权，错误的公钥指纹
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Alice.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1，许可中的公钥指纹错了，许可无效
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权，错误的用户ID
	constructLicReq(&licReq, NULL, USER_ID_CAROL, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1，许可中的用户ID错了，许可无效
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// Alice的许可不能转换Bob的S1
	ret = convertCipher(&key_Bob, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 没有许可不能转换Alice的S1给Bob
	ret = convertCipher(&key_Alice, &userKey_Bob, NULL, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, NULL);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// Bob使用Alice的许可做父许可给Bob的密钥授权
	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Bob使用Alice的许可对Bob密钥给Carol授权
	constructLicReq(&licReq, licA2B.LicID, USER_ID_CAROL, key_Carol.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_bob, sizeof(userprikey_bob), userpubkey_bob, sizeof(userpubkey_bob));

	// 签发许可
	ret = issueLicense(&key_Bob, &userKey_Bob, LIC_ID_ALICE_TO_BOB_TO_CAROL, &licA2B, &licReq, &licA2B2C);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// Carol使用Alice给Bob的许可做父许可
	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Bob使用Alice的许可对Bob密钥给Carol授权
	constructLicReq(&licReq, licA2B.LicID, USER_ID_CAROL, key_Carol.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_carol, sizeof(userprikey_carol), userpubkey_carol, sizeof(userpubkey_carol));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Carol, LIC_ID_ALICE_TO_BOB_TO_CAROL, &licA2B, &licReq, &licA2B2C);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 错误的KeyID
	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，错误的KeyID
	constructLicReq(&licReq, licA2B.LicID, USER_ID_CAROL, key_Carol.OwnerKeyFingerprint, KEY_ID_OTHER, userprikey_bob, sizeof(userprikey_bob), userpubkey_bob, sizeof(userpubkey_bob));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Bob, LIC_ID_ALICE_TO_BOB_TO_CAROL, &licA2B, &licReq, &licA2B2C);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 错误的FatherLicID
	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，错误的FatherID
	constructLicReq(&licReq, LIC_ID_ALICE_TO_CAROL, USER_ID_CAROL, key_Carol.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_bob, sizeof(userprikey_bob), userpubkey_bob, sizeof(userpubkey_bob));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Bob, LIC_ID_ALICE_TO_BOB_TO_CAROL, &licA2B, &licReq, &licA2B2C);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	return 0;
}

int test_negtive()
{
	int ret, i;
	USER_PUB_KEY userKey_Alice, userKey_Bob, userKey_Carol, userKey_Eve;
	KEY_REC key_Alice, key_Bob, key_Carol, key_Eve;
	S1_CIPHER s1_Kc_Alice, s1_Ku_Alice, s1_Kc_Bob, s1_Ku_Bob, s1_Kc_Carol, s1_Ku_Carol;
	S1_CIPHER s1_Ku_Alice_to_Bob;
	LIC_REQ licReq, licReq_Eve;
	LICENSE licA2B, licA2B2C, licEve;
	KEY_REC_REQ keyReq;
	uint32 outlen;
	uint8 fingerprint[32];
	KEY_PERIOD keyPeriod;
	uint64 timeStamp;
	uint8 FatherlicID[16] = { 0 };
	uint8 licID[16] = { 1 };
	LICENSE lic;

	// 1.测试对公钥签名
	// bad version
	userKey_Alice.Version = VERSION_CURRENT_VERSION+1;
	memcpy(userKey_Alice.OwnerUserID, USER_ID_ALICE, 16);
	userKey_Alice.TimeStamp = 0;
	userKey_Alice.AlgoID = ALGID_SM2_PUB;
	userKey_Alice.KeyBits = 256;
	userKey_Alice.KeyLen = 65;
	memcpy(userKey_Alice.KeyValue, userpubkey_alice, 65);

	// 对公钥结构签名（MAC）
	ret = SignUserPubKey(&userKey_Alice);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("SignUserPubKey Failed:0x%08X\n", ret);
		return 1;
	}

	// bad AlgoID
	userKey_Alice.Version = VERSION_CURRENT_VERSION;
	memcpy(userKey_Alice.OwnerUserID, USER_ID_ALICE, 16);
	userKey_Alice.TimeStamp = 0;
	userKey_Alice.AlgoID = ALGID_AES;
	userKey_Alice.KeyBits = 256;
	userKey_Alice.KeyLen = 65;
	memcpy(userKey_Alice.KeyValue, userpubkey_alice, 65);

	// 对公钥结构签名（MAC）
	ret = SignUserPubKey(&userKey_Alice);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("SignUserPubKey Failed:0x%08X\n", ret);
		return 1;
	}

	// bad keybits
	userKey_Alice.Version = VERSION_CURRENT_VERSION;
	memcpy(userKey_Alice.OwnerUserID, USER_ID_ALICE, 16);
	userKey_Alice.TimeStamp = 0;
	userKey_Alice.AlgoID = ALGID_SM2_PUB;
	userKey_Alice.KeyBits = 1000;
	userKey_Alice.KeyLen = 65;
	memcpy(userKey_Alice.KeyValue, userpubkey_alice, 65);

	// 对公钥结构签名（MAC）

	ret = SignUserPubKey(&userKey_Alice);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("SignUserPubKey Failed:0x%08X\n", ret);
		return 1;
	}

	// 2.测试生成云端密钥
	// 构建公钥结构
	constructUserKey(&userKey_Alice, USER_ID_ALICE, userpubkey_alice);

	// 对公钥结构签名（MAC）
	ret = SignUserPubKey(&userKey_Alice);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("SignUserPubKey Failed:0x%08X\n", ret);
		return 1;
	}

	// 计算公钥结构指纹
	SlcSm3((SLC_BYTE *)&userKey_Alice, sizeof(USER_PUB_KEY), fingerprint, sizeof(fingerprint), &outlen);

	timeStamp = time(NULL);
	
	// bad version
	keyReq.Version = VERSION_CURRENT_VERSION + 1;
	memcpy(keyReq.KeyID, KEY_ID_COMMON, 16);
	memcpy(keyReq.OwnerUserID, USER_ID_ALICE, 16);
	memcpy(keyReq.OwnerKeyFingerprint, fingerprint, 32);
	memcpy(keyReq.DevlpID, DEVLP_ID_ALI, 8);
	memcpy(keyReq.AppID, APP_ID_TAOBAO, 8);
	keyReq.AlgoID = ALGID_SM4;
	keyReq.KeyBits = 128;
	keyReq.BeginTime = timeStamp - 3600;
	keyReq.EndTime = timeStamp + 3600;

	ret = sm2SignMsg(userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice), &keyReq, sizeof(KEY_REC_REQ) - 256, keyReq.Signature);
	if (ret != 0)
		return 1;

	// 生成云端密钥
	ret = GenerateKeyCloud(&keyReq, &userKey_Alice, &key_Alice);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateKeyCloud Failed:0x%08X\n", ret);
		return 1;
	}

	// bad AlgoID
	keyReq.Version = VERSION_CURRENT_VERSION;
	memcpy(keyReq.KeyID, KEY_ID_COMMON, 16);
	memcpy(keyReq.OwnerUserID, USER_ID_ALICE, 16);
	memcpy(keyReq.OwnerKeyFingerprint, fingerprint, 32);
	memcpy(keyReq.DevlpID, DEVLP_ID_ALI, 8);
	memcpy(keyReq.AppID, APP_ID_TAOBAO, 8);
	keyReq.AlgoID = ALGID_RSA_PUB;
	keyReq.KeyBits = 128;
	keyReq.BeginTime = timeStamp - 3600;
	keyReq.EndTime = timeStamp + 3600;

	ret = sm2SignMsg(userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice), &keyReq, sizeof(KEY_REC_REQ) - 256, keyReq.Signature);
	if (ret != 0)
		return 1;

	// 生成云端密钥
	ret = GenerateKeyCloud(&keyReq, &userKey_Alice, &key_Alice);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateKeyCloud Failed:0x%08X\n", ret);
		return 1;
	}

	// bad KeyBits
	keyReq.Version = VERSION_CURRENT_VERSION;
	memcpy(keyReq.KeyID, KEY_ID_COMMON, 16);
	memcpy(keyReq.OwnerUserID, USER_ID_ALICE, 16);
	memcpy(keyReq.OwnerKeyFingerprint, fingerprint, 32);
	memcpy(keyReq.DevlpID, DEVLP_ID_ALI, 8);
	memcpy(keyReq.AppID, APP_ID_TAOBAO, 8);
	keyReq.AlgoID = ALGID_SM4;
	keyReq.KeyBits = 1000;
	keyReq.BeginTime = timeStamp - 3600;
	keyReq.EndTime = timeStamp + 3600;

	ret = sm2SignMsg(userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice), &keyReq, sizeof(KEY_REC_REQ) - 256, keyReq.Signature);
	if (ret != 0)
		return 1;

	// 生成云端密钥
	ret = GenerateKeyCloud(&keyReq, &userKey_Alice, &key_Alice);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateKeyCloud Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建云端密钥请求
	constructKeyReq(&keyReq, KEY_ID_COMMON, USER_ID_ALICE, fingerprint, DEVLP_ID_ALI, APP_ID_TAOBAO, timeStamp, timeStamp - 3600, timeStamp + 3600, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// bad signature
	memset(keyReq.Signature, 0, 256);

	// 生成云端密钥
	ret = GenerateKeyCloud(&keyReq, &userKey_Alice, &key_Alice);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateKeyCloud Failed:0x%08X\n", ret);
		return 1;
	}

	// 3.测试设置云端密钥有效期
	// 初始化Alice的公钥、云端密钥、S1
	ret = initUser(
		&userKey_Alice,
		USER_ID_ALICE,
		userpubkey_alice,
		&key_Alice,
		KEY_ID_COMMON,
		DEVLP_ID_ALI,
		APP_ID_TAOBAO,
		&s1_Kc_Alice,
		&s1_Ku_Alice,
		userprikey_alice,
		sizeof(userprikey_alice),
		userpubkey_alice,
		sizeof(userpubkey_alice)
	);
	if (ret != 0)
		return ret;

	// bad version
	keyPeriod.Version = VERSION_CURRENT_VERSION + 1;
	memcpy(keyPeriod.KeyID, KEY_ID_COMMON, 16);
	keyPeriod.TimeStamp = timeStamp;
	keyPeriod.BeginTime = timeStamp - 3600;
	keyPeriod.EndTime = timeStamp + 3600;

	ret = sm2SignMsg(userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice), &keyPeriod, sizeof(KEY_PERIOD) - 256, keyPeriod.Signature);
	if (ret != 0)
		return 1;

	// 设置密钥有效期
	ret = SetKeyCloudPeriod(&key_Alice, &userKey_Alice, &keyPeriod, &key_Alice);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("SetKeyCloudPeriod Failed:0x%08X\n", ret);
		return 1;
	}

	// bad signature
	keyPeriod.Version = VERSION_CURRENT_VERSION;
	memcpy(keyPeriod.KeyID, KEY_ID_COMMON, 16);
	keyPeriod.TimeStamp = timeStamp;
	keyPeriod.BeginTime = timeStamp - 3600;
	keyPeriod.EndTime = timeStamp + 3600;
	memset(keyPeriod.Signature, 0, 256);

	// 设置密钥有效期
	ret = SetKeyCloudPeriod(&key_Alice, &userKey_Alice, &keyPeriod, &key_Alice);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("SetKeyCloudPeriod Failed:0x%08X\n", ret);
		return 1;
	}

	// 4.测试生成S1
	// 构建公钥结构
	constructUserKey(&userKey_Alice, USER_ID_ALICE, userpubkey_alice);

	// 对公钥结构签名（MAC）
	ret = SignUserPubKey(&userKey_Alice);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("SignUserPubKey Failed:0x%08X\n", ret);
		return 1;
	}

	// 计算公钥结构指纹
	SlcSm3((SLC_BYTE *)&userKey_Alice, sizeof(USER_PUB_KEY), fingerprint, sizeof(fingerprint), &outlen);

#if 0
	timeStamp = time(NULL);
	// 构建密钥有效期
	constructKeyPeriod(&keyPeriod, KEY_ID_COMMON, timeStamp, timeStamp - 3600, timeStamp + 3600, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));
#endif

	// 生成云端密钥
	keyReq.Version = VERSION_CURRENT_VERSION;
	memcpy(keyReq.KeyID, KEY_ID_COMMON, 16);
	memcpy(keyReq.OwnerUserID, USER_ID_ALICE, 16);
	memcpy(keyReq.OwnerKeyFingerprint, fingerprint, 32);
	memcpy(keyReq.DevlpID, DEVLP_ID_ALI, 8);
	memcpy(keyReq.AppID, APP_ID_TAOBAO, 8);
	keyReq.AlgoID = ALGID_SM4;
	keyReq.KeyBits = 128;

	ret = sm2SignMsg(userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice), &keyReq, sizeof(KEY_REC_REQ)-256, keyReq.Signature);
	if (ret != 0)
		return 1;

	// 生成云端密钥
	ret = GenerateKeyCloud(&keyReq, &userKey_Alice, &key_Alice);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("GenerateKeyCloud Failed:0x%08X\n", ret);
		return 1;
	}

	// 没有许可不能生成S1
	ret = GenerateS1(&key_Alice, &userKey_Alice, NULL, &s1_Kc_Alice, &s1_Ku_Alice, NULL);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateS1 Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, timeStamp - 3600, 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_ENCRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构建许可请求
	ret = constructLicReq(&licReq, FatherlicID, USER_ID_ALICE, fingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("constructLicReq Failed:0x%08X\n", ret);
		return 1;
	}

	// 为自己颁发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, licID, 0, &licReq, &lic);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	for (i = 0; i < sizeof(userKey_Eve); i++)
	{
		// 篡改用户公钥任何一个字节，都会导致不可用
		memcpy(&userKey_Eve, &userKey_Alice, sizeof(userKey_Alice));
		((uint8 *)&userKey_Eve)[i] ++;

		// 生成S1
		ret = GenerateS1(&key_Alice, &userKey_Eve, &lic, &s1_Kc_Alice, &s1_Ku_Alice, &lic);
		if (ret == CC_ERROR_SUCCESS)
		{
			cc_error("GenerateS1 Failed:0x%08X\n", ret);
			return 1;
		}
	}

	for (i = 0; i < sizeof(key_Eve); i++)
	{
		// 篡改云端密钥任何一个字节，也会导致不可用
		memcpy(&key_Eve, &key_Alice, sizeof(key_Alice));
		((uint8 *)&key_Eve)[i] ++;

		// 生成S1
		ret = GenerateS1(&key_Eve, &userKey_Alice, &lic, &s1_Kc_Alice, &s1_Ku_Alice, &lic);
		if (ret == CC_ERROR_SUCCESS)
		{
			cc_error("GenerateS1 Failed:0x%08X\n", ret);
			return 1;
		}
	}

	// 构建公钥结构
	constructUserKey(&userKey_Bob, USER_ID_BOB, userpubkey_bob);

	// 对公钥结构签名（MAC）
	ret = SignUserPubKey(&userKey_Bob);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("SignUserPubKey Failed:0x%08X\n", ret);
		return 1;
	}

	// 用户公钥和许可不对应
	// 生成S1
	ret = GenerateS1(&key_Alice, &userKey_Bob, &lic, &s1_Kc_Alice, &s1_Ku_Alice, &lic);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("GenerateS1 Failed:0x%08X\n", ret);
		return 1;
	}

	// 5.测试签发许可
	// 初始化Alice的公钥、云端密钥、S1
	ret = initUser(
		&userKey_Alice,
		USER_ID_ALICE,
		userpubkey_alice,
		&key_Alice,
		KEY_ID_COMMON,
		DEVLP_ID_ALI,
		APP_ID_TAOBAO,
		&s1_Kc_Alice,
		&s1_Ku_Alice,
		userprikey_alice,
		sizeof(userprikey_alice),
		userpubkey_alice,
		sizeof(userpubkey_alice)
	);
	if (ret != 0)
		return ret;

	// 初始化Bob的公钥、云端密钥、S1
	ret = initUser(
		&userKey_Bob,
		USER_ID_BOB,
		userpubkey_bob,
		&key_Bob,
		KEY_ID_COMMON,
		DEVLP_ID_ALI,
		APP_ID_TAOBAO,
		&s1_Kc_Bob,
		&s1_Ku_Bob,
		userprikey_bob,
		sizeof(userprikey_bob),
		userpubkey_bob,
		sizeof(userpubkey_bob)
	);
	if (ret != 0)
		return ret;

	// 初始化Carol的公钥、云端密钥、S1
	ret = initUser(
		&userKey_Carol,
		USER_ID_CAROL,
		userpubkey_carol,
		&key_Carol,
		KEY_ID_COMMON,
		DEVLP_ID_ALI,
		APP_ID_TAOBAO,
		&s1_Kc_Carol,
		&s1_Ku_Carol,
		userprikey_carol,
		sizeof(userprikey_carol),
		userpubkey_carol,
		sizeof(userpubkey_carol)
	);
	if (ret != 0)
		return ret;

	// 构建许可条款,bad version
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);
	licReq.licLimited.Version++;

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));
	// bad version
	licReq.Version++;

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret == CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	for (i = 0; i < sizeof(userKey_Eve); i++)
	{
		// 篡改用户公钥任何一个字节，都会导致不可用
		memcpy(&userKey_Eve, &userKey_Alice, sizeof(userKey_Alice));
		((uint8 *)&userKey_Eve)[i] ++;

		// 签发许可
		ret = issueLicense(&key_Alice, &userKey_Eve, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
		if (ret == CC_ERROR_SUCCESS)
		{
			cc_error("issueLicense Failed:0x%08X\n", ret);
			return 1;
		}
	}

	for (i = 0; i < sizeof(key_Eve); i++)
	{
		// 篡改云端密钥任何一个字节，也会导致不可用
		memcpy(&key_Eve, &key_Alice, sizeof(key_Alice));
		((uint8 *)&key_Eve)[i] ++;

		// 签发许可
		ret = issueLicense(&key_Eve, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
		if (ret == CC_ERROR_SUCCESS)
		{
			cc_error("issueLicense Failed:0x%08X\n", ret);
			return 1;
		}
	}
	//修改，许可请求签名字段256字节，只有前64字节有效，若修改64字节之后的无效内容不影响签发许可
	//将sizeof(licReq_Eve)修改为(sizeof(licReq_Eve)-sizeof(licReq_Eve.Signature)+64)
	for (i = 0; i < (sizeof(licReq_Eve)-sizeof(licReq_Eve.Signature)+64); i++)
	{
		// 篡改许可请求任何一个字节，也会导致不可用
		memcpy(&licReq_Eve, &licReq, sizeof(licReq));
		((uint8 *)&licReq_Eve)[i] ++;

		// 签发许可
		ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq_Eve, &licA2B);
		if (ret == CC_ERROR_SUCCESS)
		{
			cc_error("issueLicense Failed:0x%08X\n", ret);
			return 1;
		}
	}

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// Bob使用Alice的许可给Carol授权
	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Bob使用Alice的许可对Carol授权
	constructLicReq(&licReq, licA2B.LicID, USER_ID_CAROL, key_Carol.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_bob, sizeof(userprikey_bob), userpubkey_bob, sizeof(userpubkey_bob));

	for (i = 0; i < sizeof(licEve); i++)
	{
		// 篡改父许可任何一个字节，也会导致不可用
		memcpy(&licEve, &licA2B, sizeof(licA2B));
		((uint8 *)&licEve)[i] ++;

		// 签发许可
		ret = issueLicense(&key_Alice, &userKey_Bob, LIC_ID_ALICE_TO_BOB_TO_CAROL, &licEve, &licReq, &licA2B2C);
		if (ret == CC_ERROR_SUCCESS)
		{
			cc_error("issueLicense Failed:0x%08X\n", ret);
			return 1;
		}
	}

	// 5.测试转换密文
	// 初始化Alice的公钥、云端密钥、S1
	ret = initUser(
		&userKey_Alice,
		USER_ID_ALICE,
		userpubkey_alice,
		&key_Alice,
		KEY_ID_COMMON,
		DEVLP_ID_ALI,
		APP_ID_TAOBAO,
		&s1_Kc_Alice,
		&s1_Ku_Alice,
		userprikey_alice,
		sizeof(userprikey_alice),
		userpubkey_alice,
		sizeof(userpubkey_alice)
	);
	if (ret != 0)
		return ret;

	// 初始化Bob的公钥、云端密钥、S1
	ret = initUser(
		&userKey_Bob,
		USER_ID_BOB,
		userpubkey_bob,
		&key_Bob,
		KEY_ID_COMMON,
		DEVLP_ID_ALI,
		APP_ID_TAOBAO,
		&s1_Kc_Bob,
		&s1_Ku_Bob,
		userprikey_bob,
		sizeof(userprikey_bob),
		userpubkey_bob,
		sizeof(userpubkey_bob)
	);
	if (ret != 0)
		return ret;

	// 初始化Carol的公钥、云端密钥、S1
	ret = initUser(
		&userKey_Carol,
		USER_ID_CAROL,
		userpubkey_carol,
		&key_Carol,
		KEY_ID_COMMON,
		DEVLP_ID_ALI,
		APP_ID_TAOBAO,
		&s1_Kc_Carol,
		&s1_Ku_Carol,
		userprikey_carol,
		sizeof(userprikey_carol),
		userpubkey_carol,
		sizeof(userpubkey_carol)
	);
	if (ret != 0)
		return ret;

	// 构建许可条款
	constructLicLim(&licReq.licLimited, FLAG_START_TIME, time(NULL), 0, 0, 0, POLICY_INHERIT | POLICY_DECRYPT | POLICY_PRINT | POLICY_EXPORT);

	// 构造许可请求，Alice对Bob授权
	constructLicReq(&licReq, NULL, USER_ID_BOB, key_Bob.OwnerKeyFingerprint, KEY_ID_COMMON, userprikey_alice, sizeof(userprikey_alice), userpubkey_alice, sizeof(userpubkey_alice));

	// 签发许可
	ret = issueLicense(&key_Alice, &userKey_Alice, LIC_ID_ALICE_TO_BOB, NULL, &licReq, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("issueLicense Failed:0x%08X\n", ret);
		return 1;
	}

	// 使用许可转换Alice的S1
	ret = convertCipher(&key_Alice, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
	if (ret != CC_ERROR_SUCCESS)
	{
		cc_error("convertCipher Failed:0x%08X\n", ret);
		return 1;
	}

	for (i = 0; i < sizeof(userKey_Eve); i++)
	{
		// 篡改用户公钥任何一个字节，都会导致不可用
		memcpy(&userKey_Eve, &userKey_Bob, sizeof(userKey_Bob));
		((uint8 *)&userKey_Eve)[i] ++;

		// 使用许可转换Alice的S1
		ret = convertCipher(&key_Alice, &userKey_Eve, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
		if (ret == CC_ERROR_SUCCESS)
		{
			cc_error("convertCipher Failed:0x%08X\n", ret);
			return 1;
		}
	}

	for (i = 0; i < sizeof(key_Eve); i++)
	{
		// 篡改云端密钥任何一个字节，也会导致不可用
		memcpy(&key_Eve, &key_Alice, sizeof(key_Alice));
		((uint8 *)&key_Eve)[i] ++;

		// 使用许可转换Alice的S1
		ret = convertCipher(&key_Eve, &userKey_Bob, &licA2B, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
		if (ret == CC_ERROR_SUCCESS)
		{
			cc_error("convertCipher Failed:0x%08X\n", ret);
			return 1;
		}
	}

	for (i = 0; i < sizeof(licEve); i++)
	{
		// 篡改许可任何一个字节，也会导致不可用
		memcpy(&licEve, &licA2B, sizeof(licA2B));
		((uint8 *)&licEve)[i] ++;

		// 使用许可转换Alice的S1
		ret = convertCipher(&key_Alice, &userKey_Bob, &licEve, &s1_Kc_Alice, &s1_Ku_Alice_to_Bob, &licA2B);
		if (ret == CC_ERROR_SUCCESS)
		{
			cc_error("convertCipher Failed:0x%08X\n", ret);
			return 1;
		}
	}

	return 0;
}

int main()
{
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


	if (0x00 != OpenDevice())
	{
		printf("OpenDevice err\n");
		return 1;
	}

	test_positive();
	printf("积极测试完成！\n");
	test_negtive();
	printf("消极测试完成！\n");

	CloseDevice();
	printf("测试完成！\n");
	getchar();

end:

	if (eckey)
		EC_KEY_free(eckey);

	if (group)
		SM2_Cleanup(group);
	
	return 0;
}
