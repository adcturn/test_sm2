#include <stdio.h>
#include <string.h>
#include <time.h>
#include <Windows.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "libsenc.h"
#include "sm2.h"


/***********************************����-��Կ����-**********************************/
/***********************************����-��Կ����-**********************************/

#define RTC_TIME_PIN_CODE					"\x00\x11\x22\x33\x44\x55\x66\x77" //PIN��
#define RTC_TIME_PIN_CODE_LEN				8								   //PIN�볤��
#define DEFAULT_SM2_SIGN_USER_ID			"1234567812345678"				   //Ĭ��SM2�û�ID
#define DEFAULT_SM2_SIGN_USER_ID_LEN		16								   //Ĭ��SM2�û�ID����
#define cc_error printf

#define FLAG								0x00000001				//����-��Կ�����������ݽṹ��־λ�������ò���
#define SM2_PUBKEY_LEN						64						//SM2��Կ����
#define SM2_PRIKEY_LEN						32						//SM2˽Կ����

//֤��·��
#define	ROOT_CERT_PATH						"./֤��/root.cer"		//��֤��
#define	ROOT_PRIKEY_PATH					"./֤��/root.pri"		//��˽Կ
#define	CA_CERT_PATH						"./֤��/ca.cer"			//�м�CA֤��
#define	CA_PRIKEY_PATH						"./֤��/ca.pri"			//�м�CA˽Կ
#define	FIRMAIL_CERT_PATH					"./֤��/firmail.cer"		//Firmail�������豸֤��
#define	KEYBAG1_CERT_PATH					"./֤��/keybag1.cer"		//keybag1�������豸֤�� ��ӦDog
#define	KEYBAG2_CERT_PATH					"./֤��/keybag2.cer"		//keybag2�������豸֤�� ��ӦCat

SENCryptCardList gDevList;											//�忨�б�
HANDLE dHandle;														//�忨���
EC_GROUP *group = NULL;												//SM2ǩ����ǩ�����õ��ı���
EC_KEY	*eckey = NULL;												//SM2ǩ����ǩ�����õ��ı���

//֤�黺�漰����
uint8_t cacert[2048] = { 0 };
uint8_t firmailcert[2048] = { 0 };
uint8_t keybagDogcert[2048] = { 0 };
uint8_t keybagCatcert[2048] = { 0 };
uint32_t ca_certlen = 0;
uint32_t firmail_certlen = 0;
uint32_t keybagDog_certlen = 0;
uint32_t keybagCat_certlen = 0;

//��������			��userkey.c�ж���
extern uint8_t pubkey_dog[65];					//keybag_dog SM2��Կ
extern uint8_t prikey_dog[32];					//keybag_dog SM2˽Կ

extern uint8_t pubkey_cat[65];					//keybag_cat SM2��Կ
extern uint8_t prikey_cat[32];					//keybag_cat SM2˽Կ

extern uint8_t pubkey_firmail[65];				//firmail SM2��Կ
extern uint8_t prikey_firmail[32];				//firmail SM2˽Կ

extern uint8_t pubkey_jmj[65];					//���ܻ� SM2��Կ
extern uint8_t prikey_jmj[32];					//���ܻ� SM2˽Կ

extern uint8_t pubkey_AccessCode[65];			//AccessCode SM2��Կ  �������
extern uint8_t prikey_AccessCode[32];			//AccessCode SM2˽Կ  �������

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

//sm2ǩ�������ʹ��
const UINT8 TAG_CLASS_CONTEXT = 0xA0;
const UINT8 TAG_INTEGER = 0x02;
const UINT8 TAG_BIT_STRING = 0x03;
const UINT8 TAG_OCTET_STRING = 0x04;
const UINT8 TAG_OID = 0x06;
const UINT8 TAG_SEQUENCE = 0x30;

//*������eccDerEncodeSignature
//*���ܣ�sm2ǩ��Der����
//*��������
//*���ڣ�2018/12/14  by ZhangTao
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

//*������eccDerDecodeSignature
//*���ܣ�sm2ǩ��Der����
//*��������
//*���ڣ�2018/12/13  by ZhangTao
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

//*������sm2SignMsg
//*���ܣ�sm2ǩ��
//*������prikey		˽Կ
//		 prikeylen	˽Կ����
//		 pubkey		��Կ
//		 pubkeylen	��Կ����
//		 msg		��Ϣ����
//		 msglen		��Ϣ���ĳ���
//		 sig		ǩ��	 
//*���ڣ�2018/12/13  by ZhangTao
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

	//��Կ����ժҪ
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

	//˽Կǩ��
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

//*������sm2Verify
//*���ܣ�sm2��ǩ
//*������pubkey		��Կ
//		 pubkeylen	��Կ����
//		 msg		��Ϣ����
//		 msglen		��Ϣ���ĳ���
//		 sig		ǩ��	 
//*���ڣ�2018/12/14  by ZhangTao
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

	//��Կbyte����תhex�ַ���
	bn2hex(pubkey, pubkeylen, pkey);
	//��Կhex�ַ���תEC_POINT				group��ȫ�ֱ���EC_GROUP
	ecPubkey = EC_POINT_hex2point(group, pkey, ecPubkey, NULL);
	//ͨ��EC_POINT����EC_KEY�Ĺ�Կ          eckey��ȫ�ֱ���EC_KEY
	EC_KEY_set_public_key(eckey, ecPubkey);

	//��������ժҪ
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
	//sm2ǩ��der���룬��ǩ�ӿ��õ���der������ǩ��
	dersiglen = sizeof(dersig);
	eccDerEncodeSignature(sig, 64, dersig, (UINT16*)&dersiglen);
	//��ǩ������1�ɹ�������0ʧ��,��һ������Ϊ����
	ret = SM2_verify(1, digest, digestlen, dersig, dersiglen, eckey);
	if (ret != 1)
	{
		cc_error("SM2_verify Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	return 0;
}

//*������sm2EncMsg
//*���ܣ�sm����
//*������pubkey		��Կ
//		 pubkeylen	��Կ����
//		 msg		��Ϣ�����ģ�
//		 msglen		��Ϣ�����ģ�����
//		 cipher		����
//*���ڣ�2018/12/13  by ZhangTao
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

	//��Կbyte����תhex�ַ���
	bn2hex(pubkey, pubkeylen, pkey);
	//��Կhex�ַ���תEC_POINT				group��ȫ�ֱ���EC_GROUP
	ecPubkey = EC_POINT_hex2point(group, pkey, ecPubkey, NULL);
	//ͨ��EC_POINT����EC_KEY�Ĺ�Կ          eckey��ȫ�ֱ���EC_KEY
	EC_KEY_set_public_key(eckey, ecPubkey); 

	//SM2����
	ret = SM2_encrypt_with_recommended(cipher, &cipherlen, msg, msglen, eckey);
	if (ret != 1)
	{
		cc_error("SM2_encrypt_with_recommended Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	return 0;
}

//*������constructKeyChainReq
//*���ܣ����촴��keychain�����
//*������req			keychain���������
//		 KeyChainID	keychain ID
//		 ACpubkey	access code ��Կ
//		 ACpubkeylen	access code ��Կ����
//		 prikey		firmail������˽Կ
//		 prikeylen	firmail������˽Կ����
//		 pubkey		firmail��������Կ
//		 pubkeylen	firmail��������Կ����
//*���ڣ�2018/12/13  by ZhangTao
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
	req->Flags = FLAG;//���Ǽ����㷨Flag,����ܻ��޹أ����⸳ֵ
	req->TimeStamp = (uint32_t)time(NULL);
	memcpy(req->ID, KeyChainID, KEYCHAIN_ID_LEN);
	memset(req->KeyBagID, 0, KEYBAG_ID_LEN);
	memcpy(req->AccessCodePubKey, ACpubkey, ACpubkeylen);

	return sm2SignMsg(prikey, prikeylen, pubkey, pubkeylen, req, sizeof(KeychainCreateReq)-256, req->Signature);
}

//*������constructBindCode
//*���ܣ��������֤�����ݰ�
//*������BindCode		����֤�����ݰ�
//		 KeyBagID		keybag ID
//		 PhoneNumber	�绰����
//		 BindCode_Plain	����֤������
//		 jmjpubkey		���ܻ���Կ
//		 jmjpubkeylen	���ܻ���Կ����
//		 kbprikey		keybag˽Կ
//		 kbprikeylen	keybag˽Կ����
//		 kbpubkey		keybag��Կ
//		 kbpubkeylen	keybag��Կ����
//*���ڣ�2018/12/13  by ZhangTao
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
	BindCode->Flags = FLAG;//���Ǽ����㷨Flag,����ܻ��޹أ����⸳ֵ
	BindCode->TimeStamp = (uint32_t)time(NULL);
	memcpy(BindCode->KeyBagID, KeyBagID, BINDCODE_PLAIN_LEN);
	memcpy(BindCode->PhoneNumber, PhoneNumber, PHONE_NUMBER_LEN);

	if (sm2EncMsg(jmjpubkey, jmjpubkeylen, BindCode_Plain, BINDCODE_PLAIN_LEN, BindCode->BindCode))
		return 1;
	if (sm2SignMsg(kbprikey, kbprikeylen, kbpubkey, kbpubkeylen, BindCode, sizeof(KeybagBindCode)-256, BindCode->Signature))
		return 1;

	return 0;
}

//*������constructCircleReq
//*���ܣ�����Circle�����
//*������req				Circle�����
//		 KeyBagID		keybag ID
//		 PhoneNumber	�绰����
//		 BindCode_Plain	����֤������
//		 jmjpubkey		���ܻ���Կ
//		 jmjpubkeylen	���ܻ���Կ����
//		 tbprikey		ͬ��˽Կ	��keybag)
//		 tbprikeylen	ͬ��˽Կ���ȣ�keybag)
//		 tbpubkey		ͬ����Կ	��keybag)
//		 tbpubkeylen	ͬ����Կ���ȣ�keybag)
//*���ڣ�2018/12/13  by ZhangTao
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
	req->Flags = FLAG;//���Ǽ����㷨Flag,����ܻ��޹أ����⸳ֵ
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

//*������constructCircleReq
//*���ܣ�����Circle�����
//*������JCApprove		����Circle������
//		 KeyBagID		keybag ID
//		 PhoneNumber	�绰����
//		 uuid			ȫ��Ψһ��ʶ��
//		 BindCode_Plain	����֤������
//		 KeyBagIDApprover	������keybag ID
//		 newpubkey		��ͬ����Կ�������keybag��
//		 newpubkeylen	��ͬ����Կ���ȣ������keybag��
//		 jmjpubkey		���ܻ���Կ
//		 jmjpubkeylen	���ܻ���Կ����
//		 Approverprikey		������keybag˽Կ	��keybag)
//		 Approverprikeylen	������keybag˽Կ���ȣ�keybag)
//		 Approverpubkey		������keybag��Կ	��keybag)
//		 Approverpubkeylen	������keybag��Կ���ȣ�keybag)
//*���ڣ�2018/12/13  by ZhangTao
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
	JCApprove->Flags = FLAG;//���Ǽ����㷨Flag,����ܻ��޹أ����⸳ֵ
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


//*������readcert
//*���ܣ���ȡCA֤�飬Firmail�������豸֤��
//		 keybag1֤��,keybag2֤��
//*��������
//*���ڣ�2018/12/13  by ZhangTao
int readcert()
{
	FILE *fp = NULL;
	//��ȡCA֤��
	fp = fopen(CA_CERT_PATH, "rb");
	if (!fp){
		printf("��CA֤��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	ca_certlen = fread(cacert, sizeof(uint8_t), sizeof(cacert), fp);
	if (!ca_certlen){
		printf("��ȡCA֤��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	fclose(fp);
	//��ȡFIRMAIL֤��
	fp = fopen(FIRMAIL_CERT_PATH, "rb");
	if (!fp){
		printf("��FIRMAIL֤��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	firmail_certlen = fread(firmailcert, sizeof(uint8_t), sizeof(firmailcert), fp);
	if (!firmail_certlen){
		printf("��ȡFIRMAIL֤��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	fclose(fp);
	//��ȡkeybag1֤��
	fp = fopen(KEYBAG1_CERT_PATH, "rb");
	if (!fp){
		printf("��KEYBAG1֤��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	keybagDog_certlen = fread(keybagDogcert, sizeof(uint8_t), sizeof(keybagDogcert), fp);
	if (!keybagDog_certlen){
		printf("��ȡKEYBAG1֤��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	fclose(fp);
	//��ȡkeybag1֤��
	fp = fopen(KEYBAG2_CERT_PATH, "rb");
	if (!fp){
		printf("��KEYBAG2֤��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	keybagCat_certlen = fread(keybagCatcert, sizeof(uint8_t), sizeof(keybagCatcert), fp);
	if (!keybagCat_certlen){
		printf("��ȡKEYBAG2֤��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	fclose(fp);
	
	return 0;
}

//*������test_init
//*���ܣ����Գ�ʼ������
//*��������
//*���ڣ�2018/12/18  by ZhangTao
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

	//��ȡ�豸�б�
	SENC_NewDevList(&gDevList);
	flag = SENC_GetDevList(&gDevList);
	if (gDevList.DevNums == 0){
		printf("δ���ּ��ܰ忨��Line:%d\n", __LINE__);
		SENC_FreeDevList(&gDevList);
		goto end;
	}

	//���豸
	flag = SENC_Open(gDevList.devs[0], &dHandle);
	if (flag != SENC_SUCCESS){
		printf("�������ܰ忨ʧ�ܣ�������Ϊ��0x%.8x��Line:%d\n", flag, __LINE__);
		SENC_FreeDevList(&gDevList);
		goto end;
	}

	//����ʱ��
	uint64_t rtcTime = time(NULL);
	flag = SENC_DataProtector_SetRTCTime(dHandle, (uint8_t*)RTC_TIME_PIN_CODE, RTC_TIME_PIN_CODE_LEN, &rtcTime);
	if (flag != SENC_SUCCESS){
		printf("����RTCʱ��ʧ�ܣ�������Ϊ��0x%.8x��Line:%d\n", flag, __LINE__);
		SENC_FreeDevList(&gDevList);
		goto end;
	}

	//��ȡʱ��
	rtcTime = time(NULL);
	uint64_t rtcTime2 = 0;
	flag = SENC_DataProtector_GetRTCTime(dHandle, &rtcTime2);
	if (flag != SENC_SUCCESS){
		printf("��ȡRTCʱ��ʧ�ܣ�������Ϊ��0x%.8x��Line:%d\n", flag, __LINE__);
		SENC_FreeDevList(&gDevList);
		goto end;
	}

	//��ȡ֤��
	if (readcert()){
		printf("��ȡ֤��ʧ�ܣ�\n");
		goto end;
	}
	printf("��ȡ֤��ɹ���\n");

	return 0;

end:
	return 1;
}

//*������test_keymanage_all
//*���ܣ���Կ��������ҵ��ӿ��������̲���
//*��������
//*���ڣ�2018/12/17  by ZhangTao
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

	//1 ����KeyChain
	//����KeyChain��������
	constructKeyChainReq(&KCCreateReq_Dog, KEY_CHAIN_ID_DOG, pubkey_AccessCode + 1, SM2_PUBKEY_LEN, prikey_firmail, 
						  SM2_PRIKEY_LEN, pubkey_firmail, SM2_PUBKEY_LEN + 1);
	//����KeyChain
	ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReq_Dog, sizeof(KCCreateReq_Dog), cacert, ca_certlen, firmailcert, 
										 firmail_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
	if (ret != SENC_SUCCESS){//Ԥ��KeyChain�����ɹ�
		cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//��ǩKeyChainCreateCode
	ret = sm2Verify(pubkey_jmj, SM2_PUBKEY_LEN + 1, &KCCreateCode_Dog, 
		sizeof(KCCreateCode_Dog)-sizeof(KCCreateCode_Dog.Signature), KCCreateCode_Dog.Signature);
	if (ret){
		cc_error("KeyChainCreateCode SM2_Verify Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	
	//2 ����Circle
	//�������֤��    Dog����Circle�İ���֤��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1, 
						prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert, 
								   keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//Ԥ��ǩ������֤��ɹ�
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//������֤���еĵ绰�����뷵�صĵ绰�����Ƿ�һ��
	if (memcmp(PHONE_NUMBER_DOG, phonenum_Dog, PHONE_NUMBER_LEN)){
		cc_error("PhoneNumber Error,Line:%d\n",__LINE__);
		return 1;
	}
	//������֤���еİ���֤�������뷵�صİ���֤�������Ƿ�һ��
	if (memcmp(BIND_CODE_DOG, bindcode_plain_Dog, BINDCODE_PLAIN_LEN)){
		cc_error("BindCodePlain Error,Line:%d\n", __LINE__);
		return 1;
	}

	//���촴��Circle�����
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
						pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog), bindcodeVeriCipher_Dog, 
									   Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//Ԥ�ڴ���Circle�ɹ�
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//��ǩCircle
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
	//���Circle������еĵ绰������Circle���еĵ绰�����Ƿ�һ��
	if (memcmp(PHONE_NUMBER_DOG, KBCircle_Dog.PhoneNumber, PHONE_NUMBER_LEN)){
		cc_error("PhoneNumber Error,Line:%d\n", __LINE__);
		return 1;
	}
	//���Circle����KeyBag��Կ�������Ƿ�ֻ��һ��KeyBag�Ĺ�Կ��Ϣ
	if (KBCircle_Dog.Count != 1){
		cc_error("KeyBag PubKey Count Error,Line:%d\n", __LINE__);
		return 1;
	}
	//�ж�Circle���Ĺ�Կ�����н��е�һ����Կ��Ϣ�е�KeyBagID�Ƿ���KeyBagDog��ID���
	if (memcmp(KEY_BAG_ID_DOG, KBCircle_Dog.kcPubKey[0].KeyBagID, KEYBAG_ID_LEN)){
		cc_error("KeyBag ID Error,Line:%d\n", __LINE__);
		return 1;
	}
	//�жϹ�Կ�����н��е�һ����Կ��Ϣ�е�ͬ����Կ�Ƿ���KeyBagDog��ͬ����Կ���
	if (memcmp(pubkey_dog + 1, KBCircle_Dog.kcPubKey[0].SyncPubKey, SM2_PUBKEY_LEN)){
		cc_error("SyncPubKey Error,Line:%d\n", __LINE__);
		return 1;
	}
	//�жϹ�Կ�����н��е�һ����Կ��Ϣ�е�Seq�Ƿ�Ϊ1
	if (KBCircle_Dog.kcPubKey[0].KeyBagSeq != 1){
		cc_error("KeyBagSeq Error,Line:%d\n", __LINE__);
		return 1;
	}

	//����Circle
	//�������֤��    Cat����Dog��Circle�İ���֤��
	constructBindCode(&KBBindCode_Cat, KEY_BAG_ID_CAT, PHONE_NUMBER_CAT, BIND_CODE_CAT, pubkey_jmj, SM2_PUBKEY_LEN + 1, 
						prikey_cat, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Cat, sizeof(KBBindCode_Cat), cacert, ca_certlen, keybagCatcert, 
								   keybagCat_certlen, bindcode_plain_Cat, phonenum_Cat, bindcodeVeriCipher_Cat, &Catverilen);
	if (ret != SENC_SUCCESS){//Ԥ��ǩ������֤��ɹ�
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//�������Circle������
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat, 
	KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1,prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat), 
									 bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//Ԥ�ڼ���Circle�ɹ�
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//������Circle������еĵ绰�������µ�Circle���еĵ绰�����Ƿ�һ��
	if (memcmp(PHONE_NUMBER_DOG, KBCircle_Dog.PhoneNumber, PHONE_NUMBER_LEN)){
		cc_error("PhoneNumber Error,Line:%d\n", __LINE__);
		return 1;
	}
	//����µ�Circle����KeyBag��Կ�������Ƿ���2��KeyBag�Ĺ�Կ��Ϣ
	if (KBCircle_Dog.Count != 2){
		cc_error("KeyBag PubKey Count Error,Line:%d\n", __LINE__);
		return 1;
	}
	//�ж��µ�Circle���Ĺ�Կ�����һ����Կ��Ϣ�е�KeyBagID�Ƿ���KeyBagDog��ID���
	if (memcmp(KEY_BAG_ID_DOG, KBCircle_Dog.kcPubKey[0].KeyBagID, KEYBAG_ID_LEN)){
		cc_error("KeyBag ID Error,Line:%d\n", __LINE__);
		return 1;
	}
	//�ж��µ�Circle���Ĺ�Կ�����һ����Կ��Ϣ�е�ͬ����Կ�Ƿ���KeyBagDog��ͬ����Կ���
	if (memcmp(pubkey_dog + 1, KBCircle_Dog.kcPubKey[0].SyncPubKey, SM2_PUBKEY_LEN)){
		cc_error("SyncPubKey Error,Line:%d\n", __LINE__);
		return 1;
	}
	//�ж��µ�Circle���Ĺ�Կ�����һ����Կ��Ϣ�е�Seq�Ƿ�Ϊ1
	if (KBCircle_Dog.kcPubKey[0].KeyBagSeq != 1){
		cc_error("KeyBagSeq Error,Line:%d\n", __LINE__);
		return 1;
	}
	//�ж��µ�Circle���Ĺ�Կ�����һ����Կ��Ϣ�е�KeyBagID�Ƿ���KeyBagDog��ID���
	if (memcmp(KEY_BAG_ID_CAT, KBCircle_Dog.kcPubKey[1].KeyBagID, KEYBAG_ID_LEN)){
		cc_error("KeyBag ID Error,Line:%d\n", __LINE__);
		return 1;
	}
	//�ж��µ�Circle���Ĺ�Կ�����һ����Կ��Ϣ�е�ͬ����Կ�Ƿ���KeyBagDog��ͬ����Կ���
	if (memcmp(pubkey_cat + 1, KBCircle_Dog.kcPubKey[1].SyncPubKey, SM2_PUBKEY_LEN)){
		cc_error("SyncPubKey Error,Line:%d\n", __LINE__);
		return 1;
	}
	//�ж��µ�Circle���Ĺ�Կ�����һ����Կ��Ϣ�е�Seq�Ƿ�Ϊ1
	if (KBCircle_Dog.kcPubKey[1].KeyBagSeq != 2){
		cc_error("KeyBagSeq Error,Line:%d\n", __LINE__);
		return 1;
	}

	free(KBCircle_Dog.kcPubKey);
	free(KBCircle_Cat.kcPubKey);
	free(KBCircleCommon.kcPubKey);
	return 0;
}

//*������test_keymanage_positive
//*���ܣ���Կ��������ҵ��ӿڻ�������
//*��������
//*���ڣ�2018/12/14  by ZhangTao
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
	////// ���� ����KeyChain
	////////////////////////////////////////////////////////////////////////
#pragma region
	//1 ��ȷ��KeyChain��������
	//����KeyChain��������
	constructKeyChainReq(&KCCreateReq_Dog, KEY_CHAIN_ID_DOG, pubkey_AccessCode + 1, SM2_PUBKEY_LEN, prikey_firmail,
		SM2_PRIKEY_LEN, pubkey_firmail, SM2_PUBKEY_LEN + 1);
	//����KeyChain
	int lentemp = sizeof(KCCreateReq_Dog);
	ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReq_Dog, sizeof(KCCreateReq_Dog), cacert, ca_certlen,
		firmailcert, firmail_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
	if (ret != SENC_SUCCESS){//Ԥ��KeyChain�����ɹ�
		cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//2 ʹ�ô����firmail������˽Կǩ��KeyChain���������
	//����KeyChain��������
	constructKeyChainReq(&KCCreateReq_Dog, KEY_CHAIN_ID_DOG, pubkey_AccessCode + 1, SM2_PUBKEY_LEN, prikey_jmj,
		SM2_PRIKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1);
	//����KeyChain
	ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReq_Dog, sizeof(KCCreateReq_Dog), cacert, ca_certlen,
		firmailcert, firmail_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
	if (ret == SENC_SUCCESS){//Ԥ��KeyChain����ʧ��
		cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//3 �����firmail������֤��
	//����KeyChain��������
	constructKeyChainReq(&KCCreateReq_Dog, KEY_CHAIN_ID_DOG, pubkey_AccessCode + 1, SM2_PUBKEY_LEN, prikey_firmail,
		SM2_PRIKEY_LEN, pubkey_firmail, SM2_PUBKEY_LEN + 1);
	//����KeyChain
	ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReq_Dog, sizeof(KCCreateReq_Dog), cacert, ca_certlen,
		keybagDogcert, keybagDog_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
	if (ret == SENC_SUCCESS){//Ԥ��KeyChain����ʧ��
		cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
#pragma endregion

	////////////////////////////////////////////////////////////////////////
	////// ���� ǩ������֤��
	////////////////////////////////////////////////////////////////////////
#pragma region
	//4 ��ȷ��ǩ��BindCode
	//�������֤��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//Ԥ��ǩ������֤��ɹ�
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//5 ʹ�ô���ĵ绰����ǩ��KeyBind
	//�������֤��                                   ����ĵ绰����
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_CAT, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//Ԥ��ǩ������֤��ɹ�
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//6 ʹ�ô���ļ��ܰ忨֤�����BindCode����
	//�������֤��																	����ļ��ܰ忨֤��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_firmail, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret == SENC_SUCCESS){//Ԥ��ǩ������֤��ʧ��
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//7 ʹ�ô����keybag˽Կǩ��
	//�������֤��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_cat, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);//�����keybag˽Կ
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret == SENC_SUCCESS){//Ԥ��ǩ������֤��ʧ��
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//8 ʹ�ô����keybag֤��
	//�������֤��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��																					�����keybag֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagCatcert,
		keybagCat_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret == SENC_SUCCESS){//Ԥ��ǩ������֤��ʧ��
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
#pragma endregion

	////////////////////////////////////////////////////////////////////////
	////// ���� ����Circle
	////////////////////////////////////////////////////////////////////////
#pragma region
	//9 ��ȷ�ش���Circle
	//�������֤��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//Ԥ��ǩ������֤��ɹ�
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//���촴��Circle�����
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//Ԥ�ڴ���Circle�ɹ�
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//10 ʹ�ô������֤��
	//���촴��Circle�����													  ����İ���֤��
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_CAT,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڴ���Circleʧ��
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//11 ʹ�ô����keybag��Կ
	//���촴��Circle�����													  
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);//�����keybag��Կ
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڴ���Circleʧ��
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//12 ʹ�ô����keybag˽Կǩ��
	//���촴��Circle�����													  
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_cat, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);//�����keybag˽Կ
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڴ���Circleʧ��
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//13 ʹ�ô���ĵ绰����
	//���촴��Circle�����									����ĵ绰����
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_CAT, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//Ԥ�ڴ���Circle�ɹ�
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//14 ʹ�ô����keybagID
	//���촴��Circle�����					�����keybagID
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_CAT, PHONE_NUMBER_CAT, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//Ԥ�ڴ���Circle�ɹ�
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
#pragma endregion

	////////////////////////////////////////////////////////////////////////
	////// ���� ����Circle
	////////////////////////////////////////////////////////////////////////
#pragma region
	//15 ��ȷ�ؼ���Circle    Cat����Dog��Circle
	//�������֤��    Dog����Circle�İ���֤��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//Ԥ��ǩ������֤��ɹ�
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//���촴��Circle�����
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog), bindcodeVeriCipher_Dog,
		Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//Ԥ�ڴ���Circle�ɹ�
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//�������֤��    Cat����Dog��Circle�İ���֤��
	constructBindCode(&KBBindCode_Cat, KEY_BAG_ID_CAT, PHONE_NUMBER_CAT, BIND_CODE_CAT, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_cat, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Cat, sizeof(KBBindCode_Cat), cacert, ca_certlen, keybagCatcert,
		keybagCat_certlen, bindcode_plain_Cat, phonenum_Cat, bindcodeVeriCipher_Cat, &Catverilen);
	if (ret != SENC_SUCCESS){//Ԥ��ǩ������֤��ɹ�
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//�������Circle������
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//Ԥ�ڼ���Circle�ɹ�
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//16 ʹ�ô������֤��
	//�������Circle������																			   ����İ���֤��
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, BIND_CODE_NULL,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڼ���Circleʧ��
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//17 Catα��Dog�ĵ绰����
	//�������Circle������										  ����ĵ绰����
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_CAT, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڼ���Circleʧ��
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//18 Catα��Dog��KeyBagID
	//�������Circle������										  
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_CAT, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1,//�����KeyBagID
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڼ���Circleʧ��
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//19 Catα��Dog��˽Կ����ǩ��
	//�������Circle������										  
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_cat, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);//�����˽Կ
	//����Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڼ���Circleʧ��
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//20 ����CircleԤ��KeyBagID����Լ���Circle��Ӱ��
	//���촴��Circle�����
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_NULL, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog), bindcodeVeriCipher_Dog,
		Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//Ԥ�ڴ���Circle�ɹ�
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//�������Circle������
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڼ���Circleʧ��
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//21 ����CircleԤ���绰����Լ���Circle��Ӱ��
	//���촴��Circle�����
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_NULL, PHONE_NUMBER_NULL, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog), bindcodeVeriCipher_Dog,
		Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//Ԥ�ڴ���Circle�ɹ�
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//�������Circle������
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڼ���Circleʧ��
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

#pragma endregion

	free(KBCircle_Dog.kcPubKey);
	free(KBCircle_Cat.kcPubKey);
	free(KBCircleCommon.kcPubKey);
	return 0;
}

//*������test_keymanage_negative
//*���ܣ���Կ��������ҵ��ӿ���������
//*��������
//*���ڣ�2018/12/13  by ZhangTao
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

#pragma region ���Դ���KeyChain
	//A.���Դ���KeyChain
	//1 bad version
	//����KeyChain��������ʹ�ô���İ汾��
	KCCreateReq_Dog.Magic = MAGIC_DATA;
	KCCreateReq_Dog.Version = VERSION_CURRENT_VERSION + 1;//����İ汾��
	KCCreateReq_Dog.Flags = FLAG;//���Ǽ����㷨Flag,����ܻ��޹أ����⸳ֵ
	KCCreateReq_Dog.TimeStamp = (uint32_t)time(NULL);
	memcpy(KCCreateReq_Dog.ID, KEY_CHAIN_ID_DOG, KEYCHAIN_ID_LEN);
	memset(KCCreateReq_Dog.KeyBagID, 0, KEYBAG_ID_LEN);
	memcpy(KCCreateReq_Dog.AccessCodePubKey, pubkey_AccessCode + 1, SM2_PUBKEY_LEN);

	//firmail������˽Կǩ��
	ret = sm2SignMsg(prikey_firmail, SM2_PRIKEY_LEN, pubkey_firmail, SM2_PUBKEY_LEN + 1, &KCCreateReq_Dog,
		sizeof(KeychainCreateReq)-256, KCCreateReq_Dog.Signature);
	if (ret != 0){
		cc_error("SM2ǩ��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	//����KeyChain
	ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReq_Dog, sizeof(KCCreateReq_Dog), cacert, ca_certlen,
		firmailcert, firmail_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
	if (ret == SENC_SUCCESS){//Ԥ��KeyChain����ʧ��
		cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//2 bad signature
	//����KeyChain��������
	constructKeyChainReq(&KCCreateReq_Dog, KEY_CHAIN_ID_DOG, pubkey_AccessCode + 1, SM2_PUBKEY_LEN, prikey_firmail,
		SM2_PRIKEY_LEN, pubkey_firmail, SM2_PUBKEY_LEN + 1);
	//�۸�ǩ��
	memset(KCCreateReq_Dog.Signature, 0, sizeof(KCCreateReq_Dog.Signature));
	//����KeyChain
	ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReq_Dog, sizeof(KCCreateReq_Dog), cacert, ca_certlen,
		firmailcert, firmail_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
	if (ret == SENC_SUCCESS){//Ԥ��KeyChain����ʧ��
		cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//3 bad keychain req packet
	//����KeyChain��������
	constructKeyChainReq(&KCCreateReq_Dog, KEY_CHAIN_ID_DOG, pubkey_AccessCode + 1, SM2_PUBKEY_LEN, prikey_firmail,
		SM2_PRIKEY_LEN, pubkey_firmail, SM2_PUBKEY_LEN + 1);
	//�۸�ǩ�������������һ�ֽ�
	for (i = 0; i < (sizeof(KCCreateReq_Dog)-sizeof(KCCreateReq_Dog.Signature) + 64); i++)
	{
		memcpy(&KCCreateReqCommon, &KCCreateReq_Dog, sizeof(KCCreateReq_Dog));
		((uint8_t *)&KCCreateReqCommon)[i] ++;

		//����KeyChain
		ret = SENC_KeyManager_CreateKeyChain(dHandle, KCCreateReqCommon, sizeof(KCCreateReqCommon), cacert, ca_certlen,
			firmailcert, firmail_certlen, KEY_BAG_ID_DOG, &KCCreateCode_Dog, &len1);
		if (ret == SENC_SUCCESS){//Ԥ��KeyChain����ʧ��
			cc_error("CreateKeyChain Failed:0x%08X,Line:%d\n", ret, __LINE__);
			return 1;
		}
	}
#pragma endregion

#pragma region ����ǩ������֤��
	//B ����ǩ������֤��
	//4 bad version
	//�������֤�룬ʹ�ô���İ汾��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	KBBindCode_Dog.Version = VERSION_CURRENT_VERSION + 1;
	//dog˽Կ����ǩ��
	ret = sm2SignMsg(prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1, &KBBindCode_Dog,
		sizeof(KBBindCode_Dog)-256, KBBindCode_Dog.Signature);
	if (ret != 0){
		cc_error("SM2ǩ��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret == SENC_SUCCESS){//Ԥ��ǩ������֤��ʧ��
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//5 bad signature
	//�������֤��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//�۸�ǩ��
	memset(KBBindCode_Dog.Signature, 0, sizeof(KBBindCode_Dog.Signature));
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret == SENC_SUCCESS){//Ԥ��ǩ������֤��ʧ��
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//6 bad bindcode packet
	//�������֤��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//�۸İ���֤�������һ�ֽ�
	for (i = 0; i < (sizeof(KBBindCode_Dog)-sizeof(KBBindCode_Dog.Signature) + 64); i++)
	{
		memcpy(&KBBindCodeCommon, &KBBindCode_Dog, sizeof(KBBindCode_Dog));
		((uint8_t *)&KBBindCodeCommon)[i] ++;

		//ǩ������֤��
		ret = SENC_KeyManager_BindCode(dHandle, KBBindCodeCommon, sizeof(KBBindCodeCommon), cacert, ca_certlen, keybagDogcert,
			keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
		if (ret == SENC_SUCCESS){//Ԥ��ǩ������֤��ʧ��
			cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
			return 1;
		}
	}
#pragma endregion 

#pragma region  ���Դ���Circle
	//C ���Դ���Circle
	//7 bad version
	//�������֤��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//Ԥ��ǩ������֤��ɹ�
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//���촴��Circle�����   ����İ汾��
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	KBCreateCirReq_Dog.Version = VERSION_CURRENT_VERSION + 1;

	//dog˽Կ����ǩ��
	ret = sm2SignMsg(prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1, &KBCreateCirReq_Dog,
		sizeof(KBCreateCirReq_Dog)-256, KBCreateCirReq_Dog.Signature);
	if (ret != 0){
		cc_error("SM2ǩ��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڴ���Circleʧ��
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//8 bad bindcode
	//���촴��Circle�����,����İ���֤�룬							Ӧ��Ϊbindcode_plain_Dog
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Cat,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڴ���Circleʧ��
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//9 bad signature
	//���촴��Circle�����,�����ǩ��
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	memset(KBCreateCirReq_Dog.Signature, 0, sizeof(KBCreateCirReq_Dog.Signature));
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog),
		bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڴ���Circleʧ��
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//10 bad circle req packet
	//���촴��Circle�����
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//�۸�Circle���������һ�ֽ�
	for (i = 0; i < (sizeof(KBCreateCirReq_Dog)-sizeof(KBCreateCirReq_Dog.Signature) + 64); i++)
	{
		memcpy(&KBCreateCirReqCommon, &KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog));
		((uint8_t *)&KBCreateCirReqCommon)[i] ++;

		//����Circle
		ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReqCommon, sizeof(KBCreateCirReqCommon),
			bindcodeVeriCipher_Dog, Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
		if (ret == SENC_SUCCESS){//Ԥ�ڴ���Circleʧ��
			cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
			return 1;
		}
	}
#pragma endregion

#pragma region  ���Լ���Circle
	//D ���Լ���Circle
	//11 bad version
	//�������֤��    Dog����Circle�İ���֤��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//Ԥ��ǩ������֤��ɹ�
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//���촴��Circle�����
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog), bindcodeVeriCipher_Dog,
		Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//Ԥ�ڴ���Circle�ɹ�
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//�������֤��    Cat����Dog��Circle�İ���֤��
	constructBindCode(&KBBindCode_Cat, KEY_BAG_ID_CAT, PHONE_NUMBER_CAT, BIND_CODE_CAT, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_cat, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Cat, sizeof(KBBindCode_Cat), cacert, ca_certlen, keybagCatcert,
		keybagCat_certlen, bindcode_plain_Cat, phonenum_Cat, bindcodeVeriCipher_Cat, &Catverilen);
	if (ret != SENC_SUCCESS){//Ԥ��ǩ������֤��ɹ�
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//�������Circle������
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����İ汾�� 
	KBJoinCir_DogApproveCat.Version += 1;
	//KeyBagDog��˽Կ����ǩ��JoinCircle�����
	ret = sm2SignMsg(prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1, &KBJoinCir_DogApproveCat,
		sizeof(KBJoinCir_DogApproveCat)-256, KBJoinCir_DogApproveCat.Signature);
	if (ret != 0){
		cc_error("SM2ǩ��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	//����Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڼ���Circleʧ��
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//12 bad phonenumber
	//�������Circle������
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����ĵ绰����
	memcpy(KBJoinCir_DogApproveCat.PhoneNumber, PHONE_NUMBER_CAT, PHONE_NUMBER_LEN);
	//KeyBagDog��˽Կ����ǩ��JoinCircle�����
	ret = sm2SignMsg(prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1, &KBJoinCir_DogApproveCat,
		sizeof(KBJoinCir_DogApproveCat)-256, KBJoinCir_DogApproveCat.Signature);
	if (ret != 0){
		cc_error("SM2ǩ��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	//����Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڼ���Circleʧ��
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//13 bad Approver ID
	//�������Circle������
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//�����������ID
	memcpy(KBJoinCir_DogApproveCat.KeyBagIDApprover, KEY_BAG_ID_CAT, KEYBAG_ID_LEN);
	//KeyBagDog��˽Կ����ǩ��JoinCircle�����
	ret = sm2SignMsg(prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1, &KBJoinCir_DogApproveCat,
		sizeof(KBJoinCir_DogApproveCat)-256, KBJoinCir_DogApproveCat.Signature);
	if (ret != 0){
		cc_error("SM2ǩ��ʧ�ܣ�Line:%d\n", __LINE__);
		return 1;
	}
	//����Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڼ���Circleʧ��
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//14 bad signature
	//�������Circle������
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//�����ǩ��
	memset(KBJoinCir_DogApproveCat.Signature, 0, sizeof(KBJoinCir_DogApproveCat.Signature));
	//����Circle
	ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
		bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
	if (ret == SENC_SUCCESS){//Ԥ�ڼ���Circleʧ��
		cc_error("JoinCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	//15 bad join circle packet
	//�������Circle������
	constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_CAT, PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
		KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//�۸�Circle���������һ�ֽ�
	for (i = 0; i < (sizeof(KBJoinCir_DogApproveCat)-sizeof(KBJoinCir_DogApproveCat.Signature) + 64); i++)
	{
		memcpy(&KBJoinCirApproveCommon, &KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat));
		((uint8_t *)&KBJoinCirApproveCommon)[i] ++;

		//����Circle
		ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCirApproveCommon, sizeof(KBJoinCirApproveCommon),
			bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
		if (ret == SENC_SUCCESS){//Ԥ�ڼ���Circleʧ��
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

//*������test_keymanage_joincircle
//*���ܣ���Կ�������circle����
//*��������
//*���ڣ�2018/12/18  by ZhangTao
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

	uint8_t KEY_BAG_ID_COMMON[14][8] = { 0 };//Circle������14��

	//15 ��ȷ�ؼ���Circle    Cat����Dog��Circle
	//�������֤��    Dog����Circle�İ���֤��
	constructBindCode(&KBBindCode_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, BIND_CODE_DOG, pubkey_jmj, SM2_PUBKEY_LEN + 1,
		prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//ǩ������֤��
	ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Dog, sizeof(KBBindCode_Dog), cacert, ca_certlen, keybagDogcert,
		keybagDog_certlen, bindcode_plain_Dog, phonenum_Dog, bindcodeVeriCipher_Dog, &Dogverilen);
	if (ret != SENC_SUCCESS){//Ԥ��ǩ������֤��ɹ�
		cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}
	//���촴��Circle�����
	constructCircleReq(&KBCreateCirReq_Dog, KEY_BAG_ID_DOG, PHONE_NUMBER_DOG, bindcode_plain_Dog,
		pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
	//����Circle
	ret = SENC_KeyManager_CreateCircle(dHandle, CIRCLE_ID_DOG, KBCreateCirReq_Dog, sizeof(KBCreateCirReq_Dog), bindcodeVeriCipher_Dog,
		Dogverilen, &timestamp1, &KBCircle_Dog, &DogCirclelen);
	if (ret != SENC_SUCCESS){//Ԥ�ڴ���Circle�ɹ�
		cc_error("CreateCircle Failed:0x%08X,Line:%d\n", ret, __LINE__);
		return 1;
	}

	for (i = 0; i < 14; i++)
	{
		KEY_BAG_ID_COMMON[i][7] = i + 2;

		//�������֤��    Cat����Dog��Circle�İ���֤��
		constructBindCode(&KBBindCode_Cat, KEY_BAG_ID_COMMON[i], PHONE_NUMBER_CAT, BIND_CODE_CAT, pubkey_jmj, SM2_PUBKEY_LEN + 1,
			prikey_cat, SM2_PRIKEY_LEN, pubkey_cat, SM2_PUBKEY_LEN + 1);
		//ǩ������֤��
		ret = SENC_KeyManager_BindCode(dHandle, KBBindCode_Cat, sizeof(KBBindCode_Cat), cacert, ca_certlen, keybagCatcert,
			keybagCat_certlen, bindcode_plain_Cat, phonenum_Cat, bindcodeVeriCipher_Cat, &Catverilen);
		if (ret != SENC_SUCCESS){//Ԥ��ǩ������֤��ɹ�
			cc_error("BindCode Failed:0x%08X,Line:%d\n", ret, __LINE__);
			return 1;
		}
		//�������Circle������
		constructJoinCircle(&KBJoinCir_DogApproveCat, KEY_BAG_ID_COMMON[i], PHONE_NUMBER_DOG, KBCircle_Dog.Uuid, bindcode_plain_Cat,
			KEY_BAG_ID_DOG, pubkey_cat + 1, SM2_PUBKEY_LEN, pubkey_jmj, SM2_PUBKEY_LEN + 1, prikey_dog, SM2_PRIKEY_LEN, pubkey_dog, SM2_PUBKEY_LEN + 1);
		//����Circle
		ret = SENC_KeyManager_JoinCircle(dHandle, KBCircle_Dog, DogCirclelen, KBJoinCir_DogApproveCat, sizeof(KBJoinCir_DogApproveCat),
			bindcodeVeriCipher_Cat, Catverilen, &timestamp2, &KBCircle_Dog, &DogCirclelen);
		if (ret != SENC_SUCCESS){//Ԥ�ڼ���Circle�ɹ�
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
	//���Գ�ʼ��
	if (test_init()){
		printf("���Գ�ʼ��ʧ�ܣ�\n");
		goto end;
	}
	printf("���Գ�ʼ���ɹ���\n");
	getchar();

	//ȫ���̲���
	if (test_keymanage_all()){
		printf("��Կ����ȫ���̲���ʧ�ܣ�\n");
		goto end;
	}
	printf("��Կ����ȫ���̲��Գɹ���\n");
	getchar();


	//��������
	if (test_keymanage_positive()){
		printf("��Կ�����������ʧ�ܣ�\n");
		goto end;
	}
	printf("��Կ����������Գɹ���\n");
	getchar();

	//��������
	if (test_keymanage_negative()){
		printf("��Կ������������ʧ�ܣ�\n");
		goto end;
	}
	printf("��Կ�����������Գɹ���\n");
	getchar();

	//����Circle����
	if (test_keymanage_joincircle()){
		printf("����Circle����ʧ�ܣ�\n");
		goto end;
	}
	printf("����Circle���Գɹ���\n");

	//�ر��豸���ͷ��豸�б�
	SENC_Close(dHandle);
	SENC_FreeDevList(&gDevList);

	printf("������ɣ�\n");
	getchar();

end:
	if (eckey)
		EC_KEY_free(eckey);

	if (group)
		SM2_Cleanup(group);
	
	getchar();
	return 0;
}
