#include <ta_pub_key.h>

#define PTA_CAAUTH_UUID {0x42116460, 0xb389, 0x4013, \
        { 0xa2, 0x20, 0xb4, 0x3e, 0x92, 0x33, 0x8a, 0x3d} }

#define PTA_NAME "caauth.pta"

#define EXPECTED_HASH_ALGO TEE_ALG_SHA256
#define EXPECTED_SIG_ALGO TEE_ALG_RSASSA_PKCS1_V1_5_SHA256

#define CAAUTH_CMD_SET_CA_UUID		0
#define CAAUTH_CMD_AUTHENTICATE_ELF 1
#define CAAUTH_CMD_IS_CAAUTH_SUPP 	2

struct caauthdata {
	uint32_t magic;
	uint32_t img_size;
	uint32_t hash_algo;
	uint32_t sig_algo;
	uint16_t digest_len;
	uint16_t sig_len;
};