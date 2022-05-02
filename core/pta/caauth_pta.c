#include <kernel/misc.h>
#include <kernel/pseudo_ta.h>
#include "caauth_pta.h"
#include <crypto/crypto.h>
#include <utee_defines.h>
#include <string.h>
// #include <stdlib.h>

/*
 * Trusted Application Entry Points
 */
static TEE_Result open_session(uint32_t nParamTypes __unused,
			       TEE_Param pParams[TEE_NUM_PARAMS] __unused,
			       void **ppSessionContext __unused)
{
	DMSG("open session SUCCESS...");
	return TEE_SUCCESS;
}

static TEE_Result set_ca_uuid(uint32_t types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_Result res;
	char *obj_id = params[0].memref.buffer;
	size_t obj_id_sz = params[0].memref.size;

	if (types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	DMSG("obj_id -> %s,  obj_id_sz -> %d", obj_id, obj_id_sz * sizeof(char));
	thread_get_tsd()->ca_uuid = malloc(obj_id_sz);
	// DMSG("malloc");
	// thread_get_tsd()->ca_uuid = (char *)malloc(obj_id_sz);
	strcpy(&thread_get_tsd()->ca_uuid, obj_id);
	// DMSG("memcpy");
	// // TEE_CA_UUID ca_uuid = CA_SECURE_STORAGE_UUID;
	// memcpy(&thread_get_tsd()->ca_uuid, obj_id, obj_id_sz + 1);
	// thread_get_tsd()->ca_uuid = obj_id;
	DMSG("thread_get_tsd()->ca_uuid -> %s", 
		thread_get_tsd()->ca_uuid);

	return TEE_SUCCESS;
}

static TEE_Result authenticate_elf(uint32_t types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	char *elf_va = params[0].memref.buffer, *caauth_va = params[1].memref.buffer;
	size_t elf_len = params[0].memref.size, caauth_len = params[1].memref.size;
	TEE_Result res;
	struct caauthdata *caauthdata = (struct caauthdata *)caauth_va;
	char *sig;
	void *hash_ctx = NULL;
	char dig[32];
	struct rsa_public_key key;
	uint32_t e = TEE_U32_TO_BIG_ENDIAN(ta_pub_key_exponent);

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	DMSG("CAAUTH img sz = %d", caauthdata->img_size);
	DMSG("CAAUTH HASH algo = %x", caauthdata->hash_algo);
	DMSG("CAAUTH SIG algo = %x", caauthdata->sig_algo);
	DMSG("CAAUTH digest size = %d", caauthdata->digest_len);
	DMSG("EXPECTED ELF len after extraction = %d", elf_len);

	/* caauth header check */
	if (elf_len != caauthdata->img_size)
		return TEE_ERROR_BAD_PARAMETERS;
	EMSG("#################");
	if (EXPECTED_HASH_ALGO != caauthdata->hash_algo)
		return TEE_ERROR_BAD_PARAMETERS;
	EMSG("#################");
	if (EXPECTED_SIG_ALGO != caauthdata->sig_algo)
		return TEE_ERROR_BAD_PARAMETERS;

	//EMSG("#################");
	sig = caauth_va + sizeof(struct caauthdata);

	/* Message Digest */
	res = crypto_hash_alloc_ctx(&hash_ctx, caauthdata->hash_algo);
	if (res != TEE_SUCCESS)
		goto error_exit;
	res = crypto_hash_init(hash_ctx);
	if (res != TEE_SUCCESS)
		goto error_free_hash;
	res = crypto_hash_update(hash_ctx, caauthdata,
				     sizeof(struct caauthdata));
	if (res != TEE_SUCCESS)
		goto error_free_hash;
	res = crypto_hash_update(hash_ctx, elf_va,
				     elf_len);
	if (res != TEE_SUCCESS)
		goto error_free_hash;
	res = crypto_hash_final(hash_ctx, dig, 32);
	if (res != TEE_SUCCESS)
		goto error_free_hash;

	EMSG("GOT :: %x %x %x %x", dig[0], dig[1], dig[2], dig[3]);
	
	thread_get_tsd()->ca_uuid = malloc(33);
	for(int i = 0; i < 32; i ++){
		thread_get_tsd()->ca_uuid[i] = dig[i];
	}
	thread_get_tsd()->ca_uuid[32] = '\0';
	// DMSG("thread_get_tsd() -> %s", thread_get_tsd()->ca_uuid);
	/* Signature Verification */
	res = crypto_acipher_alloc_rsa_public_key(&key, caauthdata->sig_len);
	if (res)
		EMSG("crypto_acipher_alloc_rsa_public_key");
		goto error_free_hash;
	res = crypto_bignum_bin2bn((uint8_t *)&e, sizeof(e), key.e);
	if (res)
		EMSG("crypto_bignum_bin2bn((uint8_t *)&e, sizeof(e), key.e)");
		goto error_cipher_free;

	res = crypto_bignum_bin2bn(ta_pub_key_modulus, ta_pub_key_modulus_size,
				   key.n);
	if (res)
		EMSG("crypto_bignum_bin2bn(ta_pub_key_modulus, ta_pub_key_modulus_size, key.n)");
		goto error_cipher_free;

	res = crypto_acipher_rsassa_verify(caauthdata->sig_algo, &key, -1,
					   dig, 32,
					   sig, caauthdata->sig_len);

	if (res)
		EMSG("crypto_acipher_rsassa_verify");

error_cipher_free:
	crypto_acipher_free_rsa_public_key(&key);
error_free_hash:
	crypto_hash_free_ctx(hash_ctx);
error_exit:
	return res;
}
static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID __unused, uint32_t nParamTypes __unused,
				 TEE_Param pParams[TEE_NUM_PARAMS] __unused)
{

	switch (nCommandID) {
	case CAAUTH_CMD_AUTHENTICATE_ELF:
		return authenticate_elf(nParamTypes, pParams);
	case CAAUTH_CMD_IS_CAAUTH_SUPP:
		return TEE_SUCCESS;
	case CAAUTH_CMD_SET_CA_UUID:
		return set_ca_uuid(nParamTypes, pParams);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}
pseudo_ta_register(.uuid = PTA_CAAUTH_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_SECURE_DATA_PATH,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);