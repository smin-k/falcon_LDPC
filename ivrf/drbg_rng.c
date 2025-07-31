/* 2022-07-10: Modified by Raymond K. Zhao to adapt AES-NI */
/* Original copyright info from NIST: */
/*
NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software.
 
NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
 
You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.
*/

#include <string.h>
#include "drbg_rng.h"

#include <x86intrin.h>

void AES256_ECB(unsigned char *key, unsigned char *ctr, unsigned char *buffer);

/*
 seedexpander_init()
 ctx            - stores the current state of an instance of the seed expander
 seed           - a 32 byte random value
 diversifier    - an 8 byte diversifier
 maxlen         - maximum number of bytes (less than 2**32) generated under this seed and diversifier
 */
int seedexpander_init(AES_XOF_struct *ctx, unsigned char *seed,
		      unsigned char *diversifier, unsigned long maxlen)
{
	if (maxlen >= 0x100000000)
		return RNG_BAD_MAXLEN;

	ctx->length_remaining = maxlen;

	memcpy(ctx->key, seed, 32);

	memcpy(ctx->ctr, diversifier, 8);
	ctx->ctr[11] = maxlen % 256;
	maxlen >>= 8;
	ctx->ctr[10] = maxlen % 256;
	maxlen >>= 8;
	ctx->ctr[9] = maxlen % 256;
	maxlen >>= 8;
	ctx->ctr[8] = maxlen % 256;
	memset(ctx->ctr + 12, 0x00, 4);

	ctx->buffer_pos = 16;
	memset(ctx->buffer, 0x00, 16);

	return RNG_SUCCESS;
}

/*
 seedexpander()
    ctx  - stores the current state of an instance of the seed expander
    x    - returns the XOF data
    xlen - number of bytes to return
 */
int seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen)
{
	unsigned long offset;

	if (x == NULL)
		return RNG_BAD_OUTBUF;
	if (xlen >= ctx->length_remaining)
		return RNG_BAD_REQ_LEN;

	ctx->length_remaining -= xlen;

	offset = 0;
	while (xlen > 0) {
		if (xlen <= (16 - ctx->buffer_pos)) { // buffer has what we need
			memcpy(x + offset, ctx->buffer + ctx->buffer_pos, xlen);
			ctx->buffer_pos += xlen;

			return RNG_SUCCESS;
		}

		// take what's in the buffer
		memcpy(x + offset, ctx->buffer + ctx->buffer_pos,
		       16 - ctx->buffer_pos);
		xlen -= 16 - ctx->buffer_pos;
		offset += 16 - ctx->buffer_pos;

		AES256_ECB(ctx->key, ctx->ctr, ctx->buffer);
		ctx->buffer_pos = 0;

		//increment the counter
		for (int i = 15; i >= 12; i--) {
			if (ctx->ctr[i] == 0xff)
				ctx->ctr[i] = 0x00;
			else {
				ctx->ctr[i]++;
				break;
			}
		}
	}

	return RNG_SUCCESS;
}

static inline void KEY_256_ASSIST_1(__m128i *temp1, __m128i *temp2)
{
	__m128i temp4;
	*temp2 = _mm_shuffle_epi32(*temp2, 0xff);
	temp4 = _mm_slli_si128(*temp1, 0x4);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	temp4 = _mm_slli_si128(temp4, 0x4);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	temp4 = _mm_slli_si128(temp4, 0x4);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	*temp1 = _mm_xor_si128(*temp1, *temp2);
}

static inline void KEY_256_ASSIST_2(__m128i *temp1, __m128i *temp3)
{
	__m128i temp2, temp4;
	temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
	temp2 = _mm_shuffle_epi32(temp4, 0xaa);
	temp4 = _mm_slli_si128(*temp3, 0x4);
	*temp3 = _mm_xor_si128(*temp3, temp4);
	temp4 = _mm_slli_si128(temp4, 0x4);
	*temp3 = _mm_xor_si128(*temp3, temp4);
	temp4 = _mm_slli_si128(temp4, 0x4);
	*temp3 = _mm_xor_si128(*temp3, temp4);
	*temp3 = _mm_xor_si128(*temp3, temp2);
}

// Use whatever AES implementation you have. This uses AES-NI from:
// Intel® Advanced Encryption Standard (Intel® AES) Instructions Set - Rev 3.01
// https://software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf
//    key - 256-bit AES key
//    ctr - a 128-bit plaintext value
//    buffer - a 128-bit ciphertext value
void AES256_ECB(unsigned char *key, unsigned char *ctr, unsigned char *buffer)
{
	__m128i round_key[15];

	__m128i tmp, temp1, temp2, temp3;

	temp1 = _mm_loadu_si128((__m128i *)key);
	temp3 = _mm_loadu_si128((__m128i *)(key + 16));
	round_key[0] = temp1;
	round_key[1] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
	KEY_256_ASSIST_1(&temp1, &temp2);
	round_key[2] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	round_key[3] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
	KEY_256_ASSIST_1(&temp1, &temp2);
	round_key[4] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	round_key[5] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
	KEY_256_ASSIST_1(&temp1, &temp2);
	round_key[6] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	round_key[7] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
	KEY_256_ASSIST_1(&temp1, &temp2);
	round_key[8] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	round_key[9] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
	KEY_256_ASSIST_1(&temp1, &temp2);
	round_key[10] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	round_key[11] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
	KEY_256_ASSIST_1(&temp1, &temp2);
	round_key[12] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	round_key[13] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
	KEY_256_ASSIST_1(&temp1, &temp2);
	round_key[14] = temp1;

	tmp = _mm_loadu_si128((__m128i *)ctr);
	tmp = _mm_xor_si128(tmp, round_key[0]);
	tmp = _mm_aesenc_si128(tmp, round_key[1]);
	tmp = _mm_aesenc_si128(tmp, round_key[2]);
	tmp = _mm_aesenc_si128(tmp, round_key[3]);
	tmp = _mm_aesenc_si128(tmp, round_key[4]);
	tmp = _mm_aesenc_si128(tmp, round_key[5]);
	tmp = _mm_aesenc_si128(tmp, round_key[6]);
	tmp = _mm_aesenc_si128(tmp, round_key[7]);
	tmp = _mm_aesenc_si128(tmp, round_key[8]);
	tmp = _mm_aesenc_si128(tmp, round_key[9]);
	tmp = _mm_aesenc_si128(tmp, round_key[10]);
	tmp = _mm_aesenc_si128(tmp, round_key[11]);
	tmp = _mm_aesenc_si128(tmp, round_key[12]);
	tmp = _mm_aesenc_si128(tmp, round_key[13]);
	tmp = _mm_aesenclast_si128(tmp, round_key[14]);
	_mm_storeu_si128((__m128i *)buffer, tmp);
}

void drbg_randombytes_init(AES256_CTR_DRBG_struct *DRBG_ctx,
			   unsigned char *entropy_input,
			   unsigned char *personalization_string,
			   int security_strength)
{
	unsigned char seed_material[48];

	memcpy(seed_material, entropy_input, 48);
	if (personalization_string)
		for (int i = 0; i < 48; i++)
			seed_material[i] ^= personalization_string[i];
	memset(DRBG_ctx->Key, 0x00, 32);
	memset(DRBG_ctx->V, 0x00, 16);
	AES256_CTR_DRBG_Update(seed_material, DRBG_ctx->Key, DRBG_ctx->V);
	DRBG_ctx->reseed_counter = 1;
}

int drbg_randombytes(AES256_CTR_DRBG_struct *DRBG_ctx, unsigned char *x,
		     unsigned long long xlen)
{
	unsigned char block[16];
	int i = 0;

	while (xlen > 0) {
		//increment V
		for (int j = 15; j >= 0; j--) {
			if (DRBG_ctx->V[j] == 0xff)
				DRBG_ctx->V[j] = 0x00;
			else {
				DRBG_ctx->V[j]++;
				break;
			}
		}
		AES256_ECB(DRBG_ctx->Key, DRBG_ctx->V, block);
		if (xlen > 15) {
			memcpy(x + i, block, 16);
			i += 16;
			xlen -= 16;
		} else {
			memcpy(x + i, block, xlen);
			xlen = 0;
		}
	}
	AES256_CTR_DRBG_Update(NULL, DRBG_ctx->Key, DRBG_ctx->V);
	DRBG_ctx->reseed_counter++;

	return RNG_SUCCESS;
}

void AES256_CTR_DRBG_Update(unsigned char *provided_data, unsigned char *Key,
			    unsigned char *V)
{
	unsigned char temp[48];

	for (int i = 0; i < 3; i++) {
		//increment V
		for (int j = 15; j >= 0; j--) {
			if (V[j] == 0xff)
				V[j] = 0x00;
			else {
				V[j]++;
				break;
			}
		}
		AES256_ECB(Key, V, temp + 16 * i);
	}
	if (provided_data != NULL)
		for (int i = 0; i < 48; i++)
			temp[i] ^= provided_data[i];
	memcpy(Key, temp, 32);
	memcpy(V, temp + 32, 16);
}
