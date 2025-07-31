/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * iVRF                           *
 * ****************************** */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include <time.h>

#include "falcon.h"
#include "drbg_rng.h"

#include "cpucycles.h"

#include "inner.h"

#define LOGN 18
#define N (1 << LOGN)
#define T 100
#define LAMBDA 16
#define SEED_LENGTH 48

#define HASH_LENGTH (2 * LAMBDA)
#define MU_LENGTH (2 * LAMBDA)

#define FALCON_LOGN 9

#define BENCHMARK_ITERATION 1000

static long long keygen_falcon_cycle, eval_falcon_keygen_cycle,
	eval_falcon_sign_cycle, verify_falcon_cycle;

typedef struct {
	unsigned char hash[HASH_LENGTH];
} TREE_NODE;

void keygen(TREE_NODE *tree, AES256_CTR_DRBG_struct *s,
	    AES256_CTR_DRBG_struct *s_prime)
{
	unsigned char buf[15879];
	uint32_t i, j;
	unsigned char seed_s[SEED_LENGTH], seed_s_prime[SEED_LENGTH];
	AES256_CTR_DRBG_struct s_i, s_prime_i;
	unsigned char r_i[SEED_LENGTH];

	unsigned char pk_i[897], sk_i[1281];
	shake256_context sc_i;

	long long cycle1, cycle2;

	/* s, s_prime <-- G.Key(1^{\lambda}) */
	Zf(get_seed)(seed_s, SEED_LENGTH);
	Zf(get_seed)(seed_s_prime, SEED_LENGTH);

	drbg_randombytes_init(&s_i, seed_s, NULL, LAMBDA);
	memcpy(s, &s_i, sizeof(s_i));
	drbg_randombytes_init(&s_prime_i, seed_s_prime, NULL, LAMBDA);
	memcpy(s_prime, &s_prime_i, sizeof(s_prime_i));

	for (i = 0; i < N; i++) {
		/* Derive x_{i,0} by running G.Next on s */
		drbg_randombytes(&s_i, tree[N + i].hash, HASH_LENGTH);

		/* x_{i,j+1} = H(x_{i,j}) */
		for (j = 0; j < T - 1; j++) {
			memcpy(buf, tree[N + i].hash, HASH_LENGTH);
			SHA256(buf, HASH_LENGTH, tree[N + i].hash);
		}

		/* Derive r_i by running G.Next on s' */
		drbg_randombytes(&s_prime_i, r_i, SEED_LENGTH);

		cycle1 = cpucycles();
		/* (pk_i, sk_i) <-- Falcon.KeyGen(r_i) */
		shake256_init_prng_from_seed(&sc_i, r_i, SEED_LENGTH);
		falcon_keygen_make(&sc_i, FALCON_LOGN, sk_i,
				   FALCON_PRIVKEY_SIZE(FALCON_LOGN), pk_i,
				   FALCON_PUBKEY_SIZE(FALCON_LOGN), buf,
				   FALCON_TMPSIZE_KEYGEN(FALCON_LOGN));

		cycle2 = cpucycles();
		keygen_falcon_cycle += cycle2 - cycle1;

		/* x_{i,t}=H(x_{i,t-1},pk_i) */
		memcpy(buf, tree[N + i].hash, HASH_LENGTH);
		memcpy(buf + HASH_LENGTH, pk_i,
		       FALCON_PUBKEY_SIZE(FALCON_LOGN));
		SHA256(buf, HASH_LENGTH + FALCON_PUBKEY_SIZE(FALCON_LOGN),
		       tree[N + i].hash);
	}

	/* Merkle tree 
	 * root index = 1
	 * for index i, left child is 2*i, right child is 2*i+1 
	 * for index i, its sibling is i^1, its parent is i>>1 */
	for (i = N; i >= 2; i >>= 1) {
		for (j = i >> 1; j < i; j++) {
			memcpy(buf, tree[2 * j].hash, HASH_LENGTH);
			memcpy(buf + HASH_LENGTH, tree[2 * j + 1].hash,
			       HASH_LENGTH);
			SHA256(buf, 2 * HASH_LENGTH, tree[j].hash);
		}
	}
}

void keyupd(AES256_CTR_DRBG_struct *s, AES256_CTR_DRBG_struct *s_prime)
{
	unsigned char buf[SEED_LENGTH];

	/* (s, s') <-- (G.Next(s), G.Next(s')) */
	drbg_randombytes(s, buf, HASH_LENGTH);
	drbg_randombytes(s_prime, buf, SEED_LENGTH);
}

void eval(unsigned char *v, unsigned char *y, TREE_NODE *ap, unsigned char *pk,
	  unsigned char *sig, size_t *sig_len, const unsigned char *mu1,
	  const unsigned char *mu2, const uint32_t i_in, const uint32_t j_in,
	  const AES256_CTR_DRBG_struct *s,
	  const AES256_CTR_DRBG_struct *s_prime, const TREE_NODE *tree)
{
	unsigned char buf[39943];
	uint32_t i, j;
	AES256_CTR_DRBG_struct s_in, s_prime_in;
	unsigned char r[SEED_LENGTH];

	unsigned char sk[1281];
	shake256_context sc_key, sc_sig;

	long long cycle1, cycle2, cycle3;

	/* Parse sk_av=(s_i, x_{i,0}, s_i', r_i) */
	memcpy(&s_in, s, sizeof(s_in));
	drbg_randombytes(&s_in, y, HASH_LENGTH);
	memcpy(&s_prime_in, s_prime, sizeof(s_prime_in));
	drbg_randombytes(&s_prime_in, r, SEED_LENGTH);

	/* y = H^{t-1-j}(x_{i,0}) */
	for (j = 0; j < T - 1 - j_in; j++) {
		memcpy(buf, y, HASH_LENGTH);
		SHA256(buf, HASH_LENGTH, y);
	}

	/* v = H(y,\mu1) */
	memcpy(buf, y, HASH_LENGTH);
	memcpy(buf + HASH_LENGTH, mu1, MU_LENGTH);
	SHA256(buf, HASH_LENGTH + MU_LENGTH, v);

	cycle1 = cpucycles();
	/* pk <-- Falcon.KeyGen(r_i) */
	shake256_init_prng_from_seed(&sc_key, r, SEED_LENGTH);
	falcon_keygen_make(&sc_key, FALCON_LOGN, sk,
			   FALCON_PRIVKEY_SIZE(FALCON_LOGN), pk,
			   FALCON_PUBKEY_SIZE(FALCON_LOGN), buf,
			   FALCON_TMPSIZE_KEYGEN(FALCON_LOGN));

	cycle2 = cpucycles();
	/* sig <-- Falcon.Sign(sk, \mu_2) */
	shake256_init_prng_from_system(&sc_sig);
	*sig_len = FALCON_SIG_COMPRESSED_MAXSIZE(FALCON_LOGN);
	falcon_sign_dyn(&sc_sig, sig, sig_len, FALCON_SIG_COMPRESSED, sk,
			FALCON_PRIVKEY_SIZE(FALCON_LOGN), mu2, MU_LENGTH, buf,
			FALCON_TMPSIZE_SIGNDYN(FALCON_LOGN));

	cycle3 = cpucycles();
	eval_falcon_keygen_cycle = cycle2 - cycle1;
	eval_falcon_sign_cycle = cycle3 - cycle2;

	/* copy the hash values of siblings along the path to the root for i-th leaf (index is N+i) */
	j = 0;
	for (i = N + i_in; i > 1; i >>= 1) {
		memcpy(ap[j++].hash, tree[i ^ 1].hash, HASH_LENGTH);
	}
}

uint32_t verify(const unsigned char *mu1, const unsigned char *mu2,
		const uint32_t i_in, const uint32_t j_in,
		const unsigned char *v, const unsigned char *y,
		const TREE_NODE *ap, const unsigned char *pk,
		const unsigned char *sig, const size_t sig_len,
		const TREE_NODE *root)
{
	unsigned char buf[4097];
	uint32_t i, j, i_cur;
	unsigned char v_new[HASH_LENGTH];
	unsigned char root_new[HASH_LENGTH];
	int falcon_verify_res;

	long long cycle1, cycle2;

	/* H(y,\mu1)*/
	memcpy(buf, y, HASH_LENGTH);
	memcpy(buf + HASH_LENGTH, mu1, MU_LENGTH);
	SHA256(buf, HASH_LENGTH + MU_LENGTH, v_new);

	/* if v != H(y,\mu1), return 0 */
	for (i = 0; i < HASH_LENGTH; i++) {
		if (v_new[i] != v[i]) {
			return 0;
		}
	}

	cycle1 = cpucycles();
	/* Falcon.Verify(pk, sig, \mu2) */
	falcon_verify_res = falcon_verify(sig, sig_len, FALCON_SIG_COMPRESSED,
					  pk, FALCON_PUBKEY_SIZE(FALCON_LOGN),
					  mu2, MU_LENGTH, buf,
					  FALCON_TMPSIZE_VERIFY(FALCON_LOGN));

	cycle2 = cpucycles();
	verify_falcon_cycle = cycle2 - cycle1;

	if (falcon_verify_res) {
		return 0;
	}

	/* y'=H^{j}(y) */
	memcpy(root_new, y, HASH_LENGTH);
	for (j = 0; j < j_in; j++) {
		memcpy(buf, root_new, HASH_LENGTH);
		SHA256(buf, HASH_LENGTH, root_new);
	}

	/* x_i=H(y',pk) */
	memcpy(buf, root_new, HASH_LENGTH);
	memcpy(buf + HASH_LENGTH, pk, FALCON_PUBKEY_SIZE(FALCON_LOGN));
	SHA256(buf, HASH_LENGTH + FALCON_PUBKEY_SIZE(FALCON_LOGN), root_new);

	/* compute root' by using x_{i}, index i_in, and AP */
	i_cur = i_in;
	for (i = 0; i < LOGN; i++) {
		/* if i-th LSB of i_in is 1, then for i-th node on the path to the root, its parent has hash value H(AP || x), where x is the hash value of this node and AP is some hash value from the AuthPath i.e. this node's sibling */
		if (i_cur & 1) {
			memcpy(buf, ap[i].hash, HASH_LENGTH);
			memcpy(buf + HASH_LENGTH, root_new, HASH_LENGTH);
		}
		/* otherwise, this node's parent has hash value H(x || AP) */
		else {
			memcpy(buf, root_new, HASH_LENGTH);
			memcpy(buf + HASH_LENGTH, ap[i].hash, HASH_LENGTH);
		}
		SHA256(buf, 2 * HASH_LENGTH, root_new);

		i_cur >>= 1;
	}

	/* if root' != pk_av, return 0 */
	for (i = 0; i < HASH_LENGTH; i++) {
		if (root_new[i] != root->hash[i]) {
			return 0;
		}
	}

	return 1;
}

int main()
{
	static TREE_NODE tree[2 * N];
	AES256_CTR_DRBG_struct s_orig, s_prime_orig, s, s_prime;
	uint32_t i;
	uint32_t i_in, j_in;
	unsigned char v[HASH_LENGTH], y[HASH_LENGTH];
	TREE_NODE ap[LOGN];
	unsigned char mu1[MU_LENGTH], mu2[MU_LENGTH];

	unsigned char pk[897], sig[752];
	size_t sig_len;

	long long cycle1, cycle2, cycle3, cycle4, cycle5;

	uint32_t verify_res;

	uint32_t benchmark_iteration;

	memset(tree, 0, sizeof(tree));

	cycle1 = cpucycles();
	keygen(tree, &s_orig, &s_prime_orig);
	cycle2 = cpucycles();

	printf("%lld,%lld\n", cycle2 - cycle1, keygen_falcon_cycle);

	srand(time(NULL));

	/* j = 0 */
	for (benchmark_iteration = 0; benchmark_iteration < BENCHMARK_ITERATION;
	     benchmark_iteration++) {
		memcpy(&s, &s_orig, sizeof(s));
		memcpy(&s_prime, &s_prime_orig, sizeof(s_prime));

		Zf(get_seed)(mu1, MU_LENGTH);
		Zf(get_seed)(mu2, MU_LENGTH);

		i_in = rand() % N;
		j_in = 0;

		for (i = 0; i < i_in; i++) {
			keyupd(&s, &s_prime);
		}

		cycle3 = cpucycles();
		eval(v, y, ap, pk, sig, &sig_len, mu1, mu2, i_in, j_in, &s,
		     &s_prime, tree);
		cycle4 = cpucycles();
		verify_res = verify(mu1, mu2, i_in, j_in, v, y, ap, pk, sig,
				    sig_len, tree + 1);
		cycle5 = cpucycles();

		printf("%lld,%lld,%lld,%lld,%lld,%u\n", cycle4 - cycle3,
		       eval_falcon_keygen_cycle, eval_falcon_sign_cycle,
		       cycle5 - cycle4, verify_falcon_cycle, verify_res);
	}

	/* j = t - 1 */
	for (benchmark_iteration = 0; benchmark_iteration < BENCHMARK_ITERATION;
	     benchmark_iteration++) {
		memcpy(&s, &s_orig, sizeof(s));
		memcpy(&s_prime, &s_prime_orig, sizeof(s_prime));

		Zf(get_seed)(mu1, MU_LENGTH);
		Zf(get_seed)(mu2, MU_LENGTH);

		i_in = rand() % N;
		j_in = T - 1;

		for (i = 0; i < i_in; i++) {
			keyupd(&s, &s_prime);
		}

		cycle3 = cpucycles();
		eval(v, y, ap, pk, sig, &sig_len, mu1, mu2, i_in, j_in, &s,
		     &s_prime, tree);
		cycle4 = cpucycles();
		verify_res = verify(mu1, mu2, i_in, j_in, v, y, ap, pk, sig,
				    sig_len, tree + 1);
		cycle5 = cpucycles();

		printf("%lld,%lld,%lld,%lld,%lld,%u\n", cycle4 - cycle3,
		       eval_falcon_keygen_cycle, eval_falcon_sign_cycle,
		       cycle5 - cycle4, verify_falcon_cycle, verify_res);
	}

	return 0;
}
