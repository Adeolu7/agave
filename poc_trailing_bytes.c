/* poc_trailing_bytes.c :   proof-verification paths accept trailing bytes.
 *
 * For each of three verifier paths, a valid proof is generated and verified
 * first; then 4 arbitrary bytes are appended and the same verifier is called.
 * A truncated proof is rejected everywhere, showing the length check is
 * one-sided (lower bound only).
 *
 * Build (target commit 00ae08b, after cmake/make of libcosigner):
 *   gcc -O2 -Iinclude -Ibuild/src/common poc_trailing_bytes.c \
 *       -Lbuild/src/common -lcosigner /usr/lib/x86_64-linux-gnu/libcrypto.a \
 *       -lzstd -lz -ldl -pthread -lm \
 *       -Wl,-rpath,$(pwd)/build/src/common -o poc_trailing_bytes
 */
#include "crypto/commitments/ring_pedersen.h"
#include "crypto/paillier/paillier.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail = 0;

static void check(const char* name, zero_knowledge_proof_status result, zero_knowledge_proof_status expected)
{
    printf("%-58s -> %s (%d)%s\n", name,
           result == expected ? "as expected" : "UNEXPECTED", result,
           result == expected ? "" : "   <-- MISMATCH");
    if (result != expected) fail = 1;
}

/* append 4 bytes to a paillier_with_range_proof_t (deep copy) */
static paillier_with_range_proof_t append_bytes(const paillier_with_range_proof_t* proof)
{
    paillier_with_range_proof_t out = *proof;
    out.proof_len = proof->proof_len + 4;
    out.serialized_proof = malloc(out.proof_len);
    memcpy(out.serialized_proof, proof->serialized_proof, proof->proof_len);
    memcpy(out.serialized_proof + proof->proof_len, "\xde\xad\xbe\xef", 4);
    return out;
}

int main(void)
{
    ring_pedersen_public_t *rp_pub = NULL;
    ring_pedersen_private_t *rp_priv = NULL;
    paillier_public_key_t *paillier_pub = NULL;
    paillier_private_key_t *paillier_priv = NULL;
    elliptic_curve256_algebra_ctx_t *algebra = NULL;
    const uint8_t aad[] = "trailing-byte validation";

    if (ring_pedersen_generate_key_pair(1024, &rp_pub, &rp_priv))
    {
        puts("ring-pedersen keygen failed");
        return 2;
    }
    if (paillier_generate_key_pair(2048, &paillier_pub, &paillier_priv))
    {
        puts("paillier keygen failed");
        return 2;
    }
    algebra = elliptic_curve256_new_secp256k1_algebra();
    if (!algebra)
    {
        puts("algebra failed");
        return 2;
    }

    /* - 1. exponent range proof - */
    {
        paillier_with_range_proof_t *proof = NULL;
        elliptic_curve256_scalar_t x;
        elliptic_curve256_point_t X;

        if (algebra->rand(algebra, &x) || algebra->generator_mul(algebra, &X, &x) ||
            range_proof_paillier_encrypt_with_exponent_zkpok_generate(
                rp_pub, paillier_pub, algebra, aad, sizeof(aad) - 1, &x, 0, &proof))
        {
            puts("exponent proof generation failed");
            return 3;
        }

        paillier_with_range_proof_t with_suffix = append_bytes(proof);
        paillier_with_range_proof_t truncated = *proof;
        truncated.proof_len = proof->proof_len - 1;

        check("exponent zkpok: valid proof",
              range_proof_exponent_zkpok_verify(rp_priv, paillier_pub, algebra, aad, sizeof(aad) - 1, &X, proof, 1, 0),
              ZKP_SUCCESS);
        check("exponent zkpok + 4 trailing bytes accepted",
              range_proof_exponent_zkpok_verify(rp_priv, paillier_pub, algebra, aad, sizeof(aad) - 1, &X, &with_suffix, 1, 0),
              ZKP_SUCCESS);
        check("exponent zkpok truncated by 1 byte rejected",
              range_proof_exponent_zkpok_verify(rp_priv, paillier_pub, algebra, aad, sizeof(aad) - 1, &X, &truncated, 1, 0),
              ZKP_INVALID_PARAMETER);

        range_proof_free_paillier_with_range_proof(proof);
        free(with_suffix.serialized_proof);
    }

    /* - 2. Diffie-Hellman range proof - */
    {
        paillier_with_range_proof_t *proof = NULL;
        elliptic_curve256_scalar_t x, a, b, ab, abx;
        elliptic_curve256_point_t X, A, B;

        /* The generator proves X = (a*b + x)*G, not X = x*G. */
        if (algebra->rand(algebra, &x) || algebra->rand(algebra, &a) || algebra->rand(algebra, &b) ||
            algebra->mul_scalars(algebra, &ab, a, sizeof(a), b, sizeof(b)) ||
            algebra->add_scalars(algebra, &abx, ab, sizeof(ab), x, sizeof(x)) ||
            algebra->generator_mul(algebra, &X, &abx) ||
            algebra->generator_mul(algebra, &A, &a) ||
            algebra->generator_mul(algebra, &B, &b) ||
            range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(
                rp_pub, paillier_pub, algebra, aad, sizeof(aad) - 1, &x, &a, &b, 0, &proof))
        {
            puts("DH proof generation failed");
            return 3;
        }

        paillier_with_range_proof_t with_suffix = append_bytes(proof);
        paillier_with_range_proof_t truncated = *proof;
        truncated.proof_len = proof->proof_len - 1;

        check("DH zkpok: valid proof",
              range_proof_diffie_hellman_zkpok_verify(rp_priv, paillier_pub, algebra, aad, sizeof(aad) - 1, &X, &A, &B, proof, 1, 0),
              ZKP_SUCCESS);
        check("DH zkpok + 4 trailing bytes accepted",
              range_proof_diffie_hellman_zkpok_verify(rp_priv, paillier_pub, algebra, aad, sizeof(aad) - 1, &X, &A, &B, &with_suffix, 1, 0),
              ZKP_SUCCESS);
        check("DH zkpok truncated by 1 byte rejected",
              range_proof_diffie_hellman_zkpok_verify(rp_priv, paillier_pub, algebra, aad, sizeof(aad) - 1, &X, &A, &B, &truncated, 1, 0),
              ZKP_INVALID_PARAMETER);

        range_proof_free_paillier_with_range_proof(proof);
        free(with_suffix.serialized_proof);
    }

    /* - 3. Paillier large-factors proof - */
    {
        uint8_t buffer[4096];
        uint32_t real_len = 0;

        zero_knowledge_proof_status gen = range_proof_paillier_large_factors_zkp_generate(
            paillier_priv, rp_pub, aad, sizeof(aad) - 1, 0, buffer, sizeof(buffer), &real_len);
        if (gen != ZKP_SUCCESS || real_len == 0 || real_len > sizeof(buffer))
        {
            printf("large-factors proof generation failed (%d, len %u)\n", gen, real_len);
            return 3;
        }

        uint8_t with_suffix[sizeof(buffer) + 4];
        memcpy(with_suffix, buffer, real_len);
        memcpy(with_suffix + real_len, "\xde\xad\xbe\xef", 4);

        check("large-factors zkp: valid proof",
              range_proof_paillier_large_factors_zkp_verify(paillier_pub, rp_priv, aad, sizeof(aad) - 1, 0, buffer, real_len),
              ZKP_SUCCESS);
        check("large-factors zkp + 4 trailing bytes accepted",
              range_proof_paillier_large_factors_zkp_verify(paillier_pub, rp_priv, aad, sizeof(aad) - 1, 0, with_suffix, real_len + 4),
              ZKP_SUCCESS);
        check("large-factors zkp truncated by 1 byte rejected",
              range_proof_paillier_large_factors_zkp_verify(paillier_pub, rp_priv, aad, sizeof(aad) - 1, 0, buffer, real_len - 1),
              ZKP_INVALID_PARAMETER);
    }

    printf("\n%s\n", fail ? "RESULT: MISMATCH :   investigate"
           : "RESULT: exponent, DH, and large-factors proofs accept trailing bytes; truncation rejected everywhere (one-sided check)");
    return fail;
}
