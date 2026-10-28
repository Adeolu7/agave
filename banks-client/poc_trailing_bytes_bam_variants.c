/* poc_trailing_bytes_bam_variants.c  :    BAM client proof verifiers accept trailing bytes.
 *
 * Two verifier paths used by the BAM client are exercised:
 *   - paillier_commitment_exponent_zkpok_verify (Damgard-Fujisaki, signing path)
 *   - range_proof_paillier_large_factors_quadratic_zkp_verify (setup path)
 * Each valid proof is verified first, then the same proof with 4 appended
 * bytes. Truncation is also checked, showing the length check is one-sided.
 *
 * Build (target commit 00ae08b, after cmake/make of libcosigner):
 *   gcc -O2 -Iinclude -Ibuild/src/common poc_trailing_bytes_bam_variants.c \
 *       -Lbuild/src/common -lcosigner -lcrypto -lm \
 *       -Wl,-rpath,$(realpath build/src/common) -o poc_trailing_bytes_bam_variants
 */
#include "crypto/paillier/paillier.h"
#include "crypto/paillier_commitment/paillier_commitment.h"
#include "crypto/commitments/damgard_fujisaki.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail = 0;

static void check(const char* name, long result, long expected)
{
    int ok = (result == expected);
    printf("%-60s -> %s (%ld)%s\n", name,
           ok ? "as expected" : "UNEXPECTED", result,
           ok ? "" : "   <-- MISMATCH");
    fflush(stdout);
    if (!ok) fail = 1;
}

static void show(const char* name, long result)
{
    printf("%-60s -> %ld\n", name, result);
    fflush(stdout);
}

int main(void)
{
    const uint8_t aad[] = "Test AAD";
    const uint32_t aad_len = 8;

    /* ---------- 1. Damgard-Fujisaki small-group exponent proof ---------- */
    {
        damgard_fujisaki_public_t* df_pub = NULL;
        damgard_fujisaki_private_t* df_priv = NULL;
        paillier_commitment_private_key_t* pc_priv = NULL;
        elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
        elliptic_curve256_scalar_t x;
        elliptic_curve256_point_t X;
        paillier_with_range_proof_t* proof = NULL;

        if (!algebra ||
            damgard_fujisaki_generate_key_pair(1024, 2, &df_pub, &df_priv) != RING_PEDERSEN_SUCCESS ||
            paillier_commitment_generate_private_key(2048, &pc_priv) != PAILLIER_SUCCESS)
        {
            puts("DF setup failed");
            return 2;
        }
        const paillier_commitment_public_key_t* pc_pub = paillier_commitment_private_cast_to_public(pc_priv);

        if (algebra->rand(algebra, &x) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS ||
            algebra->generator_mul(algebra, &X, &x) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS ||
            paillier_commitment_encrypt_with_exponent_zkpok_generate(df_pub, pc_priv, algebra,
                                                                     aad, aad_len, x, sizeof(x), 1, &proof) != ZKP_SUCCESS)
        {
            puts("DF proof generation failed");
            return 3;
        }

        check("Damgard-Fujisaki: valid proof",
              paillier_commitment_exponent_zkpok_verify(df_priv, pc_pub, algebra, aad, aad_len, &X,
                                                        (const const_paillier_with_range_proof_t*)proof, 1),
              ZKP_SUCCESS);

        paillier_with_range_proof_t with_suffix = *proof;
        with_suffix.proof_len = proof->proof_len + 4;
        with_suffix.serialized_proof = malloc(with_suffix.proof_len);
        memcpy(with_suffix.serialized_proof, proof->serialized_proof, proof->proof_len);
        memcpy(with_suffix.serialized_proof + proof->proof_len, "\xde\xad\xbe\xef", 4);
        check("Damgard-Fujisaki: +4 trailing bytes",
              paillier_commitment_exponent_zkpok_verify(df_priv, pc_pub, algebra, aad, aad_len, &X,
                                                        (const const_paillier_with_range_proof_t*)&with_suffix, 1),
              ZKP_SUCCESS);

        paillier_with_range_proof_t truncated = *proof;
        truncated.proof_len = proof->proof_len - 1;
        show("Damgard-Fujisaki: truncated by 1 byte",
             paillier_commitment_exponent_zkpok_verify(df_priv, pc_pub, algebra, aad, aad_len, &X,
                                                       (const const_paillier_with_range_proof_t*)&truncated, 1));

        free(with_suffix.serialized_proof);
        range_proof_free_paillier_with_range_proof(proof);
        paillier_commitment_free_private_key(pc_priv);
        damgard_fujisaki_free_public(df_pub);
        damgard_fujisaki_free_private(df_priv);
        algebra->release(algebra);
    }

    /* ---------- 2. quadratic large-factors proof ---------- */
    {
        paillier_public_key_t* pub = NULL;
        paillier_private_key_t* priv = NULL;
        uint32_t len = 0;

        if (paillier_generate_key_pair(512, &pub, &priv) != PAILLIER_SUCCESS)
        {
            puts("quadratic setup failed");
            return 2;
        }
        puts("generating quadratic proof (safe prime d)...");
        fflush(stdout);

        long st = range_proof_paillier_large_factors_quadratic_zkp_generate(
            priv, aad, aad_len, NULL, 0, NULL, 0, &len);
        if (st != ZKP_INSUFFICIENT_BUFFER || len == 0)
        {
            printf("quadratic size query failed: %ld len=%u\n", st, len);
            return 3;
        }
        uint8_t* buf = malloc(len);
        st = range_proof_paillier_large_factors_quadratic_zkp_generate(
            priv, aad, aad_len, NULL, 0, buf, len, NULL);
        if (st != ZKP_SUCCESS)
        {
            printf("quadratic proof generation failed: %ld\n", st);
            return 3;
        }

        check("quadratic: valid proof",
              range_proof_paillier_large_factors_quadratic_zkp_verify(pub, aad, aad_len, buf, len),
              ZKP_SUCCESS);

        uint8_t* with_suffix = malloc(len + 4);
        memcpy(with_suffix, buf, len);
        memcpy(with_suffix + len, "\xde\xad\xbe\xef", 4);
        check("quadratic: +4 trailing bytes",
              range_proof_paillier_large_factors_quadratic_zkp_verify(pub, aad, aad_len, with_suffix, len + 4),
              ZKP_SUCCESS);

        show("quadratic: truncated by 1 byte",
             range_proof_paillier_large_factors_quadratic_zkp_verify(pub, aad, aad_len, buf, len - 1));

        free(with_suffix);
        free(buf);
        paillier_free_private_key(priv);
        paillier_free_public_key(pub);
    }

    printf("\n%s\n", fail ? "RESULT: MISMATCH  :    investigate"
                           : "RESULT: both variants accept trailing bytes");
    return fail;
}
