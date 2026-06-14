#include "crypto/ecdsa_verifier.h"
#include <Arduino.h>

#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/error.h"

static const char* TAG = "EcdsaVerifier";

bool EcdsaVerifier::verify(
    const uint8_t* publicKeyDer, size_t publicKeyLen,
    const uint8_t* message, size_t messageLen,
    const uint8_t* signatureDer, size_t signatureLen
) {
    int ret;
    char errBuf[128];

    // ========== Pasul 1: Hash SHA-256 al mesajului ==========
    // ECDSA semneaza un hash, nu mesajul direct. Trebuie sa producem acelasi
    // hash pe care l-a folosit Android la semnare.
    uint8_t hash[32];
    ret = mbedtls_sha256_ret(message, messageLen, hash, 0); // 0 = SHA-256 (nu SHA-224)
    if (ret != 0) {
        mbedtls_strerror(ret, errBuf, sizeof(errBuf));
        Serial.print("[");
        Serial.print(TAG);
        Serial.print("] SHA-256 failed: ");
        Serial.println(errBuf);
        return false;
    }

    // ========== Pasul 2: Parsare cheie publica din DER ==========
    // mbedTLS foloseste struct mbedtls_pk_context pentru orice tip de cheie.
    // mbedtls_pk_parse_public_key accepta formatul X.509 SubjectPublicKeyInfo
    // (exact ce produce Android cu PublicKey.getEncoded()).
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    ret = mbedtls_pk_parse_public_key(&pk, publicKeyDer, publicKeyLen);
    if (ret != 0) {
        mbedtls_strerror(ret, errBuf, sizeof(errBuf));
        Serial.print("[");
        Serial.print(TAG);
        Serial.print("] Parse public key failed: ");
        Serial.println(errBuf);
        Serial.println("  Verifica: cheia e in format DER X.509 SubjectPublicKeyInfo");
        Serial.println("  (formatul produs de Android PublicKey.getEncoded())");
        mbedtls_pk_free(&pk);
        return false;
    }

    // Sanity check: cheia trebuie sa fie ECDSA P-256
    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA)) {
        Serial.print("[");
        Serial.print(TAG);
        Serial.println("] Cheia nu e ECDSA!");
        mbedtls_pk_free(&pk);
        return false;
    }

    // ========== Pasul 3: Verificare semnatura ==========
    // mbedtls_pk_verify accepta semnatura in format DER (ce produce Android).
    // Algoritmul de hash trebuie indicat explicit (MBEDTLS_MD_SHA256).
    ret = mbedtls_pk_verify(
        &pk,
        MBEDTLS_MD_SHA256,
        hash, sizeof(hash),
        signatureDer, signatureLen
    );

    if (ret != 0) {
        mbedtls_strerror(ret, errBuf, sizeof(errBuf));
        Serial.print("[");
        Serial.print(TAG);
        Serial.print("] Signature verify FAILED: ");
        Serial.println(errBuf);
        mbedtls_pk_free(&pk);
        return false;
    }

    mbedtls_pk_free(&pk);
    Serial.print("[");
    Serial.print(TAG);
    Serial.println("] ✓ Signature verified");
    return true;
}