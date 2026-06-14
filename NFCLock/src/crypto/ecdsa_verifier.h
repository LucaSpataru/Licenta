#ifndef ECDSA_VERIFIER_H
#define ECDSA_VERIFIER_H

#include <stdint.h>
#include <stddef.h>

/**
 * Verifica o semnatura ECDSA SHA256withECDSA pe curba P-256 (secp256r1).
 * 
 * Aceasta clasa e contrapartea pe ESP32 a clasei ChallengeSigner din Android.
 * Verifica semnaturi generate de cheia hardware-backed din Android Keystore,
 * folosind cheia publica transferata prin enrollment.
 * 
 * Formatul cheii publice acceptat:
 *  - DER X.509 SubjectPublicKeyInfo (formatul produs de PublicKey.getEncoded()
 *    in Android). ~91 bytes pentru P-256.
 * 
 * Formatul semnaturii acceptat:
 *  - DER (formatul ASN.1 standard, produs de Signature.sign() in Android).
 *    ~70-72 bytes pentru P-256 (variabil din cauza encoding-ului DER).
 */
class EcdsaVerifier {
public:
    /**
     * Verifica o semnatura ECDSA.
     * 
     * @param publicKeyDer       Cheia publica in format DER X.509 SubjectPublicKeyInfo
     * @param publicKeyLen       Lungimea cheii publice
     * @param message            Mesajul care a fost semnat (in clar, va fi hash-uit intern)
     * @param messageLen         Lungimea mesajului
     * @param signatureDer       Semnatura in format DER
     * @param signatureLen       Lungimea semnaturii
     * @return true daca semnatura e valida pentru (cheia, mesaj), false altfel
     */
    static bool verify(
        const uint8_t* publicKeyDer, size_t publicKeyLen,
        const uint8_t* message, size_t messageLen,
        const uint8_t* signatureDer, size_t signatureLen
    );
};

#endif // ECDSA_VERIFIER_H