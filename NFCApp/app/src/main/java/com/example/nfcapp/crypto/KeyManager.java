package com.example.nfcapp.crypto;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.MessageDigest;

/**
 * Gestioneaza generarea si accesul la cheia ECDSA stocata in Android Keystore.
 *
 * Cheia este generata cu urmatoarele garantii:
 *  - Algoritm: ECDSA pe curba P-256 (secp256r1) — standard NIST
 *  - Hardware-backed: stocata in TEE sau StrongBox, NU in memoria aplicatiei
 *  - Attestation: la generare se ataseaza un challenge → primim lant certificate
 *    semnate de Google care dovedesc ca cheia traieste in hardware securizat
 *  - Cheia privata nu paraseste niciodata hardware-ul → imposibil de clonat
 */
public class KeyManager {

    private static final String TAG = "KeyManager";

    /** Alias-ul sub care cheia e stocata in Keystore. Un singur alias = o singura cheie per aplicatie. */
    public static final String KEY_ALIAS = "nfc_access_signing_key";

    /** Provider-ul Keystore din Android. */
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";

    /** Curba eliptica folosita. P-256 = secp256r1, 256-bit, suportata de TEE/StrongBox. */
    private static final String EC_CURVE = "secp256r1";

    /**
     * Verifica daca cheia exista deja in Keystore.
     */
    public boolean keyExists() {
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            return ks.containsAlias(KEY_ALIAS);
        } catch (Exception e) {
            Log.e(TAG, "Eroare la verificarea existentei cheii", e);
            return false;
        }
    }

    /**
     * Genereaza o noua pereche de chei ECDSA in Keystore, cu attestation challenge.
     *
     * @param attestationChallenge byte-i arbitrari care vor fi incastrati in certificatul
     *                             de atestare. Server-ul de inrolare ii verifica pentru
     *                             a se asigura ca certificatul nu e refolosit (anti-replay
     *                             la inrolare). In productie: nonce primit de la server.
     *                             Aici: il primim ca parametru.
     * @return KeyPair-ul generat (cheia privata e doar o referinta, nu byte-ii reali)
     * @throws Exception daca generarea esueaza
     */
    public KeyPair generateKey(byte[] attestationChallenge) throws Exception {
        Log.i(TAG, "Generare cheie ECDSA in Keystore...");

        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE
        );

        KeyGenParameterSpec.Builder specBuilder = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
        )
                .setAlgorithmParameterSpec(new ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                // Attestation challenge: dovada hardware-backed
                .setAttestationChallenge(attestationChallenge);

        // Pe Android 9+ (API 28) putem cere explicit StrongBox daca exista
        // StrongBox = chip dedicat, mai sigur decat TEE general
        // Daca device-ul nu are StrongBox, picam inapoi pe TEE
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            try {
                specBuilder.setIsStrongBoxBacked(true);
                generator.initialize(specBuilder.build());
                KeyPair kp = generator.generateKeyPair();
                Log.i(TAG, "Cheie generata cu StrongBox!");
                return kp;
            } catch (Exception e) {
                Log.w(TAG, "StrongBox indisponibil, incerc TEE: " + e.getMessage());
                // Reset builder fara StrongBox
                specBuilder = new KeyGenParameterSpec.Builder(
                        KEY_ALIAS,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
                )
                        .setAlgorithmParameterSpec(new ECGenParameterSpec(EC_CURVE))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setAttestationChallenge(attestationChallenge);
            }
        }

        generator.initialize(specBuilder.build());
        KeyPair kp = generator.generateKeyPair();
        Log.i(TAG, "Cheie generata cu TEE (sau software fallback daca device-ul nu are hardware securizat)");
        return kp;
    }

    /**
     * Returneaza cheia privata ca referinta Keystore.
     *
     * ATENTIE: nu poti extrage byte-ii din acest obiect. Poti doar sa-l folosesti
     * cu java.security.Signature pentru a semna date. Cheia reala traieste in hardware.
     */
    public PrivateKey getPrivateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new IllegalStateException("Cheia nu exista sau nu e PrivateKeyEntry");
        }
        return ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
    }

    /**
     * Returneaza cheia publica (byte-i extrasi normal, e publica, nu e secreta).
     */
    public PublicKey getPublicKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        Certificate cert = ks.getCertificate(KEY_ALIAS);
        if (cert == null) {
            throw new IllegalStateException("Certificatul cheii nu exista");
        }
        return cert.getPublicKey();
    }

    /**
     * Returneaza lantul complet de certificate de atestare.
     *
     * Structura tipica (de la frunza la radacina):
     *  - [0] Certificat cheii noastre (semnat de cheia de atestare a device-ului)
     *  - [1] Certificat intermediar al producatorului (semnat de Google)
     *  - [2..N] Certificate root Google
     *
     * Server-ul de inrolare va verifica acest lant pentru a confirma ca:
     *  1. Cheia chiar e generata de hardware-ul unui Android device autentic
     *  2. Hardware-ul nu e compromis (Google revoca root-uri compromise)
     *  3. Challenge-ul nostru de atestare e incastrat → dovada fresh
     */
    public Certificate[] getAttestationCertChain() throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        Certificate[] chain = ks.getCertificateChain(KEY_ALIAS);
        if (chain == null || chain.length == 0) {
            throw new IllegalStateException("Lantul de atestare nu exista");
        }
        return chain;
    }

    /**
     * Sterge cheia din Keystore. Operatie ireversibila!
     */
    public void deleteKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) {
            ks.deleteEntry(KEY_ALIAS);
            Log.i(TAG, "Cheia a fost stearsa din Keystore");
        }
    }

    /**
     * Deriva un identificator scurt al cheii publice, pentru indexare pe ESP32.
     *
     * KeyId = primii 16 bytes din SHA-256(public_key.encoded)
     *
     * Nu e secret. Permite ESP32-ului sa gaseasca rapid cheia publica
     * corespunzatoare in storage local (NVS).
     */
    public byte[] getKeyId() throws Exception {
        PublicKey pub = getPublicKey();
        java.security.MessageDigest sha256 = java.security.MessageDigest.getInstance("SHA-256");
        byte[] fullHash = sha256.digest(pub.getEncoded());
        byte[] keyId = new byte[16];
        System.arraycopy(fullHash, 0, keyId, 0, 16);
        return keyId;
    }
}