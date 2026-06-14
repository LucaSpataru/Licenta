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
 gestioneaza generarea si accesul la cheia ECDSA stocata in keystore.
 */
public class KeyManager {
    private static final String TAG = "KeyManager";
    /** aliasul cheii din keystore */
    public static final String KEY_ALIAS = "nfc_access_signing_key";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    /** curba eliptica folosita*/
    private static final String EC_CURVE = "secp256r1";
    /**
     verificare daca cheia exita in keystore
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
     genereaza o noua pereche de chei ECDSA in Keystore cu attestation challenge.
     */
    public KeyPair generateKey(byte[] attestationChallenge) throws Exception {
        Log.i(TAG, "Generare cheie ECDSA in Keystore");

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
                // attestation challenge - dovada hardware-backed
                .setAttestationChallenge(attestationChallenge);

        // StrongBox = mai sigur decat TEE
        // daca device-ul nu are StrongBox -> TEE
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            try {
                specBuilder.setIsStrongBoxBacked(true);
                generator.initialize(specBuilder.build());
                KeyPair kp = generator.generateKeyPair();
                Log.i(TAG, "Cheie generata cu StrongBox");
                return kp;
            } catch (Exception e) {
                Log.w(TAG, "StrongBox indisponibil, incerc TEE: " + e.getMessage());
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
        Log.i(TAG, "Cheie generata cu TEE");
        return kp;
    }

    public PrivateKey getPrivateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new IllegalStateException("Cheia nu exista sau nu e PrivateKeyEntry");
        }
        return ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
    }

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
     lantul complet de certificare de atestare
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

    public void deleteKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) {
            ks.deleteEntry(KEY_ALIAS);
            Log.i(TAG, "Cheia a fost stearsa din Keystore");
        }
    }

    /**
     identificator al cheii publice pentru indexare la esp32
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