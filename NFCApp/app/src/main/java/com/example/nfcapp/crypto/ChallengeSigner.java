package com.example.nfcapp.crypto;

import android.util.Log;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Semneaza mesaje cu cheia ECDSA hardware-backed gestionata de KeyManager.
 *
 * Mesajul semnat are formatul:
 *   message = nonce (32B) || door_id (4B) || action_code (1B)
 * Total: 37 bytes
 *
 * Semnatura este produsa cu algoritmul SHA256withECDSA si returnata
 * in format DER (standardul X9.62). Lungimea variaza intre 70-72 bytes
 * pentru P-256 (din cauza encoding-ului DER cu lungimi variabile pentru r si s).
 *
 * Aceeasi clasa este folosita atat pentru autentificarea prin NFC
 * cat si pentru deschiderea remote prin HTTP — un singur mecanism criptografic,
 * doua transporturi.
 */
public class ChallengeSigner {

    private static final String TAG = "ChallengeSigner";
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    public static final int NONCE_LENGTH = 32;
    public static final int DOOR_ID_LENGTH = 4;
    public static final int ACTION_CODE_LENGTH = 1;
    public static final int MESSAGE_LENGTH = NONCE_LENGTH + DOOR_ID_LENGTH + ACTION_CODE_LENGTH; // 37

    /** Coduri de actiune — extensibile in viitor */
    public static final byte ACTION_OPEN_DOOR = 0x01;
    public static final byte ACTION_ENROLL = 0x02;

    private final KeyManager keyManager;

    public ChallengeSigner(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    /**
     * Construieste mesajul ce va fi semnat, din componentele sale.
     *
     * @param nonce nonce-ul primit de la ESP32 (exact 32 bytes)
     * @param doorId identificatorul usii (4 bytes, ex: int convertit)
     * @param actionCode tipul de actiune (1 byte, vezi constantele ACTION_*)
     * @return byte array de 37 bytes cu mesajul concatenat
     */
    public static byte[] buildMessage(byte[] nonce, int doorId, byte actionCode) {
        if (nonce == null || nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException(
                    "Nonce trebuie sa fie exact " + NONCE_LENGTH + " bytes, primit: "
                            + (nonce == null ? "null" : nonce.length));
        }

        ByteBuffer buffer = ByteBuffer.allocate(MESSAGE_LENGTH);
        buffer.put(nonce);
        buffer.putInt(doorId); // big-endian, 4 bytes
        buffer.put(actionCode);
        return buffer.array();
    }

    /**
     * Semneaza un mesaj folosind cheia privata din Keystore.
     *
     * Atentie: aceasta metoda declanseaza o operatie in TEE/StrongBox.
     * Latenta tipica: 10-200 ms. NU apela de pe UI thread in productie.
     *
     * @param message mesajul de semnat (in mod normal construit cu buildMessage)
     * @return semnatura in format DER (~70-72 bytes pentru P-256)
     */
    public byte[] sign(byte[] message) throws Exception {
        PrivateKey privateKey = keyManager.getPrivateKey();

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message);

        long start = System.nanoTime();
        byte[] sig = signature.sign();
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        Log.i(TAG, "Semnatura generata in " + elapsedMs + " ms, lungime: " + sig.length + " bytes");
        return sig;
    }

    /**
     * Convenience method: construieste mesajul si-l semneaza intr-un singur apel.
     */
    public byte[] signChallenge(byte[] nonce, int doorId, byte actionCode) throws Exception {
        byte[] message = buildMessage(nonce, doorId, actionCode);
        return sign(message);
    }

    public KeyManager getKeyManager() {
        return keyManager;
    }

    /**
     * Verifica o semnatura folosind cheia publica din Keystore.
     *
     * Aceasta metoda exista DOAR pentru testare locala — in arhitectura reala,
     * ESP32-ul verifica semnatura cu cheia publica pe care a primit-o la inrolare.
     *
     * @return true daca semnatura e valida pentru mesajul dat
     */
    public boolean verifyLocally(byte[] message, byte[] signatureBytes) throws Exception {
        PublicKey publicKey = keyManager.getPublicKey();

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(signatureBytes);
    }
}
