package com.example.nfcapp.crypto;

import android.util.Log;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 semneaza mesaje cu cheia ECDSA hardware-backed gestionata de KeyManager.
 message = nonce || door_id || action_code
 semnatura este produsa cu algoritmul SHA256withECDSA si returnata in format DER
 folosit pentru autentificarea nfc + autentificarea remote
 */
public class ChallengeSigner {

    private static final String TAG = "ChallengeSigner";
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    public static final int NONCE_LENGTH = 32;
    public static final int DOOR_ID_LENGTH = 4;
    public static final int ACTION_CODE_LENGTH = 1;
    public static final int MESSAGE_LENGTH = NONCE_LENGTH + DOOR_ID_LENGTH + ACTION_CODE_LENGTH; // 37

    //coduri de actiune
    public static final byte ACTION_OPEN_DOOR = 0x01;
    private final KeyManager keyManager;
    public ChallengeSigner(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    /**
     construieste mesajul ce trebuie semnat
     */
    public static byte[] buildMessage(byte[] nonce, int doorId, byte actionCode) {
        if (nonce == null || nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException(
                    "Nonce trebuie sa fie exact " + NONCE_LENGTH + " bytes, primit: "
                            + (nonce == null ? "null" : nonce.length));
        }
        ByteBuffer buffer = ByteBuffer.allocate(MESSAGE_LENGTH);
        buffer.put(nonce);
        buffer.putInt(doorId);
        buffer.put(actionCode);
        return buffer.array();
    }

    /**
     semneaza un mesaj folosind cheia privata din Keystore.
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

    public KeyManager getKeyManager() {
        return keyManager;
    }

    /**
     testare locala pentru AccessHceService - comanda apdu
     */
    public boolean verifyLocally(byte[] message, byte[] signatureBytes) throws Exception {
        PublicKey publicKey = keyManager.getPublicKey();
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(signatureBytes);
    }
}
