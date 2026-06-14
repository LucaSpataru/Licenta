package com.example.nfcapp.nfc;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import com.example.nfcapp.crypto.ChallengeSigner;
import com.example.nfcapp.crypto.KeyManager;
import com.example.nfcapp.util.HexUtils;

import java.util.Arrays;

/**
 * Service HCE care implementeaza protocolul de autentificare prin NFC.
 *
 * Flow:
 *   1. SELECT AID            — raspuns: 9000
 *   2. GET CHALLENGE (Data=nonce 32B)  — raspuns: keyId (16B) + 9000
 *   3. SIGN CHALLENGE (Data=msg 37B)   — raspuns: signature DER (~70-72B) + 9000
 *
 * State machine:
 *   IDLE → AID_SELECTED → CHALLENGE_RECEIVED → SIGNED
 *   (orice abatere de la secventa → 6985 Conditions not satisfied)
 */
public class AccessHceService extends HostApduService {
    private static final String TAG = "AccessHceService";

    /** Starile posibile ale conversatiei NFC. */
    private enum State { IDLE, AID_SELECTED, CHALLENGE_RECEIVED }
    private State state = State.IDLE;

    /** Ne tinem minte nonce-ul primit intre GET CHALLENGE si SIGN CHALLENGE. */
    private byte[] currentNonce = null;

    /** Lazy init — instantiate la primul APDU, ca service-ul sa porneasca rapid. */
    private KeyManager keyManager;
    private ChallengeSigner signer;

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {
        Log.e(TAG, "════════════════════════════════════════");
        Log.e(TAG, "processCommandApdu APELAT! Length: " + commandApdu.length);
        Log.e(TAG, "Bytes: " + HexUtils.bytesToHex(commandApdu));
        Log.e(TAG, "════════════════════════════════════════");

        Log.i(TAG, "─── APDU primit (" + commandApdu.length + "B): "
                + HexUtils.bytesToHex(commandApdu));

        if (commandApdu.length < 4) {
            return logAndReturn(ApduCommands.SW_WRONG_LENGTH);
        }

        // Lazy init
        if (keyManager == null) {
            keyManager = new KeyManager();
            signer = new ChallengeSigner(keyManager);
        }

        // Verificare: cheia trebuie sa fie generata
        if (!keyManager.keyExists()) {
            Log.e(TAG, "Cheia nu e generata! Genereaza-o din UI intai.");
            return logAndReturn(ApduCommands.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte cla = commandApdu[0];
        byte ins = commandApdu[1];

        try {
            // SELECT AID — standard ISO
            if (cla == ApduCommands.CLA_ISO && ins == ApduCommands.INS_SELECT) {
                return handleSelect(commandApdu);
            }

            // Comenzi proprietare
            if (cla == ApduCommands.CLA_PROPRIETARY) {
                switch (ins) {
                    case ApduCommands.INS_GET_CHALLENGE:
                        return handleGetChallenge(commandApdu);
                    case ApduCommands.INS_SIGN_CHALLENGE:
                        return handleSignChallenge(commandApdu);
                    default:
                        Log.w(TAG, "INS necunoscut: " + String.format("%02X", ins));
                        return logAndReturn(ApduCommands.SW_INS_NOT_SUPPORTED);
                }
            }

            Log.w(TAG, "CLA necunoscut: " + String.format("%02X", cla));
            return logAndReturn(ApduCommands.SW_INS_NOT_SUPPORTED);

        } catch (Exception e) {
            Log.e(TAG, "Eroare interna la procesare APDU", e);
            return logAndReturn(ApduCommands.SW_INTERNAL_ERROR);
        }
    }

    // ==================== HANDLERS ====================

    private byte[] handleSelect(byte[] apdu) {
        if (apdu.length < 5) return logAndReturn(ApduCommands.SW_WRONG_LENGTH);
        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc) return logAndReturn(ApduCommands.SW_WRONG_LENGTH);

        byte[] receivedAid = Arrays.copyOfRange(apdu, 5, 5 + lc);
        Log.i(TAG, "SELECT AID: " + HexUtils.bytesToHex(receivedAid));

        if (!Arrays.equals(receivedAid, ApduCommands.AID)) {
            Log.w(TAG, "AID nepotrivit");
            return logAndReturn(ApduCommands.SW_AID_NOT_FOUND);
        }

        state = State.AID_SELECTED;
        currentNonce = null;
        Log.i(TAG, "✓ AID selectat, state=AID_SELECTED");
        return logAndReturn(ApduCommands.SW_SUCCESS);
    }

    /**
     * GET CHALLENGE: reader-ul trimite un nonce de 32B, telefonul raspunde cu KeyId.
     *
     * Format command:  80 10 00 00 20 <nonce 32B>
     * Format response: <keyId 16B> 90 00
     */
    private byte[] handleGetChallenge(byte[] apdu) throws Exception {
        if (state != State.AID_SELECTED && state != State.CHALLENGE_RECEIVED) {
            Log.w(TAG, "GET CHALLENGE in stare invalida: " + state);
            return logAndReturn(ApduCommands.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Format asteptat: CLA INS P1 P2 Lc Data
        // Lc trebuie = 32 (NONCE_LENGTH)
        if (apdu.length < 5 + ChallengeSigner.NONCE_LENGTH) {
            Log.w(TAG, "GET CHALLENGE: APDU prea scurt, primit " + apdu.length
                    + "B, asteptat " + (5 + ChallengeSigner.NONCE_LENGTH));
            return logAndReturn(ApduCommands.SW_WRONG_LENGTH);
        }
        int lc = apdu[4] & 0xFF;
        if (lc != ChallengeSigner.NONCE_LENGTH) {
            Log.w(TAG, "GET CHALLENGE: Lc=" + lc + ", asteptat " + ChallengeSigner.NONCE_LENGTH);
            return logAndReturn(ApduCommands.SW_WRONG_LENGTH);
        }

        currentNonce = Arrays.copyOfRange(apdu, 5, 5 + ChallengeSigner.NONCE_LENGTH);
        Log.i(TAG, "Nonce primit: " + HexUtils.bytesToHex(currentNonce));

        byte[] keyId = keyManager.getKeyId();
        Log.i(TAG, "KeyId: " + HexUtils.bytesToHex(keyId));

        state = State.CHALLENGE_RECEIVED;
        return logAndReturn(ApduCommands.response(keyId, ApduCommands.SW_SUCCESS));
    }

    /**
     * SIGN CHALLENGE: reader trimite mesajul complet (37B), telefonul raspunde cu signature.
     *
     * Format command:  80 20 00 00 25 <message 37B>
     * Format response: <signature DER ~70-72B> 90 00
     *
     * IMPORTANT: verificam ca primii 32B din message sunt EXACT nonce-ul primit anterior.
     * Asta previne ca reader-ul (sau un atacator MITM) sa ne ceara sa semnam un nonce
     * diferit decat cel pe care l-am acceptat.
     */
    private byte[] handleSignChallenge(byte[] apdu) throws Exception {
        if (state != State.CHALLENGE_RECEIVED) {
            Log.w(TAG, "SIGN CHALLENGE in stare invalida: " + state);
            return logAndReturn(ApduCommands.SW_CONDITIONS_NOT_SATISFIED);
        }

        if (apdu.length < 5 + ChallengeSigner.MESSAGE_LENGTH) {
            return logAndReturn(ApduCommands.SW_WRONG_LENGTH);
        }
        int lc = apdu[4] & 0xFF;
        if (lc != ChallengeSigner.MESSAGE_LENGTH) {
            Log.w(TAG, "SIGN CHALLENGE: Lc=" + lc + ", asteptat " + ChallengeSigner.MESSAGE_LENGTH);
            return logAndReturn(ApduCommands.SW_WRONG_LENGTH);
        }

        byte[] message = Arrays.copyOfRange(apdu, 5, 5 + ChallengeSigner.MESSAGE_LENGTH);
        Log.i(TAG, "Mesaj de semnat: " + HexUtils.bytesToHex(message));

        // Validare: primii 32B din message trebuie sa fie nonce-ul primit anterior
        byte[] noncePart = Arrays.copyOfRange(message, 0, ChallengeSigner.NONCE_LENGTH);
        if (!Arrays.equals(noncePart, currentNonce)) {
            Log.e(TAG, "Nonce din mesaj NU se potriveste cu cel primit la GET CHALLENGE!");
            Log.e(TAG, "  Asteptat: " + HexUtils.bytesToHex(currentNonce));
            Log.e(TAG, "  Primit:   " + HexUtils.bytesToHex(noncePart));
            return logAndReturn(ApduCommands.SW_CONDITIONS_NOT_SATISFIED);
        }

        long start = System.nanoTime();
        byte[] signature = signer.sign(message);
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        Log.i(TAG, "✓ Semnatura generata in " + elapsedMs + " ms ("
                + signature.length + "B): " + HexUtils.bytesToHex(signature));

        // Reset state — sesiunea s-a incheiat, urmatoarea va trebui sa reia de la AID
        state = State.AID_SELECTED;
        currentNonce = null;

        return logAndReturn(ApduCommands.response(signature, ApduCommands.SW_SUCCESS));
    }

    // ==================== HELPERS ====================

    private byte[] logAndReturn(byte[] response) {
        Log.i(TAG, "→ Raspuns (" + response.length + "B): " + HexUtils.bytesToHex(response));
        return response;
    }

    @Override
    public void onDeactivated(int reason) {
        String reasonStr = (reason == DEACTIVATION_LINK_LOSS)
                ? "LINK_LOSS"
                : "DESELECTED";
        Log.i(TAG, "onDeactivated: " + reasonStr);
        state = State.IDLE;
        currentNonce = null;
    }
}