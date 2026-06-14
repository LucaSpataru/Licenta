package com.example.nfcapp.nfc;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import com.example.nfcapp.crypto.ChallengeSigner;
import com.example.nfcapp.crypto.KeyManager;
import com.example.nfcapp.util.HexUtils;

import java.util.Arrays;

/**
 service hce pentru partea de autentificare nfc
 select aid - raspuns 9000
 get challenge - raspuns keyId + 9000
 sign challenge - raspuns signature + 9000
 */
public class AccessHceService extends HostApduService {
    private static final String TAG = "AccessHceService";

    //stariile pentru procesul nfc
    private enum State { IDLE, AID_SELECTED, CHALLENGE_RECEIVED }
    private State state = State.IDLE;

    //nonceul primit in sesiunea respectiva
    private byte[] currentNonce = null;

    //keyManager si ChallengeSigner sunt folosite pentru semnare si autentificare
    private KeyManager keyManager;
    private ChallengeSigner signer;

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {
        Log.i(TAG, "APDU primit (" + commandApdu.length + "B): " + HexUtils.bytesToHex(commandApdu));

        if (commandApdu.length < 4) {
            return logAndReturn(ApduCommands.SW_WRONG_LENGTH);
        }

        if (keyManager == null) {
            keyManager = new KeyManager();
            signer = new ChallengeSigner(keyManager);
        }

        if (!keyManager.keyExists()) {
            Log.e(TAG, "Cheia nu e generata. Trebuie generata din UI.");
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
            Log.e(TAG, "Eroare la procesare APDU", e);
            return logAndReturn(ApduCommands.SW_INTERNAL_ERROR);
        }
    }
    //functii pentru comanda apdu
    //handle select
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
        Log.i(TAG, "AID selectat, state=AID_SELECTED");
        return logAndReturn(ApduCommands.SW_SUCCESS);
    }

    /**
     GET CHALLENGE: reader trimite un nonce de 32B, telefonul raspunde cu KeyId.
     format command:  80 10 00 00 20 nonce
     format response: keyId 90 00
     */
    private byte[] handleGetChallenge(byte[] apdu) throws Exception {
        if (state != State.AID_SELECTED && state != State.CHALLENGE_RECEIVED) {
            Log.w(TAG, "GET CHALLENGE in stare invalida: " + state);
            return logAndReturn(ApduCommands.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Format asteptat: CLA INS P1 P2 Lc Data
        if (apdu.length < 5 + ChallengeSigner.NONCE_LENGTH) {
            Log.w(TAG, "GET CHALLENGE: APDU prea scurt, primit " + apdu.length + ", asteptat " + (5 + ChallengeSigner.NONCE_LENGTH));
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
     SIGN CHALLENGE: reader trimite mesajul complet, telefonul raspunde cu signature.
     format command:  80 20 00 00 25 message
     format response: DER signature 90 00
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

        // primii 32B din message trebuie sa fie nonceul primit anterior
        byte[] noncePart = Arrays.copyOfRange(message, 0, ChallengeSigner.NONCE_LENGTH);
        if (!Arrays.equals(noncePart, currentNonce)) {
            Log.e(TAG, "Nonce din mesaj nu se potriveste cu cel primit la GET CHALLENGE!");
            Log.e(TAG, "  Asteptat: " + HexUtils.bytesToHex(currentNonce));
            Log.e(TAG, "  Primit:   " + HexUtils.bytesToHex(noncePart));
            return logAndReturn(ApduCommands.SW_CONDITIONS_NOT_SATISFIED);
        }

        long start = System.nanoTime();
        byte[] signature = signer.sign(message);
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        Log.i(TAG, "Semnatura generata in " + elapsedMs + " ms (" + signature.length + "B): " + HexUtils.bytesToHex(signature));

        //sesiunea s-a incheiat, urmatoarea va trebui sa reia de la AID
        state = State.AID_SELECTED;
        currentNonce = null;

        return logAndReturn(ApduCommands.response(signature, ApduCommands.SW_SUCCESS));
    }

    //functii ajutatoare
    private byte[] logAndReturn(byte[] response) {
        Log.i(TAG, "Raspuns (" + response.length + "B): " + HexUtils.bytesToHex(response));
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