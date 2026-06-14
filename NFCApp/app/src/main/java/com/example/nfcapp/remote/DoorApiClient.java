package com.example.nfcapp.remote;

import android.util.Log;

import com.example.nfcapp.crypto.ChallengeSigner;
import com.example.nfcapp.util.HexUtils;

import org.json.JSONObject;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

/**
 * Client HTTP pentru comunicarea cu ESP32-ul de control acces.
 *
 * Flow:
 *   1. requestChallenge() → GET /api/challenge → primeste nonce
 *   2. Telefonul construieste mesaj (nonce + door_id + action)
 *   3. Telefonul semneaza mesajul cu ChallengeSigner (cheia TEE)
 *   4. openDoor() → POST /api/open cu mesaj + semnatura
 *   5. ESP32 verifica ECDSA si raspunde granted/denied
 *
 * Refoloseste acelasi ChallengeSigner ca AccessHceService (NFC).
 * Un singur mecanism criptografic, doua transporturi.
 */
public class DoorApiClient {

    private static final String TAG = "DoorApiClient";
    private static final MediaType JSON_MEDIA = MediaType.parse("application/json");

    private final String baseUrl;
    private final ChallengeSigner signer;
    private final OkHttpClient http;

    public DoorApiClient(String baseUrl, ChallengeSigner signer) {
        this.baseUrl = baseUrl.endsWith("/")
                ? baseUrl.substring(0, baseUrl.length() - 1)
                : baseUrl;
        this.signer = signer;
        this.http = new OkHttpClient.Builder()
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .writeTimeout(5, TimeUnit.SECONDS)
                .build();
    }

    /**
     * Rezultatul unei tentative de deschidere.
     */
    public static class Result {
        public final boolean success;
        public final String status;       // "granted" sau "denied"
        public final String reason;       // motiv daca denied
        public final long totalTimeMs;
        public final long challengeTimeMs;
        public final long signTimeMs;
        public final long openTimeMs;
        public final String nonceHex;
        public final String signatureHex;

        public Result(boolean success, String status, String reason,
                      long totalTimeMs, long challengeTimeMs, long signTimeMs, long openTimeMs,
                      String nonceHex, String signatureHex) {
            this.success = success;
            this.status = status;
            this.reason = reason;
            this.totalTimeMs = totalTimeMs;
            this.challengeTimeMs = challengeTimeMs;
            this.signTimeMs = signTimeMs;
            this.openTimeMs = openTimeMs;
            this.nonceHex = nonceHex;
            this.signatureHex = signatureHex;
        }
    }

    /**
     * Flow complet de deschidere usa.
     * RULEAZA PE BACKGROUND THREAD! Operatiile sunt blocante.
     */
    public Result openDoor(int doorId, byte action) throws Exception {
        long t0 = System.currentTimeMillis();

        // ============ Pas 1: GET challenge ============
        long tChStart = System.currentTimeMillis();
        Request challengeReq = new Request.Builder()
                .url(baseUrl + "/api/challenge")
                .get()
                .build();

        byte[] nonce;
        try (Response resp = http.newCall(challengeReq).execute()) {
            if (!resp.isSuccessful()) {
                throw new IOException("Challenge request failed: HTTP " + resp.code());
            }
            ResponseBody body = resp.body();
            if (body == null) throw new IOException("Empty challenge response");

            JSONObject json = new JSONObject(body.string());
            String nonceHex = json.getString("nonce");
            nonce = HexUtils.hexToBytes(nonceHex);

            Log.i(TAG, "Challenge primit: " + nonceHex);
        }
        long tChEnd = System.currentTimeMillis();

        // ============ Pas 2: build message + sign ============
        long tSigStart = System.currentTimeMillis();
        byte[] message = ChallengeSigner.buildMessage(nonce, doorId, action);
        byte[] signature = signer.sign(message);
        long tSigEnd = System.currentTimeMillis();

        Log.i(TAG, "Mesaj: " + HexUtils.bytesToHex(message));
        Log.i(TAG, "Semnatura (" + signature.length + "B): " + HexUtils.bytesToHex(signature));

        // ============ Pas 3: POST /api/open ============
        long tOpenStart = System.currentTimeMillis();
        // Calculeaza keyId-ul (identic cu cel din ESP32 keyStore)
        byte[] keyId = signer.getKeyManager().getKeyId();

        JSONObject payload = new JSONObject();
        payload.put("key_id", HexUtils.bytesToHex(keyId));
        payload.put("message", HexUtils.bytesToHex(message));
        payload.put("signature", HexUtils.bytesToHex(signature));

        Request openReq = new Request.Builder()
                .url(baseUrl + "/api/open")
                .post(RequestBody.create(payload.toString(), JSON_MEDIA))
                .build();

        String status, reason = "";
        boolean success;
        try (Response resp = http.newCall(openReq).execute()) {
            ResponseBody body = resp.body();
            String respText = body != null ? body.string() : "";
            Log.i(TAG, "Open response: HTTP " + resp.code() + " " + respText);

            JSONObject json = new JSONObject(respText);
            status = json.optString("status", "unknown");
            reason = json.optString("reason", "");
            success = resp.isSuccessful() && "granted".equals(status);
        }
        long tOpenEnd = System.currentTimeMillis();

        long tEnd = System.currentTimeMillis();
        return new Result(
                success, status, reason,
                tEnd - t0,
                tChEnd - tChStart,
                tSigEnd - tSigStart,
                tOpenEnd - tOpenStart,
                HexUtils.bytesToHex(nonce),
                HexUtils.bytesToHex(signature)
        );
    }
}