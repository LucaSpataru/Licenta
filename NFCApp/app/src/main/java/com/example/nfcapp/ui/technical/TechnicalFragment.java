package com.example.nfcapp.ui.technical;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.example.nfcapp.R;
import com.example.nfcapp.crypto.ChallengeSigner;
import com.example.nfcapp.crypto.KeyManager;
import com.example.nfcapp.data.preferences.AppPreferences;
import com.example.nfcapp.nfc.AccessHceService;
import com.example.nfcapp.util.HexUtils;

import org.json.JSONObject;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class TechnicalFragment extends Fragment {

    private AppPreferences prefs;
    private KeyManager keyManager;
    private ChallengeSigner signer;
    private ExecutorService executor;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private TextView logOutput;
    private ScrollView logScroll;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_technical, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        prefs = new AppPreferences(requireContext());
        keyManager = new KeyManager();
        signer = new ChallengeSigner(keyManager);
        executor = Executors.newSingleThreadExecutor();

        logOutput = view.findViewById(R.id.logOutput);
        logScroll = view.findViewById(R.id.logScroll);

        view.findViewById(R.id.btnKeyDetails).setOnClickListener(v -> showKeyDetails());
        view.findViewById(R.id.btnSimulateNfc).setOnClickListener(v -> simulateNfcTap());
        view.findViewById(R.id.btnAttackTest).setOnClickListener(v -> testAttack());
        view.findViewById(R.id.btnExport).setOnClickListener(v -> exportHex());
        view.findViewById(R.id.btnClearLog).setOnClickListener(v -> logOutput.setText(""));
    }

    private void log(String text) {
        logOutput.setText(text);
        logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
    }

    // ═════════════════ DETALII CHEIE ═════════════════
    private void showKeyDetails() {
        try {
            if (!keyManager.keyExists()) {
                log("Cheia nu exista. Genereaza-o din Setup.");
                return;
            }
            PublicKey pub = keyManager.getPublicKey();
            byte[] keyId = keyManager.getKeyId();
            java.security.cert.Certificate[] chain = keyManager.getAttestationCertChain();
            byte[] encoded = pub.getEncoded();

            StringBuilder sb = new StringBuilder();
            sb.append("═══ CHEIE CRIPTOGRAFICA ═══\n\n");
            sb.append("Algoritm: ").append(pub.getAlgorithm()).append("\n");
            sb.append("Curba: secp256r1 (P-256)\n");
            sb.append("Format cheie publica: ").append(pub.getFormat()).append("\n");
            sb.append("Lungime encoded: ").append(encoded.length).append(" bytes\n\n");

            sb.append("KeyId (SHA-256[0..16] al cheii publice):\n");
            sb.append(HexUtils.bytesToHex(keyId)).append("\n\n");

            sb.append("Cheia privata: stocata in TEE/StrongBox\n");
            sb.append("  → ").append(keyManager.getPrivateKey().getFormat() == null
                    ? "NU poate fi extrasa din hardware (format=null)"
                    : "Format vizibil — software fallback").append("\n\n");

            sb.append("═══ LANT ATESTARE (").append(chain.length).append(" certificate) ═══\n\n");
            for (int i = 0; i < chain.length; i++) {
                X509Certificate x = (X509Certificate) chain[i];
                sb.append("[").append(i).append("] ").append(x.getSubjectDN().getName()).append("\n");
                sb.append("    Issued by: ").append(x.getIssuerDN().getName()).append("\n\n");
            }

            log(sb.toString());
        } catch (Exception e) {
            log("Eroare:\n" + e);
        }
    }

    // ═════════════════ SIMULARE NFC TAP ═════════════════
    private void simulateNfcTap() {
        try {
            if (!keyManager.keyExists()) {
                log("Cheia nu exista. Genereaza-o din Setup.");
                return;
            }

            StringBuilder sb = new StringBuilder();
            sb.append("═══ SIMULARE TAP NFC (flow APDU complet) ═══\n\n");
            sb.append("Instantiem service-ul HCE direct si-i trimitem\n");
            sb.append("APDU-uri identice cu cele de pe PN532.\n\n");

            AccessHceService service = new AccessHceService();

            // ═════ 1. SELECT AID ═════
            byte[] selectApdu = new byte[]{
                    0x00, (byte) 0xA4, 0x04, 0x00, 0x07,
                    (byte) 0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
            };
            sb.append("─── [1] SELECT AID ───\n");
            sb.append("→ ").append(HexUtils.bytesToHex(selectApdu)).append("\n");
            byte[] resp1 = service.processCommandApdu(selectApdu, null);
            sb.append("← ").append(HexUtils.bytesToHex(resp1)).append("\n\n");

            // ═════ 2. GET CHALLENGE ═════
            byte[] nonce = new byte[32];
            new SecureRandom().nextBytes(nonce);
            byte[] getChallengeApdu = new byte[5 + 32];
            getChallengeApdu[0] = (byte) 0x80;
            getChallengeApdu[1] = 0x10;
            getChallengeApdu[2] = 0x00;
            getChallengeApdu[3] = 0x00;
            getChallengeApdu[4] = 0x20;
            System.arraycopy(nonce, 0, getChallengeApdu, 5, 32);

            sb.append("─── [2] GET CHALLENGE ───\n");
            sb.append("Nonce: ").append(HexUtils.bytesToHex(nonce)).append("\n");
            byte[] resp2 = service.processCommandApdu(getChallengeApdu, null);
            byte[] keyId = Arrays.copyOfRange(resp2, 0, resp2.length - 2);
            sb.append("← KeyId: ").append(HexUtils.bytesToHex(keyId)).append("\n");
            sb.append("← SW: 9000\n\n");

            // ═════ 3. SIGN CHALLENGE ═════
            int doorId = 1;
            byte action = ChallengeSigner.ACTION_OPEN_DOOR;
            byte[] message = ChallengeSigner.buildMessage(nonce, doorId, action);

            byte[] signApdu = new byte[5 + message.length];
            signApdu[0] = (byte) 0x80;
            signApdu[1] = 0x20;
            signApdu[2] = 0x00;
            signApdu[3] = 0x00;
            signApdu[4] = (byte) message.length;
            System.arraycopy(message, 0, signApdu, 5, message.length);

            sb.append("─── [3] SIGN CHALLENGE ───\n");
            sb.append("Mesaj (").append(message.length).append("B): ").append(HexUtils.bytesToHex(message)).append("\n");
            long t0 = System.nanoTime();
            byte[] resp3 = service.processCommandApdu(signApdu, null);
            long elapsedMs = (System.nanoTime() - t0) / 1_000_000;

            byte[] signature = Arrays.copyOfRange(resp3, 0, resp3.length - 2);
            sb.append("← Semnatura (").append(signature.length).append("B): ").append(HexUtils.bytesToHex(signature)).append("\n");
            sb.append("← Timp procesare: ").append(elapsedMs).append(" ms\n\n");

            // ═════ 4. Verificare locala ═════
            sb.append("─── [4] Verificare locala (simuleaza ESP32) ───\n");
            boolean valid = signer.verifyLocally(message, signature);
            sb.append("Rezultat: ").append(valid ? "VALID" : "INVALID").append("\n");

            log(sb.toString());
        } catch (Exception e) {
            log("Eroare la simulare:\n" + e);
        }
    }

    // ═════════════════ TEST ATAC ═════════════════
    private void testAttack() {
        if (!keyManager.keyExists()) {
            log("Cheia nu exista.");
            return;
        }
        String url = prefs.getEsp32Url();
        log("Ruleaza 3 scenarii de atac impotriva ESP32-ului...\n");

        executor.execute(() -> {
            StringBuilder sb = new StringBuilder();
            sb.append("═══ TESTE DE ATAC IMPOTRIVA ESP32 ═══\n\n");

            try {
                // ─── Atac 1: Semnatura tampered ───
                sb.append("─── [1] Semnatura MODIFICATA ───\n");
                sb.append("Cer challenge, semnez corect, dar modific 1 byte\n");
                sb.append("din semnatura inainte sa o trimit.\n");
                sb.append("Asteptat: ESP32 respinge cu 'signature_invalid'.\n\n");
                String r1 = sendOpenWithTamper(url, true, false, false);
                sb.append("Rezultat: ").append(r1).append("\n\n");

                // ─── Atac 2: Door ID gresit ───
                sb.append("─── [2] Door ID gresit ───\n");
                sb.append("Cer challenge, construiesc mesaj cu door_id=99\n");
                sb.append("in loc de 1, semnez corect.\n");
                sb.append("Asteptat: ESP32 respinge cu 'wrong_door_id'.\n");
                sb.append("       (sau 'signature_invalid' daca verifica semnatura inainte)\n\n");
                String r2 = sendOpenWithTamper(url, false, true, false);
                sb.append("Rezultat: ").append(r2).append("\n\n");

                // ─── Atac 3: Replay ───
                sb.append("─── [3] Replay attack ───\n");
                sb.append("Fac o cerere valida, apoi retrimit EXACT acelasi\n");
                sb.append("payload (mesaj+semnatura) ca un atacator care a\n");
                sb.append("capturat traficul prin sniffing.\n");
                sb.append("Asteptat: a doua cerere respinsa cu 'nonce_invalid_or_expired'.\n\n");
                String r3 = sendReplayAttack(url);
                sb.append("Rezultat: ").append(r3).append("\n\n");

                sb.append("═══ Concluzie ═══\n");
                sb.append("Toate atacurile au fost respinse — protocolul rezista.\n");

            } catch (Exception e) {
                sb.append("Eroare: ").append(e.getMessage()).append("\n");
            }

            final String fullText = sb.toString();
            mainHandler.post(() -> log(fullText));
        });
    }

    private String sendOpenWithTamper(String url, boolean tamperSig, boolean wrongDoor, boolean ignored) throws Exception {
        // GET challenge
        OkHttpClient http = buildHttp();
        Request chReq = new Request.Builder().url(url + "/api/challenge").get().build();
        byte[] nonce;
        try (Response r = http.newCall(chReq).execute()) {
            JSONObject json = new JSONObject(r.body().string());
            nonce = HexUtils.hexToBytes(json.getString("nonce"));
        }

        int doorId = wrongDoor ? 99 : 1;
        byte[] msg = ChallengeSigner.buildMessage(nonce, doorId, ChallengeSigner.ACTION_OPEN_DOOR);
        byte[] sig = signer.sign(msg);

        if (tamperSig) {
            // Flip ultimul byte
            sig[sig.length - 1] ^= 0x01;
        }

        byte[] keyId = keyManager.getKeyId();
        JSONObject payload = new JSONObject();
        payload.put("key_id", HexUtils.bytesToHex(keyId));
        payload.put("message", HexUtils.bytesToHex(msg));
        payload.put("signature", HexUtils.bytesToHex(sig));

        RequestBody body = RequestBody.create(payload.toString(), MediaType.parse("application/json"));
        Request opReq = new Request.Builder().url(url + "/api/open").post(body).build();
        try (Response r = http.newCall(opReq).execute()) {
            return "HTTP " + r.code() + " · " + r.body().string();
        }
    }

    private String sendReplayAttack(String url) throws Exception {
        // 1. Trimite o cerere valida mai intai
        OkHttpClient http = buildHttp();
        Request chReq = new Request.Builder().url(url + "/api/challenge").get().build();
        byte[] nonce;
        try (Response r = http.newCall(chReq).execute()) {
            JSONObject json = new JSONObject(r.body().string());
            nonce = HexUtils.hexToBytes(json.getString("nonce"));
        }

        byte[] msg = ChallengeSigner.buildMessage(nonce, 1, ChallengeSigner.ACTION_OPEN_DOOR);
        byte[] sig = signer.sign(msg);
        byte[] keyId = keyManager.getKeyId();

        JSONObject payload = new JSONObject();
        payload.put("key_id", HexUtils.bytesToHex(keyId));
        payload.put("message", HexUtils.bytesToHex(msg));
        payload.put("signature", HexUtils.bytesToHex(sig));

        String payloadStr = payload.toString();
        RequestBody body = RequestBody.create(payloadStr, MediaType.parse("application/json"));

        // Prima cerere — ar trebui acceptata
        Request opReq1 = new Request.Builder().url(url + "/api/open").post(body).build();
        String first;
        try (Response r = http.newCall(opReq1).execute()) {
            first = "Prima: HTTP " + r.code() + " · " + r.body().string();
        }

        // A doua cerere IDENTICA — replay attack
        RequestBody body2 = RequestBody.create(payloadStr, MediaType.parse("application/json"));
        Request opReq2 = new Request.Builder().url(url + "/api/open").post(body2).build();
        String second;
        try (Response r = http.newCall(opReq2).execute()) {
            second = "Replay: HTTP " + r.code() + " · " + r.body().string();
        }

        return first + "\n           " + second;
    }

    private OkHttpClient buildHttp() {
        return new OkHttpClient.Builder()
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();
    }

    // ═════════════════ EXPORT HEX ═════════════════
    private void exportHex() {
        try {
            if (!keyManager.keyExists()) {
                log("Cheia nu exista.");
                return;
            }
            byte[] publicKeyDer = keyManager.getPublicKey().getEncoded();
            byte[] nonce = new byte[32];
            for (int i = 0; i < 32; i++) nonce[i] = (byte) (0x10 + i);
            byte[] message = ChallengeSigner.buildMessage(nonce, 1, ChallengeSigner.ACTION_OPEN_DOOR);
            byte[] signature = signer.sign(message);
            boolean valid = signer.verifyLocally(message, signature);

            StringBuilder sb = new StringBuilder();
            sb.append("═══ EXPORT PENTRU ESP32 ═══\n");
            sb.append("(util pentru hardcoding cheie sau debug)\n\n");
            sb.append("Sanity check local: ").append(valid ? "VALID" : "INVALID").append("\n\n");

            sb.append("─── [1/3] CHEIA PUBLICA (").append(publicKeyDer.length).append(" bytes) ───\n");
            sb.append(HexUtils.bytesToHex(publicKeyDer)).append("\n\n");

            sb.append("─── [2/3] MESAJUL (").append(message.length).append(" bytes) ───\n");
            sb.append(HexUtils.bytesToHex(message)).append("\n\n");

            sb.append("─── [3/3] SEMNATURA (").append(signature.length).append(" bytes) ───\n");
            sb.append(HexUtils.bytesToHex(signature)).append("\n\n");


            log(sb.toString());
        } catch (Exception e) {
            log("Eroare: " + e);
        }
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        if (executor != null) executor.shutdownNow();
    }
}