package com.example.nfcapp.ui.setup;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.Fragment;

import com.example.nfcapp.R;
import com.example.nfcapp.crypto.KeyManager;
import com.example.nfcapp.data.preferences.AppPreferences;
import com.example.nfcapp.util.HexUtils;

import org.json.JSONObject;

import java.security.KeyPair;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class SetupFragment extends Fragment {

    private AppPreferences prefs;
    private KeyManager keyManager;
    private ExecutorService executor;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private EditText etEsp32Url;
    private Button btnSaveUrl, btnRegenerateKey, btnEnroll;
    private TextView urlTestResult, keyStatusText, keyDetailsText,
            enrollStatusText, enrollResultText;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_setup, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        prefs = new AppPreferences(requireContext());
        keyManager = new KeyManager();
        executor = Executors.newSingleThreadExecutor();

        etEsp32Url = view.findViewById(R.id.etEsp32Url);
        btnSaveUrl = view.findViewById(R.id.btnSaveUrl);
        urlTestResult = view.findViewById(R.id.urlTestResult);
        keyStatusText = view.findViewById(R.id.keyStatusText);
        keyDetailsText = view.findViewById(R.id.keyDetailsText);
        btnRegenerateKey = view.findViewById(R.id.btnRegenerateKey);
        enrollStatusText = view.findViewById(R.id.enrollStatusText);
        btnEnroll = view.findViewById(R.id.btnEnroll);
        enrollResultText = view.findViewById(R.id.enrollResultText);

        etEsp32Url.setText(prefs.getEsp32Url());
        btnSaveUrl.setOnClickListener(v -> saveAndTestUrl());
        btnRegenerateKey.setOnClickListener(v -> regenerateKeyWithConfirm());
        btnEnroll.setOnClickListener(v -> enrollDevice());

        refreshKeyStatus();
        refreshEnrollStatus();
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshKeyStatus();
        refreshEnrollStatus();
    }

    // ═════════════════ URL ═════════════════
    private void saveAndTestUrl() {
        String url = etEsp32Url.getText().toString().trim();
        if (url.isEmpty()) {
            Toast.makeText(requireContext(), "Introdu URL!", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url;
            etEsp32Url.setText(url);
        }
        prefs.setEsp32Url(url);
        urlTestResult.setText("Testez...");
        urlTestResult.setTextColor(0xFF757575);

        final String testUrl = url;
        executor.execute(() -> {
            try {
                OkHttpClient http = new OkHttpClient.Builder()
                        .connectTimeout(3, TimeUnit.SECONDS)
                        .readTimeout(3, TimeUnit.SECONDS)
                        .build();
                Request req = new Request.Builder()
                        .url(testUrl + "/api/status")
                        .get()
                        .build();
                try (Response resp = http.newCall(req).execute()) {
                    final boolean ok = resp.isSuccessful();
                    final String body = resp.body() != null ? resp.body().string() : "";
                    mainHandler.post(() -> {
                        if (ok) {
                            urlTestResult.setText("Conexiune OK · HTTP 200");
                            urlTestResult.setTextColor(0xFF2E7D32);
                            refreshEnrollStatus();
                        } else {
                            urlTestResult.setText("Server raspunde: HTTP " + resp.code());
                            urlTestResult.setTextColor(0xFFE65100);
                        }
                    });
                }
            } catch (Exception e) {
                mainHandler.post(() -> {
                    urlTestResult.setText("✗ " + e.getClass().getSimpleName() + " — verifica WiFi + IP");
                    urlTestResult.setTextColor(0xFFC62828);
                });
            }
        });
    }

    // ═════════════════ Cheie ═════════════════
    private void refreshKeyStatus() {
        try {
            if (!keyManager.keyExists()) {
                keyStatusText.setText("Status: cheie negenerata");
                keyDetailsText.setText("Apasa 'Regenereaza cheia' pentru a o crea.");
                return;
            }
            keyStatusText.setText("Status: generata (hardware-backed)");

            java.security.PublicKey pub = keyManager.getPublicKey();
            byte[] keyId = keyManager.getKeyId();
            int chainLen = keyManager.getAttestationCertChain().length;

            String details = String.format(Locale.US,
                    "Algoritm: %s P-256\nCheie publica: %d bytes\nKeyId: %s...\nLant atestare: %d certificate",
                    pub.getAlgorithm(),
                    pub.getEncoded().length,
                    HexUtils.bytesToHex(java.util.Arrays.copyOf(keyId, 8)),
                    chainLen);
            keyDetailsText.setText(details);
        } catch (Exception e) {
            keyStatusText.setText("Status: eroare");
            keyDetailsText.setText(e.getMessage());
        }
    }

    private void regenerateKeyWithConfirm() {
        new AlertDialog.Builder(requireContext())
                .setTitle("Regenereaza cheia?")
                .setMessage("Cheia curenta va fi stearsa definitiv. Va trebui sa reinrolezi acest telefon la ESP32.\n\nContinui?")
                .setPositiveButton("Da, regenereaza", (d, w) -> doRegenerateKey())
                .setNegativeButton("Anuleaza", null)
                .show();
    }

    private void doRegenerateKey() {
        try {
            keyManager.deleteKey();
            byte[] challenge = "regen-challenge".getBytes();
            KeyPair kp = keyManager.generateKey(challenge);
            Toast.makeText(requireContext(), "Cheie regenerata", Toast.LENGTH_SHORT).show();
            refreshKeyStatus();
        } catch (Exception e) {
            Toast.makeText(requireContext(), "Eroare: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    // ═════════════════ Enrollment ═════════════════
    private void refreshEnrollStatus() {
        enrollStatusText.setText("Verific status server...");
        String url = prefs.getEsp32Url();
        executor.execute(() -> {
            try {
                OkHttpClient http = new OkHttpClient.Builder()
                        .connectTimeout(3, TimeUnit.SECONDS)
                        .build();
                Request req = new Request.Builder().url(url + "/api/status").get().build();
                try (Response resp = http.newCall(req).execute()) {
                    if (!resp.isSuccessful()) {
                        mainHandler.post(() -> enrollStatusText.setText("Server inaccessibil"));
                        return;
                    }
                    JSONObject json = new JSONObject(resp.body().string());
                    int enrolled = json.getInt("enrolled_devices");
                    int max = json.getInt("max_devices");
                    boolean open = json.getBoolean("enrollment_open");
                    long remaining = json.optLong("enrollment_remaining_ms", 0);

                    final String txt;
                    if (open) {
                        txt = String.format(Locale.US,
                                "Fereastra deschisa · %ds ramas\nInrolari: %d / %d",
                                remaining / 1000, enrolled, max);
                    } else {
                        txt = String.format(Locale.US,
                                "Fereastra inchisa\nInrolari: %d / %d\nApasa BOOT pe ESP32 pentru a redeschide.",
                                enrolled, max);
                    }
                    mainHandler.post(() -> enrollStatusText.setText(txt));
                }
            } catch (Exception e) {
                mainHandler.post(() -> enrollStatusText.setText("Eroare: " + e.getClass().getSimpleName()));
            }
        });
    }

    private void enrollDevice() {
        if (!keyManager.keyExists()) {
            Toast.makeText(requireContext(), "Genereaza cheia mai intai!", Toast.LENGTH_SHORT).show();
            return;
        }
        String url = prefs.getEsp32Url();
        enrollResultText.setText("Trimit cerere...");
        enrollResultText.setTextColor(0xFF757575);

        executor.execute(() -> {
            try {
                byte[] publicKeyDer = keyManager.getPublicKey().getEncoded();
                String pubKeyHex = HexUtils.bytesToHex(publicKeyDer);
                String deviceLabel = android.os.Build.MODEL;

                JSONObject payload = new JSONObject();
                payload.put("public_key", pubKeyHex);
                payload.put("device_label", deviceLabel);

                OkHttpClient http = new OkHttpClient.Builder()
                        .connectTimeout(5, TimeUnit.SECONDS)
                        .readTimeout(5, TimeUnit.SECONDS)
                        .build();

                RequestBody body = RequestBody.create(
                        payload.toString(),
                        MediaType.parse("application/json"));
                Request req = new Request.Builder()
                        .url(url + "/api/enroll")
                        .post(body)
                        .build();

                try (Response resp = http.newCall(req).execute()) {
                    final int code = resp.code();
                    final String respBody = resp.body() != null ? resp.body().string() : "";
                    mainHandler.post(() -> {
                        if (code == 200) {
                            try {
                                JSONObject json = new JSONObject(respBody);
                                String label = json.getString("device_label");
                                int total = json.getInt("total_enrolled");
                                int remaining = json.getInt("slots_remaining");
                                enrollResultText.setText(String.format(Locale.US,
                                        "Inrolat ca '%s'\nTotal: %d device-uri · %d sloturi libere",
                                        label, total, remaining));
                                enrollResultText.setTextColor(0xFF2E7D32);
                            } catch (Exception e) {
                                enrollResultText.setText("Inrolat\n" + respBody);
                                enrollResultText.setTextColor(0xFF2E7D32);
                            }
                            refreshEnrollStatus();
                        } else if (code == 403) {
                            enrollResultText.setText("Fereastra de enrollment inchisa.\nApasa BOOT pe ESP32 si incearca din nou.");
                            enrollResultText.setTextColor(0xFFC62828);
                        } else if (code == 409) {
                            enrollResultText.setText("Acest telefon e deja inrolat sau lista e plina.");
                            enrollResultText.setTextColor(0xFFE65100);
                        } else {
                            enrollResultText.setText("HTTP " + code + ": " + respBody);
                            enrollResultText.setTextColor(0xFFC62828);
                        }
                    });
                }
            } catch (Exception e) {
                mainHandler.post(() -> {
                    enrollResultText.setText(e.getClass().getSimpleName() + ": " + e.getMessage());
                    enrollResultText.setTextColor(0xFFC62828);
                });
            }
        });
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        if (executor != null) executor.shutdownNow();
    }
}