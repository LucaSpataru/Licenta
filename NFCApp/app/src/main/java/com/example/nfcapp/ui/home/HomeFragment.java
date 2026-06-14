package com.example.nfcapp.ui.home;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.example.nfcapp.R;
import com.example.nfcapp.crypto.ChallengeSigner;
import com.example.nfcapp.crypto.KeyManager;
import com.example.nfcapp.data.preferences.AppPreferences;
import com.example.nfcapp.remote.DoorApiClient;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class HomeFragment extends Fragment {

    private AppPreferences prefs;
    private KeyManager keyManager;
    private ChallengeSigner signer;
    private ExecutorService executor;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    // Views
    private View statusDot;
    private TextView statusText, serverInfoText, deviceInfoText;
    private Button btnOpenDoor;
    private LinearLayout resultCard;
    private TextView resultStatus, resultTime, resultLatency;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_home, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        prefs = new AppPreferences(requireContext());
        keyManager = new KeyManager();
        signer = new ChallengeSigner(keyManager);
        executor = Executors.newSingleThreadExecutor();

        // Bind views
        statusDot = view.findViewById(R.id.statusDot);
        statusText = view.findViewById(R.id.statusText);
        serverInfoText = view.findViewById(R.id.serverInfoText);
        deviceInfoText = view.findViewById(R.id.deviceInfoText);
        btnOpenDoor = view.findViewById(R.id.btnOpenDoor);
        resultCard = view.findViewById(R.id.resultCard);
        resultStatus = view.findViewById(R.id.resultStatus);
        resultTime = view.findViewById(R.id.resultTime);
        resultLatency = view.findViewById(R.id.resultLatency);

        btnOpenDoor.setOnClickListener(v -> onOpenDoorClicked());

        // Check status periodic la pornire
        checkServerStatus();
    }

    @Override
    public void onResume() {
        super.onResume();
        // Re-check status cand reintri pe tab Home
        checkServerStatus();
    }

    /**
     * Verifica starea ESP32-ului prin /api/status.
     * Actualizeaza indicatorul vizual de conexiune.
     */
    private void checkServerStatus() {
        statusText.setText("Verificare conexiune...");
        statusDot.setBackgroundColor(0xFFBDBDBD); // gri

        String url = prefs.getEsp32Url();
        serverInfoText.setText("ESP32: " + url);

        executor.execute(() -> {
            try {
                OkHttpClient http = new OkHttpClient.Builder()
                        .connectTimeout(3, java.util.concurrent.TimeUnit.SECONDS)
                        .readTimeout(3, java.util.concurrent.TimeUnit.SECONDS)
                        .build();

                Request req = new Request.Builder()
                        .url(url.endsWith("/") ? url + "api/status" : url + "/api/status")
                        .get()
                        .build();

                try (Response resp = http.newCall(req).execute()) {
                    final boolean ok = resp.isSuccessful();
                    final String body = resp.body() != null ? resp.body().string() : "";

                    mainHandler.post(() -> {
                        if (ok) {
                            statusText.setText("Conectat la ESP32");
                            statusDot.setBackgroundColor(0xFF43A047); // verde
                            btnOpenDoor.setEnabled(true);

                            // Parse enrolled count din status
                            try {
                                org.json.JSONObject json = new org.json.JSONObject(body);
                                int enrolled = json.optInt("enrolled_devices", 0);
                                int maxDev = json.optInt("max_devices", 5);
                                boolean enrollOpen = json.optBoolean("enrollment_open", false);

                                String deviceLine = String.format(Locale.US,
                                        "Telefoane inrolate: %d / %d%s",
                                        enrolled, maxDev,
                                        enrollOpen ? " · 🟡 Enrollment activ" : "");
                                deviceInfoText.setText(deviceLine);
                            } catch (Exception e) {
                                deviceInfoText.setText("Telefon: -");
                            }
                        } else {
                            statusText.setText("ESP32 raspunde dar cu eroare");
                            statusDot.setBackgroundColor(0xFFFFA000); // portocaliu
                        }
                    });
                }
            } catch (Exception e) {
                mainHandler.post(() -> {
                    statusText.setText("Nu pot accesa ESP32");
                    statusDot.setBackgroundColor(0xFFE53935); // rosu
                    deviceInfoText.setText("Seteaza URL-ul in Setup");
                    btnOpenDoor.setEnabled(false);
                });
            }
        });
    }

    /**
     * Apasare pe butonul mare "Deschide usa".
     */
    private void onOpenDoorClicked() {
        if (!keyManager.keyExists()) {
            Toast.makeText(requireContext(),
                    "Cheia nu exista! Mergi in Setup si apasa 'Regenereaza cheia'.",
                    Toast.LENGTH_LONG).show();
            return;
        }

        String url = prefs.getEsp32Url();
        btnOpenDoor.setEnabled(false);
        btnOpenDoor.setText("Procesez...");

        executor.execute(() -> {
            try {
                DoorApiClient client = new DoorApiClient(url, signer);
                DoorApiClient.Result result = client.openDoor(
                        1,
                        ChallengeSigner.ACTION_OPEN_DOOR
                );
                mainHandler.post(() -> displayResult(result));
            } catch (Exception e) {
                mainHandler.post(() -> displayError(e));
            } finally {
                mainHandler.post(() -> {
                    btnOpenDoor.setEnabled(true);
                    btnOpenDoor.setText("DESCHIDE USA");
                });
            }
        });
    }

    private void displayResult(DoorApiClient.Result result) {
        resultCard.setVisibility(View.VISIBLE);

        if (result.success) {
            resultStatus.setText("ACCES PERMIS");
            resultStatus.setTextColor(0xFF2E7D32);
            btnOpenDoor.setBackgroundTintList(
                    android.content.res.ColorStateList.valueOf(0xFF43A047));
        } else {
            resultStatus.setText("ACCES RESPINS");
            resultStatus.setTextColor(0xFFC62828);
            // Motivul pe linia 2
            String reasonHuman = humanizeReason(result.reason);
            resultStatus.append("\n");
            TextView extra = new TextView(requireContext());
            // de fapt scoatem newline-ul, folosim resultTime pentru motiv
        }

        String now = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        if (result.success) {
            resultTime.setText("La " + now);
        } else {
            resultTime.setText("La " + now + " · " + humanizeReason(result.reason));
        }

        // Latente defalcate
        String latencyText = String.format(Locale.US,
                "Total:     %d ms\nChallenge: %d ms\nSemnare:   %d ms (TEE)\nOpen:      %d ms",
                result.totalTimeMs,
                result.challengeTimeMs,
                result.signTimeMs,
                result.openTimeMs);
        resultLatency.setText(latencyText);
    }

    private void displayError(Exception e) {
        resultCard.setVisibility(View.VISIBLE);
        resultStatus.setText("⚠ Eroare conexiune");
        resultStatus.setTextColor(0xFFC62828);
        String now = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        resultTime.setText("La " + now);
        resultLatency.setText(e.getClass().getSimpleName() + "\n" +
                (e.getMessage() != null ? e.getMessage() : ""));

        // Refresh statusul
        checkServerStatus();
    }

    private String humanizeReason(String reason) {
        if (reason == null) return "motiv necunoscut";
        switch (reason) {
            case "nonce_invalid_or_expired": return "nonce expirat sau invalid (anti-replay)";
            case "wrong_door_id":             return "id usa gresit";
            case "rate_limit":                 return "prea multe cereri (rate limit)";
            case "unknown_device":             return "telefon neinrolat sau revocat";
            case "signature_invalid":          return "semnatura criptografica invalida";
            case "bad_format":                 return "format date invalid";
            default: return reason;
        }
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        if (executor != null) executor.shutdownNow();
    }
}