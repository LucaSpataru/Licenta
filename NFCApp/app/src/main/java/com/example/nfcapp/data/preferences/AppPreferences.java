package com.example.nfcapp.data.preferences;

import android.content.Context;
import android.content.SharedPreferences;

/**
 stocare a configuratiei aplicatiei.
 */
public class AppPreferences {

    private static final String PREFS_NAME = "nfc_access_prefs";
    private static final String KEY_ESP32_URL = "esp32_url";

    private final SharedPreferences prefs;

    public AppPreferences(Context context) {
        // applicationContext evita memory leaks la rotatie ecran
        this.prefs = context.getApplicationContext()
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    /**
     returneaza URL-ul ESP32 stocat sau valoarea default daca nu exista.
     */
    public String getEsp32Url() {
        return prefs.getString(KEY_ESP32_URL, "http://192.168.1.123");
    }

    public void setEsp32Url(String url) {
        prefs.edit().putString(KEY_ESP32_URL, url).apply();
    }
}