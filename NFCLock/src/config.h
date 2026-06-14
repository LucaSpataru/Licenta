#ifndef CONFIG_H
#define CONFIG_H

// ============== WiFi credentials ==============
// Schimba cu credentialele tale reale.
// IMPORTANT: nu commita acest fisier intr-un repo public!
#define WIFI_SSID "netspataru2,4"    
#define WIFI_PASSWORD "lucahoria57"
//"LucasiPhone"
//"kanyewest"

// ============== HTTP server ==============
#define HTTP_PORT 80

// ============== GPIO LEDs ==============
#define LED_DOOR_PIN        2   // Verde: door open
#define LED_DENIED_PIN      4   // Rosu: access denied  
#define LED_READY_PIN       25  // Albastru: sistem pornit
#define LED_ENROLLMENT_PIN  26  // Galben: enrollment mode active

// ============== Nonce config ==============
#define NONCE_VALIDITY_MS 30000  // un nonce e valid 30 secunde dupa emitere
#define NONCE_LENGTH 32

// ============== Door config ==============
#define DOOR_ID 1  // ID-ul acestei usi (trebuie sa match cu cel din mesajul telefonului)

// ============== Action codes ==============
#define ACTION_OPEN_DOOR 0x01

// ============== Enrollment config ==============
#define MAX_ENROLLED_DEVICES 5
#define ENROLLMENT_WINDOW_MS 60000  // 60 secunde dupa boot/buton
#define ENROLLMENT_BUTTON_PIN 0      // GPIO 0 = butonul BOOT pe majoritatea placilor ESP32
#define ENROLLMENT_LED_PIN 2         // Folosim acelasi LED_OK_PIN pentru indicator


// ============== APDU custom (proprietar) ==============
// AID-ul aplicației noastre Android
#define APP_AID_HEX {0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
#define APP_AID_LEN 7

// INS codes (CLA = 0x80 pentru toate)
#define APDU_CLA_PROPRIETARY  0x80
#define APDU_INS_GET_CHALLENGE 0x10
#define APDU_INS_SIGN_CHALLENGE 0x20

// Status words
#define SW1_SUCCESS 0x90
#define SW2_SUCCESS 0x00

#endif // CONFIG_H