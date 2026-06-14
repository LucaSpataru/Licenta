#ifndef NFC_AUTHENTICATOR_H
#define NFC_AUTHENTICATOR_H

#include <stdint.h>
#include <Arduino.h>

/**
 * Gestioneaza autentificarea prin NFC HCE.
 * 
 * Flow:
 *   1. inListPassiveTarget() — detecteaza telefonul
 *   2. SELECT AID — verifica aplicatia raspunde
 *   3. GET CHALLENGE — trimite nonce generat de ESP32, primeste keyId
 *   4. SIGN CHALLENGE — trimite mesaj (nonce+doorId+action), primeste semnatura
 *   5. Verifica keyId in storage, verifica ECDSA → LED + LOG
 * 
 * Aceleasi primitive criptografice ca pe HTTP — un singur protocol, doua
 * transporturi (NFC si HTTP).
 */
class NfcAuthenticator {
public:
    enum Result {
        NO_TAG,            // nimic in camp
        TAG_NOT_HCE,       // tag pasiv (MIFARE etc), nu HCE — verifica in NfcAuthenticator
        TAG_MIFARE_BACKUP, // cartela MIFARE inrolata ca backup
        SELECT_FAILED,     // SELECT AID a esuat (telefon gresit / restrictie)
        FLOW_INCOMPLETE,   // unul din pasii APDU a esuat (telefon miscat)
        SIGNATURE_INVALID, // semnatura primita dar ECDSA verify a esuat
        UNKNOWN_DEVICE,    // keyId nu exista in storage
        SUCCESS            // telefonul a fost autentificat si usa s-a deschis
    };

    /**
     * Initializeaza PN532. Apelat o singura data in setup().
     * Returneaza true daca PN532 raspunde.
     */
    bool init();

    /**
     * Verifica campul NFC pentru un tag si (daca exista) ruleaza flow-ul de
     * autentificare complet. Non-blocking — foloseste timeout intern scurt.
     * 
     * @param outDeviceLabel Buffer pentru label-ul telefonului recunoscut (daca SUCCESS)
     * @param labelBufSize   Capacitatea bufer-ului
     * @param outLatencyMs   Timpul total al flow-ului (informativ)
     * @return enum Result
     */
    Result tick(char* outDeviceLabel, size_t labelBufSize, uint32_t* outLatencyMs);

    /**
     * Pentru endpoint /api/mifare/last_detected — returneaza ultimul UID detectat.
     */
    void getLastDetectedUid(uint8_t* outUid, uint8_t* outLen, uint32_t* outAgoMs);

    bool isAvailable() const { return available; }

private:
    bool available = false;
    
    // Ultimul UID detectat (pentru API status / mifare enrollment)
    uint8_t lastUid[7] = {0};
    uint8_t lastUidLen = 0;
    uint32_t lastDetectedAt = 0;
    
    // Debouncing — acelasi UID nu re-triggereaza in urmatoarele X ms
    uint8_t lastSuccessUid[7] = {0};
    uint8_t lastSuccessUidLen = 0;
    uint32_t lastSuccessAt = 0;
};

extern NfcAuthenticator nfcAuth;

#endif