#ifndef KEY_STORE_H
#define KEY_STORE_H

#include <stdint.h>
#include <stddef.h>
#include <Arduino.h>

#define KEY_ID_LEN 16
#define MAX_PUBLIC_KEY_LEN 128
#define MAX_DEVICE_LABEL_LEN 32

/**
 * Reprezinta un telefon inrolat.
 */
struct EnrolledDevice {
    uint8_t keyId[KEY_ID_LEN];         // primii 16B din SHA256(publicKey)
    uint8_t publicKey[MAX_PUBLIC_KEY_LEN];
    size_t  publicKeyLen;
    char    deviceLabel[MAX_DEVICE_LABEL_LEN];
    uint32_t enrolledAt;               // timestamp boot ms (informativ)
};

/**
 * Gestioneaza lista de telefoane inrolate, persistate in NVS.
 * Suporta maxim MAX_ENROLLED_DEVICES (5) telefoane.
 */
class KeyStore {
public:
    /**
     * Initializare — incarca din NVS in memorie.
     * Trebuie apelata o singura data in setup().
     */
    bool init();

    /**
     * Inroleaza un nou telefon.
     * KeyId-ul se calculeaza intern din publicKey.
     * 
     * @return true daca inrolarea a reusit
     *         false daca: storage plin, cheia deja inrolata, sau parsare key esuata
     */
    bool enroll(const uint8_t* publicKey, size_t publicKeyLen,
                const char* deviceLabel,
                uint8_t* outKeyId);

    /**
     * Cauta o cheie publica dupa keyId.
     * @return pointer catre EnrolledDevice, sau nullptr daca nu exista
     */
    const EnrolledDevice* findByKeyId(const uint8_t* keyId);

    /**
     * Calculeaza keyId-ul din cheia publica (SHA-256 truncat la 16B).
     */
    static void computeKeyId(const uint8_t* publicKey, size_t publicKeyLen, uint8_t* outKeyId);

    /**
     * Numarul curent de telefoane inrolate.
     */
    uint8_t count() const { return deviceCount; }

    /**
     * Acces la device-urile inrolate (pentru listare/debug).
     */
    const EnrolledDevice* deviceAt(uint8_t index) const {
        return (index < deviceCount) ? &devices[index] : nullptr;
    }

    /**
     * Revoca (sterge) un device inrolat dupa keyId.
     * @return true daca a fost sters, false daca nu exista
     */
    bool revokeByKeyId(const uint8_t* keyId);

    /**
     * Sterge toate inrolarile (factory reset).
     */
    void clearAll();

private:
    EnrolledDevice devices[5]; // MAX_ENROLLED_DEVICES
    uint8_t deviceCount = 0;

    bool persist();  // salveaza tot vectorul in NVS
};

extern KeyStore keyStore; // singleton global

#endif // KEY_STORE_H