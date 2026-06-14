#ifndef NONCE_MANAGER_H
#define NONCE_MANAGER_H

#include <stdint.h>
#include <stddef.h>

/**
 * Gestioneaza nonce-uri pentru protocolul challenge-response.
 * 
 * Garantii:
 *  - Nonce-urile sunt generate cu RNG hardware-backed (esp_random)
 *  - Fiecare nonce e valid o singura data (single-use)
 *  - Nonce-urile expira dupa NONCE_VALIDITY_MS (30s default)
 *  - Dupa consume(), nonce-ul nu mai e acceptat (anti-replay)
 */
class NonceManager {
public:
    /**
     * Genereaza un nonce nou. Inlocuieste cel anterior daca exista.
     * Returneaza un pointer catre byte-ii nonce-ului (32 bytes).
     * Pointer-ul e valid pana la urmatoarea operatie pe acest NonceManager.
     */
    const uint8_t* generate();

    /**
     * Verifica daca nonce-ul primit match-uieste cel curent si nu a expirat.
     * Returneaza true daca match, false altfel.
     * 
     * Nu consuma nonce-ul (mai poate fi folosit). Pentru consumare → consume().
     */
    bool check(const uint8_t* candidate, size_t candidateLen);

    /**
     * Marcheaza nonce-ul curent ca folosit. Dupa aceasta operatie, check()
     * va returna false pana la urmatorul generate().
     */
    void consume();

    /**
     * Returneaza numarul de milisecunde ramase pana la expirare.
     * 0 daca a expirat sau nu exista nonce activ.
     */
    uint32_t remainingMs() const;

private:
    uint8_t currentNonce[32];
    uint32_t generatedAt = 0;
    bool active = false;
};

extern NonceManager nonceManager;

#endif // NONCE_MANAGER_H