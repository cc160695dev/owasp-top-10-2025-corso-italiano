# A04:2025 — Errori crittografici (Cryptographic Failures)

> 📉 **Scesa dal #2 al #4** — non perché sia meno grave, ma perché altre categorie sono cresciute. Resta **una delle più dannose**: tocca direttamente *confidenzialità* (PII, credenziali, finanze) e *integrità* (firme, transazioni).

---

## 1. Obiettivi (Learning Objectives)

Alla fine di questo modulo saprai:

- Distinguere **cifratura** (reversibile) da **hashing** (irreversibile) e quando usare cosa.
- Riconoscere **algoritmi obsoleti** (MD5, SHA-1, DES, RC4, ECB, TLS < 1.2) e cosa usare al loro posto.
- Hashare password correttamente con **Argon2id**, **bcrypt**, **scrypt**, **PBKDF2** + salt.
- Configurare **TLS ≥ 1.2** con cipher moderni e **HSTS**.
- Capire il concetto di **post-quantum cryptography (PQC)** e perché OWASP raccomanda di prepararsi entro il 2030.

---

## 2. Prerequisiti

- Concetti base di hashing/cifratura → [00_introduzione.md §5.6](00_introduzione.md#56-hashing-e-cifratura-non-sono-la-stessa-cosa).
- HTTPS/TLS → [00_introduzione.md §5.3](00_introduzione.md#53-https-tls-e-perché-ci-servono).

---

## 3. Background OWASP

| Metrica | Valore |
|---------|--------|
| Posizione 2025 | **#4** ⬇ (era #2) |
| CWE mappati | 32 |
| Max incidence rate | 13.77% |
| Avg incidence rate | 3.80% |
| Total occurrences | 1.665.348 |
| Total CVE | 2.185 |

---

## 4. Descrizione (Description)

Il principio di base, dalla pagina OWASP: **tutti i dati in transito andrebbero cifrati al transport layer (OSI L4)**. Ostacoli storici (CPU, gestione chiavi) sono superati: istruzioni hardware AES, **Let's Encrypt** per certificati gratuiti automatici.

Oltre al transito, classifica i tuoi dati e decidi cosa cifrare **at rest** e/o a livello applicativo: password, carte, sanità, PII, business secrets — particolarmente sotto **GDPR** e **PCI DSS**.

### Domande-checklist (sei vulnerabile se la risposta è "sì" a una di queste)

- Algoritmi/protocolli vecchi o deboli ancora attivi (default o legacy)?
- Chiavi di default in uso? Chiavi deboli? **Chiavi riusate**?
- **Chiavi in repository di codice** (Git)?
- Cifratura **non forzata** (es. mancano direttive HTTP di sicurezza)?
- **Catena di fiducia** del certificato server validata correttamente?
- **IV** (initialization vectors) ignorati, riusati o non sufficientemente casuali?
- **Modalità insicure** in uso (es. **ECB**)?
- Password usate **direttamente come chiavi crittografiche** senza una **KDF**?
- **Random non crittografico** (es. `Math.random()`) usato per scopi di sicurezza?
- **Hash deprecati** (MD5, SHA-1) ancora in uso?
- Messaggi di errore o **side channel** sfruttabili (es. *padding oracle*)?
- Algoritmo **downgradabile** o bypassabile?

### Concetti chiave da fissare

- **KDF (Key Derivation Function):** funzione che, partendo da una password (entropia bassa), produce una chiave crittografica robusta. Se hashi password per autenticazione, usa una KDF *adattiva* (Argon2id, bcrypt, scrypt, PBKDF2-HMAC-SHA-512).
- **Salt:** valore casuale unico per utente, mescolato all'input prima dell'hash. Impedisce le **rainbow table** e le **collisioni** tra utenti con stessa password.
- **Pepper (opzionale):** secret server-side aggiunto alla password prima dell'hash. Vive **fuori dal DB** (in HSM/KMS/env). Rende inutile il DB rubato senza il pepper.
- **AEAD (Authenticated Encryption with Associated Data):** cifratura che integra un **MAC**. Esempi moderni: **AES-256-GCM**, **ChaCha20-Poly1305**. Garantisce *insieme* riservatezza + integrità + autenticità.
- **Forward Secrecy (FS):** se compromettono la chiave privata oggi, non possono decifrare il traffico **passato**. Cipher con FS: ECDHE-...
- **HSM / KMS:** *Hardware Security Module* (fisico) o *Key Management Service* (cloud, es. AWS KMS, GCP KMS, Azure Key Vault) — dove vivono le chiavi più sensibili senza essere mai materializzate in app.

---

## 5. Esempi di attacco (Example Attack Scenarios)

### Scenario #1 — TLS non forzato + downgrade

Un sito non forza TLS o accetta cipher deboli. Un attaccante in Wi-Fi pubblico **intercetta** richieste, **declassa** la connessione da HTTPS a HTTP, **ruba il cookie di sessione** e replica le richieste autenticate. Variante più grave: l'attaccante **modifica** dati in transito, es. il destinatario di un bonifico.

### Scenario #2 — Password DB con hash deboli

Il DB conserva password con hash **non salted o "veloci"** (MD5, SHA-1, SHA-256 nudo). Una falla diversa (es. file upload, A05) consente di scaricare il DB. Tutti gli hash unsalted sono crackati con una **rainbow table** in pochi secondi. Anche quelli salted, se l'algoritmo è veloce, vengono crackati con GPU a miliardi/sec. → Credential stuffing su mille altri siti dove gli utenti hanno riusato la password.

### Scenario #3 — Chiavi AES riusate / IV ripetuti

Un'app cifra dati sensibili con AES-CBC e usa **sempre lo stesso IV** (o lo riusa). Conseguenza: blocchi identici producono ciphertext identici → l'attaccante **distingue pattern**, ricostruisce dati. Variante più nota: **AES-ECB** (mai usare ECB!): l'immagine cifrata con ECB rimane riconoscibile.

---

## 6. Codice vulnerabile vs sicuro

### Esempio A — Hashing password (Python)

❌ **Vulnerabile:**

```python
import hashlib

def hash_password(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()      # veloce, no salt, no KDF
```

✅ **Sicuro** (Argon2id, raccomandato OWASP):

```python
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=64*1024, parallelism=4)

def hash_password(p: str) -> str:
    return ph.hash(p)        # genera salt unico automaticamente

def verify(stored: str, p: str) -> bool:
    try:
        ph.verify(stored, p)
        if ph.check_needs_rehash(stored):
            # opzionale: rihash con parametri aggiornati al login successivo
            pass
        return True
    except Exception:
        return False
```

> 💡 **Buona pratica:** usa la libreria del tuo linguaggio (`argon2-cffi` Python, `argon2` Go, `@node-rs/argon2` Node, BouncyCastle Java). **Mai implementare cripto a mano.**

### Esempio B — Cifratura simmetrica (Node.js)

❌ **Vulnerabile** (AES-CBC con IV fisso, no autenticazione):

```javascript
const crypto = require('crypto');
const KEY = Buffer.from('hardcoded-32-bytes-key-very-bad!', 'utf8');
const IV  = Buffer.alloc(16, 0);                             // 🚨 IV fisso

function encrypt(plain) {
  const c = crypto.createCipheriv('aes-256-cbc', KEY, IV);
  return Buffer.concat([c.update(plain), c.final()]).toString('base64');
}
```

✅ **Sicuro** (AES-256-GCM, IV random, AEAD):

```javascript
const crypto = require('crypto');

// in produzione la chiave viene da KMS/Vault, non da una const
const KEY = crypto.randomBytes(32);

function encrypt(plain, aad = Buffer.alloc(0)) {
  const iv = crypto.randomBytes(12);                          // 96-bit IV per GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('base64'), ct: ct.toString('base64'), tag: tag.toString('base64') };
}

function decrypt({ iv, ct, tag }, aad = Buffer.alloc(0)) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  decipher.setAAD(aad);
  return Buffer.concat([decipher.update(Buffer.from(ct, 'base64')), decipher.final()]).toString('utf8');
}
```

### Esempio C — Random per token di sessione

❌ **Vulnerabile:**

```javascript
const token = Math.random().toString(36).slice(2);   // PRNG non crittografico, prevedibile
```

✅ **Sicuro:**

```javascript
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('base64url');
```

### Esempio D — TLS config (nginx, profilo "intermediate" Mozilla)

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

(Generare config aggiornate da: <https://ssl-config.mozilla.org/>)

---

## 7. Come prevenirlo (How to Prevent)

Mitigazioni OWASP, riformulate:

- **Classifica e etichetta** i dati che processi/conservi/trasmetti. Senza data classification non sai cosa proteggere.
- **HSM / KMS** per le chiavi più sensibili.
- **Implementazioni trusted**, mai cripto fatta in casa.
- **Non conservare** ciò che non serve. Ogni dato non cifrato è un rischio aggiuntivo. Considera la **tokenization PCI DSS** per le carte.
- **Cifra a riposo** tutti i dati sensibili. Strumenti: TDE del DB, S3 SSE, full-disk encryption, application-level encryption per i campi più critici.
- **Algoritmi standard, aggiornati, forti**.
- **TLS ≥ 1.2** (preferibilmente 1.3), cipher con **forward secrecy** (ECDHE).
- **Drop CBC** in favore di **GCM/Poly1305**. Prepara per **PQC** (Kyber, Dilithium).
- **HSTS** per forzare HTTPS.
- **Disabilita caching** per risposte sensibili (CDN, browser, app).
- **No protocolli in chiaro**: niente FTP, niente SMTP semplice per dati confidenziali, niente Telnet, niente HTTP per le API.
- **Hash password adattivi e salted**: Argon2(id), yescrypt, scrypt, PBKDF2-HMAC-SHA-512 con work factor.
- **IV** appropriato per la modalità (12 byte per GCM; mai riusare per la stessa chiave).
- **AEAD sempre** (preferisci GCM/ChaCha20-Poly1305 a CBC+HMAC).
- **Random crittografico** ovunque servano segreti (chiavi, token, IV, salt). Mai `Math.random()`.
- **Niente algoritmi deprecati**: MD5, SHA-1, CBC mode (per nuovi design), PKCS#1 v1.5.
- **Review da specialisti** dei setting cripto.
- **Post-Quantum readiness**: pianifica la migrazione a cripto post-quantum entro il 2030 per i sistemi ad alto rischio. NIST ha standardizzato **ML-KEM (Kyber)** e **ML-DSA (Dilithium)** nel 2024.

---

## 8. CWE rilevanti

| CWE | Nome |
|-----|------|
| **CWE-327** | Use of a Broken or Risky Cryptographic Algorithm |
| **CWE-326** | Inadequate Encryption Strength |
| **CWE-319** | Cleartext Transmission of Sensitive Information |
| **CWE-321** | Use of Hard-coded Cryptographic Key |
| **CWE-330** | Use of Insufficiently Random Values |
| **CWE-331** | Insufficient Entropy |
| **CWE-338** | Use of Cryptographically Weak Pseudo-Random Number Generator |
| **CWE-759** | Use of a One-Way Hash without a Salt |
| **CWE-916** | Use of Password Hash With Insufficient Computational Effort |
| **CWE-1241** | Use of Predictable Algorithm in Random Number Generator |

---

## 9. Lab pratico

### Lab consigliati

1. **PortSwigger Academy — JWT vulnerabilities**: <https://portswigger.net/web-security/jwt> (algoritmi deboli, `alg: none`, JWK injection).
2. **CryptoHack** — <https://cryptohack.org/>: piattaforma per imparare cripto via challenge.
3. **SSL Labs Server Test** — <https://www.ssllabs.com/ssltest/>: testa la config TLS di qualunque dominio. Punta a **A** o **A+**.
4. **Hashcat** o **John the Ripper** in locale: prendi un file con hash MD5/SHA1 (es. `rockyou.txt`-like sintetico) e prova a romperlo. Ti convincerai del perché serve Argon2.

### 🧪 Esercizio guidato — Da SHA-256 a Argon2id

1. Scrivi una mini-app Python con login basato su `hashlib.sha256`.
2. Inserisci 100 utenti con password da `top-1000.txt` (lista password comuni).
3. Esporta gli hash come file `users.txt` formato `username:hash`.
4. Lancia `hashcat -m 1400 users.txt rockyou.txt` (modulo SHA-256). Quante password rompi?
5. Migra a `argon2-cffi`. Reimporta gli stessi utenti.
6. Esporta di nuovo e prova: `hashcat -m 70200 users.txt rockyou.txt --benchmark`. Quante hash/sec ottieni?

✅ **Hai completato** se: hai sperimentato in prima persona la differenza ordine-di-grandezza tra SHA-256 e Argon2id. (Spoiler: con SHA-256 GPU ~30 GH/s, con Argon2id qualche centinaio di H/s.)

---

## 10. Quiz di autovalutazione

1. Differenza tra **cifratura** e **hashing**? Per memorizzare password quale usi?
2. Cosa è un **salt** e perché impedisce le **rainbow table**?
3. **AES-CBC** vs **AES-GCM**: perché GCM è preferito?
4. Perché `Math.random()` non va bene per generare un token di sessione?
5. Cosa significa **forward secrecy**? Quale famiglia di cipher la fornisce in TLS?
6. Cosa è un **HSM** e quando lo userei?
7. Cosa è un attacco di tipo **padding oracle**? In quale famiglia di vulnerabilità OWASP cade?
8. Cosa significa **post-quantum cryptography** e perché OWASP la cita?
9. Una password viene salvata come `MD5(salt + password)`. Identifica almeno **due** problemi.

<details>
<summary>📖 Soluzioni</summary>

1. **Cifratura** = reversibile con chiave (per trasmettere/conservare e poi recuperare). **Hashing** = irreversibile (per verificare/identificare). Per le **password**: né l'una né l'altra "nuda" — usi una **KDF** (Argon2id, bcrypt, scrypt, PBKDF2), che è basata su hash ma adattiva e con salt.
2. Un valore casuale unico per record, concatenato all'input prima dell'hash. Impedisce le rainbow table (precomputed) perché ogni utente ha un dominio diverso, e impedisce che due utenti con la stessa password producano lo stesso hash.
3. **CBC** non offre autenticazione: serve un MAC separato (HMAC) e si rischiano errori (padding oracle, ordine encrypt-then-MAC). **GCM** è **AEAD**: cifra **e** autentica in un solo passaggio, con IV chiaro, tag di autenticazione e supporto per dati associati. Più semplice, più sicuro, più veloce.
4. È un PRNG **non crittografico**, statisticamente predicibile. Conoscendo qualche valore, l'attaccante può ricostruire lo stato e prevedere quelli futuri. Per i segreti: `crypto.randomBytes` (Node), `secrets` (Python), `SecureRandom` (Java), `/dev/urandom` (Unix).
5. **Forward secrecy** = se la chiave privata a lungo termine viene compromessa, non si può decrittare il **traffico passato** registrato. Si ottiene con scambio chiavi effimere: in TLS, le suite **ECDHE-...** (Elliptic-Curve Diffie-Hellman Ephemeral).
6. *Hardware Security Module* — un dispositivo (fisico o cloud-managed) dove le chiavi sono **generate, conservate e usate** senza mai uscire in chiaro. Lo usi per le chiavi più critiche (root di una CA, chiavi di firma, master key per encryption at rest, chiavi PCI DSS).
7. Attacco contro CBC: l'attaccante manda ciphertext modificati e osserva se il server risponde "padding error" o altro errore. Da quella distinzione **decifra** progressivamente il messaggio. Cade in **A04 — Cryptographic Failures** (cripto debole/mal implementata) e in parte in **A10** (messaggi d'errore troppo informativi). Mitigazione: usare AEAD (GCM).
8. Crittografia che resiste a **computer quantistici** (es. Kyber per KEM, Dilithium per firma, standardizzati NIST 2024). OWASP la cita perché un attaccante può **registrare oggi** traffico TLS e **decifrarlo domani** quando i quantistici saranno utilizzabili (*"harvest now, decrypt later"*). I sistemi ad alto rischio devono migrare entro il 2030.
9. (a) **MD5** è veloce e ha collisioni note → un attaccante con GPU rompe per brute force. (b) Manca una **KDF adattiva**: anche con un hash buono, una sola passata è insufficiente per le password. Bonus: anche se è "salted", non c'è work factor, quindi una password breve è ancora attaccabile.

</details>

---

## 11. Cheat sheet — A04 in 60 secondi

- 🔐 **Cifrare in transito**: TLS ≥ 1.2 (meglio 1.3), cipher con FS, **HSTS preload**.
- 💾 **Cifrare a riposo** ciò che è classificato sensibile.
- 🔑 **Chiavi**: random crittografico, mai hardcoded, mai in repo, in **HSM/KMS** se critiche.
- 🧂 **Password**: **Argon2id** (default moderno) o bcrypt/scrypt/PBKDF2-HMAC-SHA-512 + salt + work factor.
- 🚫 **Niente** MD5, SHA-1, DES, RC4, AES-ECB, TLS < 1.2, IV statici, `Math.random()`.
- 🛡️ **AEAD** preferito: AES-256-GCM, ChaCha20-Poly1305.
- 🪪 **Validazione certificato** sempre (mai `verify=False`).
- ⏳ **PQC** in roadmap entro 2030 per sistemi ad alto rischio.
- 🔁 **Mai conservare** dati sensibili che non servono.
- 🚪 Non cachare risposte con dati sensibili (CDN/browser/app).

---

## 12. Risorse e approfondimenti

- 🌐 [Pagina OWASP A04:2025](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- 📘 [OWASP Cheat Sheet — Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- 📘 [OWASP Cheat Sheet — Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- 📘 [OWASP Cheat Sheet — Transport Layer Security](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- 🛠️ [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- 🛠️ [SSL Labs — Server Test](https://www.ssllabs.com/ssltest/) e [Client Test](https://www.ssllabs.com/ssltest/viewMyClient.html)
- 🛠️ [testssl.sh](https://testssl.sh/) — CLI per testare TLS
- 📖 [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — autenticazione e password
- 📖 [NIST SP 800-131A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf) — algoritmi e key length
- 📖 [NIST PQC Standards (FIPS 203/204/205)](https://csrc.nist.gov/projects/post-quantum-cryptography)
- 📖 [Cryptography Engineering — Ferguson, Schneier, Kohno] (libro)

---

⬅ Modulo precedente: [03_software_supply_chain_failures.md](03_software_supply_chain_failures.md)
➡ Prossimo: [05_injection.md](05_injection.md)
