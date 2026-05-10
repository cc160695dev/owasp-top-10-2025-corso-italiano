# 99 — Glossario (Glossary) IT ↔ EN

> Termini chiave incontrati nel corso, con definizione breve, traduzione (se serve), e modulo di provenienza. Usa **Ctrl+F** per cercare.

---

## A

| Termine (EN) | Italiano | Definizione | Modulo |
|--------------|----------|-------------|--------|
| **AEAD** (Authenticated Encryption with Associated Data) | Cifratura autenticata | Cifratura che integra integrità+autenticità (es. AES-GCM, ChaCha20-Poly1305) | A04 |
| **Access control** | Controllo degli accessi | Politica che decide chi può fare cosa | A01 |
| **Account enumeration** | Enumerazione account | Distinguere "utente esistente" da "non esistente" da risposte differenti | A07 |
| **Allow-list** (≠ whitelist) | Lista di permesso | Difesa basata su "consenti solo questi"; opposto di deny-list | A05, A02 |
| **Argon2id** | — | Funzione di derivazione chiave moderna, raccomandata per password | A04, A07 |
| **ASVS** (Application Security Verification Standard) | — | Checklist OWASP di requisiti di sicurezza applicativa | A06 |
| **Attaccante** / threat actor | Attaccante | Chi cerca di violare il sistema | intro |
| **Audit log** | Log d'audit | Registro immodificabile delle azioni rilevanti | A09 |
| **Authentication** | Autenticazione | "Chi sei?" — verifica identità | intro, A07 |
| **Authorization** | Autorizzazione | "Cosa puoi fare?" — verifica permessi | intro, A01 |

## B

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **bcrypt** | — | KDF adattiva per password, con work factor | A04 |
| **Brute force** | Forza bruta | Provare *tutte* le password contro un account | A07 |
| **Business logic flaw** | Falla nella logica di business | Bug che non viola alcuna regola tecnica ma viola le regole del dominio | A06 |

## C

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **CAPTCHA** | — | Challenge umano-vs-bot | A06, A07 |
| **CIA triad** | Triade CIA | Confidentiality, Integrity, Availability | intro |
| **Circuit breaker** | Interruttore | Pattern di resilience: fail-fast verso servizio in difficoltà | A10 |
| **CSP** (Content Security Policy) | — | Header HTTP che limita risorse caricabili → mitiga XSS | A02, A05 |
| **CSRF** (Cross-Site Request Forgery) | — | Forzare l'utente loggato a fare un'azione non voluta | A01 |
| **CVE** (Common Vulnerabilities and Exposures) | — | Identificatore univoco di una vulnerabilità specifica | intro |
| **CWE** (Common Weakness Enumeration) | — | Categoria di debolezza (la "famiglia" del bug) | intro |
| **Credential stuffing** | — | Provare combinazioni `email:password` rubate altrove | A07 |
| **CycloneDX** | — | Standard SBOM di OWASP | A03 |

## D

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **DAST** (Dynamic Application Security Testing) | Test dinamici | Tester che attacca l'app in esecuzione (es. ZAP, Burp) | A05, A06 |
| **Defense in depth** | Difesa in profondità | Più strati indipendenti di protezione | intro |
| **Deny-list** (≠ blacklist) | Lista di negazione | "Blocca questi"; più debole di allow-list | A05 |
| **Deserialization** | Deserializzazione | Ricostruire un oggetto da una rappresentazione serializzata | A08 |
| **DoS** / DDoS | Denial of Service | Rendere indisponibile il servizio | A10 |
| **DOMPurify** | — | Sanitizer HTML client-side, anti-XSS | A05 |

## E

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **ECB** (Electronic CodeBook) | — | Modalità AES insicura, da non usare | A04 |
| **Encoding** (context-aware) | — | Trasformazione che rende un dato innocuo nel suo contesto (HTML, attribute, URL, JS) | A05 |
| **Escalation of privilege** | Escalation di privilegi | Diventare admin senza diritto | A01 |
| **Exploit** | — | Codice/tecnica che sfrutta una vulnerabilità | intro |

## F

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **Fail closed** / fail-secure | Fallire in chiusura | In caso di errore, *nega*. Default sicuro | A10 |
| **Fail open** | Fallire in apertura | In caso di errore, *consenti*. Default insicuro | A10 |
| **FIDO2 / WebAuthn** | — | Standard moderno di autenticazione phishing-resistant (passkey) | A07 |
| **Forced browsing** | Navigazione forzata | Indovinare URL nascosti per accedervi | A01 |
| **Forward secrecy** | Segretezza prospettica | Compromettere chiave oggi non decifra traffico passato | A04 |

## G

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **Gadget chain** | Catena di gadget | Sequenza di metodi sfruttata in deserializzazione per ottenere RCE | A08 |
| **GDPR** | RGPD | Regolamento UE su protezione dati personali | A04, A09 |

## H

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **Hardening** | Irrigidimento | Riduzione della superficie d'attacco | A02 |
| **Hashing** | — | Funzione a senso unico (≠ encryption) | intro, A04 |
| **HIBP** (Have I Been Pwned) | — | Servizio di check breach via email/password | A07 |
| **HMAC** | — | Hash-based Message Authentication Code | A08 |
| **Honeytoken** | Token-trappola | Asset finto messo come esca per intercettare attacchi | A09 |
| **HSTS** (HTTP Strict Transport Security) | — | Header che forza HTTPS sui prossimi accessi | A02, A04 |
| **HSM** (Hardware Security Module) | — | Dispositivo HW per gestire chiavi senza esporle | A04 |
| **HTTP** | — | Protocollo di comunicazione web | intro |
| **HttpOnly** (cookie flag) | — | Cookie non leggibile da JavaScript | intro, A07 |

## I

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **IAM** (Identity and Access Management) | — | Sistema di gestione identità/permessi | A02, A03 |
| **IDOR** (Insecure Direct Object Reference) | — | Accesso a risorse altrui cambiando un identificatore | A01 |
| **Idempotency key** | Chiave di idempotenza | Identifica un'operazione per evitare doppia applicazione su retry | A10 |
| **Injection** | Iniezione | Dati interpretati come comandi | A05 |
| **IV** (Initialization Vector) | Vettore di inizializzazione | Valore casuale usato dai cifrari a blocco; mai riusare con stessa chiave | A04 |

## J

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **JWT** (JSON Web Token) | — | Token stateless firmato (header.payload.signature) | intro, A01, A07 |

## K

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **KDF** (Key Derivation Function) | Funzione di derivazione chiave | Da password produce chiave robusta (Argon2id, bcrypt, scrypt, PBKDF2) | A04 |
| **KMS** (Key Management Service) | — | Servizio cloud per gestire chiavi (AWS KMS, GCP KMS, Azure Key Vault) | A04 |

## L

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **LDAP injection** | — | Iniezione in query LDAP | A05 |
| **Least privilege** | Minimo privilegio | Dare solo i permessi indispensabili | intro, A01, A02 |
| **Log injection** | — | Iniettare righe finte nei log via input non escaped | A09 |
| **LLM Prompt Injection** | — | Convincere un LLM a ignorare le istruzioni di sistema | A05 |

## M

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **MAC** (Message Authentication Code) | — | Codice di autenticazione di messaggio (es. HMAC) | A04, A08 |
| **MD5** | — | Hash deprecato per uso security | A04 |
| **MFA** (Multi-Factor Authentication) | Autenticazione a più fattori | ≥2 fattori di tipo diverso | A07 |
| **MITM** (Man-In-The-Middle) | Uomo nel mezzo | Attaccante in mezzo alla comunicazione | A04 |
| **Misuse case** | Caso d'uso malevolo | Story di "come l'attaccante usa il sistema" | A06 |
| **Mitigation** | Mitigazione | Difesa che annulla/riduce un rischio | intro |

## N

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **NIST** | — | National Institute of Standards and Technology (USA) | A04, A07, A09 |
| **NIST SP 800-63B** | — | Standard autenticazione e password | A07 |
| **NIST SP 800-61** | — | Linee guida incident response | A09 |
| **NoSQL injection** | — | Iniezione in DB non-SQL (Mongo, ecc.) | A05 |
| **NVD** (National Vulnerability Database) | — | Database CVE NIST | A03 |

## O

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **OAuth 2.0** | — | Protocollo di delega autorizzativa | A01, A07 |
| **OPA** (Open Policy Agent) | — | Policy engine come-codice | A01 |
| **OS Command Injection** | — | Eseguire comandi shell tramite input non sanitizzato | A05 |
| **OSV** (Open Source Vulnerabilities) | — | Database vulnerabilità open-source | A03 |
| **OWASP** (Open Worldwide Application Security Project) | — | Community no-profit di security applicativa | intro |

## P

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **Padding oracle** | — | Attacco contro CBC che decifra via messaggi d'errore | A04 |
| **Parametrized query** / prepared statement | Query parametrizzata | Query con parametri separati dalla struttura → no SQLi | A05 |
| **Passkey** | — | Credenziale FIDO2/WebAuthn (biometrica + dispositivo) | A07 |
| **Password spraying** | — | Provare poche password comuni contro tanti account | A07 |
| **Payload** | — | Carica utile di un exploit | intro, A05 |
| **PBKDF2** | — | KDF storica per password | A04 |
| **Pepper** | — | Secret server-side aggiunto alle password (oltre al salt) | A04 |
| **PHI** (Protected Health Information) | Dati sanitari | Dati protetti (HIPAA) | intro |
| **PII** (Personally Identifiable Information) | Dati personali | Nome, email, codice fiscale, indirizzo… | intro, A04 |
| **PQC** (Post-Quantum Cryptography) | Crittografia post-quantistica | Crypto resistente ai computer quantistici | A04 |
| **Prepared statement** | — | Vedi Parametrized query | A05 |
| **Privilege escalation** | Escalation di privilegi | Vedi sopra | A01 |

## R

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **Race condition** | Condizione di gara | Bug di concorrenza, ordinamento operazioni | A06, A10 |
| **Rainbow table** | — | Tabella precomputed di hash per cracking | A04 |
| **Rate limiting** | Limitazione di frequenza | Limite richieste per utente/IP/window | A01, A07, A10 |
| **RCE** (Remote Code Execution) | Esecuzione di codice remoto | Esecuzione arbitraria di codice sul server | A03, A05, A08 |
| **RCE chain** / gadget chain | — | Vedi gadget chain | A08 |
| **Refresh token** | — | Token di lunga durata per ottenere nuovi access token, revocabile | A01, A07 |
| **Replay attack** | Attacco di replay | Riutilizzare token/messaggio catturato | A01 |

## S

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **Saga pattern** | — | Coordinazione transazioni distribuite con compensazioni | A10 |
| **Salt** | — | Valore casuale per record, mescolato all'input prima dell'hash | A04 |
| **SameSite** (cookie flag) | — | Controlla invio del cookie in richieste cross-site | A01, A07 |
| **SAST** (Static Application Security Testing) | Test statici | Analisi sorgente senza esecuzione (Semgrep, CodeQL) | A05, A06 |
| **SBOM** (Software Bill of Materials) | Distinta base software | Lista degli "ingredienti" del software | A03 |
| **scrypt** | — | KDF adattiva per password | A04 |
| **Secure** (cookie flag) | — | Cookie inviato solo via HTTPS | intro, A07 |
| **Secure Development Lifecycle (SDLC)** | Ciclo di sviluppo sicuro | Sicurezza in ogni fase, non solo finale | A06 |
| **Session fixation** | — | Attaccante "fissa" un session ID prima del login | A07 |
| **SHA-1** | — | Hash deprecato per uso security | A04 |
| **SIEM** (Security Information and Event Management) | — | Sistema centralizzato di aggregazione/analisi log | A09 |
| **Sigstore / cosign** | — | Tool/infrastruttura per firma keyless di artefatti | A03, A08 |
| **SLO** (Single Logout) | — | Disconnessione globale in SSO | A07 |
| **SLSA** (Supply-chain Levels for Software Artifacts) | — | Framework di garanzia integrità artefatti | A03 |
| **SOC** (Security Operations Center) | — | Team che monitora alert e risponde | A09 |
| **SPDX** | — | Standard SBOM | A03 |
| **SQLi** (SQL Injection) | — | Iniezione SQL | A05 |
| **SRI** (Subresource Integrity) | Integrità delle subresource | Hash atteso per `<script>`/`<link>` esterni | A08 |
| **SSDLC** | — | Vedi SDLC | A06 |
| **SSO** (Single Sign-On) | — | Login unificato su più applicazioni | A07 |
| **SSRF** (Server-Side Request Forgery) | — | App fa richieste per conto dell'attaccante (assorbita in A01 nel 2025) | A01 |
| **SSTI** (Server-Side Template Injection) | — | Iniezione in template engine server | A05 |
| **STRIDE** | — | Tassonomia di minacce Microsoft (Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation) | intro, A06 |
| **Subresource Integrity** | — | Vedi SRI | A08 |
| **Supply chain** | Catena di fornitura | Tutto il pipeline build/distribuzione/aggiornamento | A03 |

## T

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **Tampering** | Manomissione | Modificare dati in transito o a riposo | intro, A06 |
| **Tenant isolation** | Isolamento tenant | Garantire che dati di clienti diversi non si mescolino | A06 |
| **Threat model / threat modeling** | Modello di minaccia | Analisi strutturata di chi/come/cosa potrebbe attaccare | intro, A06 |
| **TLS** (Transport Layer Security) | — | Protocollo di cifratura per il transport (sostituisce SSL) | intro, A04 |
| **Tokenization** (PCI DSS) | — | Sostituire un dato sensibile con un token "innocuo" | A04 |
| **TOTP** (Time-based One-Time Password) | — | Codice OTP di 6-8 cifre basato su tempo (RFC 6238) | A07 |

## U

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **Use case / misuse case** | — | Storia di uso normale / di abuso | A06 |

## V

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **Vault** (HashiCorp) | — | Tool di secret management | A02, A04 |
| **Vulnerability** | Vulnerabilità | Difetto sfruttabile | intro |

## W

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **WAF** (Web Application Firewall) | — | Firewall a livello applicativo (HTTP) | A02, A05 |
| **WebAuthn** | — | API browser per autenticazione FIDO2 | A07 |
| **WORM** (Write Once Read Many) | — | Storage immutabile dopo scrittura (es. S3 Object Lock) | A09 |

## X

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **XSS** (Cross-Site Scripting) | — | Iniezione di JS nel browser di altri utenti | A05 |
| **XXE** (XML External Entity) | — | Vulnerabilità di parser XML | A02, A05 |

## Y

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **yescrypt** | — | KDF moderna alternativa | A04 |
| **ysoserial** | — | Tool per generare payload di deserializzazione Java (research/test) | A08 |

## Z

| Termine | Italiano | Definizione | Modulo |
|---------|----------|-------------|--------|
| **Zero-day** | — | Vulnerabilità non ancora pubblicamente nota / patchata | A03 |

---

🔄 **Aggiornamento:** se durante lo studio incontri un termine non presente, aggiungilo qui — questo glossario è anche un appunto vivo.

⬅ Torna al [README](README.md) · 📋 [Cheat sheet finale →](99_cheatsheet_finale.md)
