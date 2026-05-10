# A09:2025 — Errori di logging e alerting (Security Logging & Alerting Failures)

> ✏️ **Rinominata** da *"Logging and **Monitoring** Failures"* (2021). Il focus 2025 è il passaggio da **monitoraggio passivo** ad **azione**: logghi → ti accorgi → **rispondi rapidamente**. Senza alerting, anche i log perfetti sono inutili.

---

## 1. Obiettivi (Learning Objectives)

Alla fine di questo modulo saprai:

- Distinguere **logging**, **monitoring** e **alerting** e capire perché OWASP ha aggiunto l'ultimo nel titolo.
- Sapere **cosa loggare** e **cosa NON loggare** (PII, password, token).
- Implementare logging strutturato (JSON), con correlation ID e log injection prevention.
- Definire **use case** di alerting (credential stuffing, exfiltration, privilege escalation) e gli **alerting threshold**.
- Costruire un mini-piano di **incident response** (NIST 800-61).

---

## 2. Prerequisiti

- Concetto di **CIA** triad (in particolare **availability** e **integrity**).
- Concetto di **logging strutturato** vs free-text.
- Concetto di **SIEM** (Security Information & Event Management) — sistema centralizzato che aggrega log.

---

## 3. Background OWASP

| Metrica | Valore |
|---------|--------|
| Posizione 2025 | **#9** (rinominata) |
| CWE mappati | 5 |
| Max incidence rate | 11.33% |
| Avg incidence rate | 3.91% |
| Total occurrences | 260.288 |
| Total CVE | 723 |

> 📌 Pochi CWE (5), ma **impatto cumulativo enorme**: senza A09 non *vedi* gli altri attacchi. Vedere fa parte di "rispondere".

---

## 4. Descrizione (Description)

Una sintesi delle 16 condizioni OWASP che rendono un'app vulnerabile in A09:

### Lato logging

1. **Eventi critici non loggati o loggati a singhiozzo**: login, login falliti, transazioni alte, cambi di privilegio.
2. **Warning/error con messaggi inadeguati o poco chiari** — log "errore generico" non aiuta nessuno.
3. **Integrità dei log non protetta** — i log sono modificabili dall'attaccante che ha accesso al server.
4. **Log non monitorati** per attività sospette.
5. **Log solo locali**, senza backup. Un server compromesso = log persi/manomessi.
6. **Sensibili logged**: password, token, carte, PII, PHI.
7. **Log non encoded correttamente** → **log injection** (l'attaccante inietta righe finte nel log per ingannare l'analisi).
8. **Errori e condizioni eccezionali non gestiti** (link diretto con A10).

### Lato alerting

9. **Threshold di alert assenti o inefficaci**.
10. **Alert non ricevuti / non revisionati in tempo ragionevole**.
11. **DAST scan e pentest non triggerano alert** — significa che attacchi reali nemmeno si vedono.
12. **L'app non è in grado di rilevare/escalare attacchi attivi in tempo reale**.
13. **Use case di alerting** mancanti o obsoleti.
14. **Troppi falsi positivi** rendono impossibile distinguere il segnale.
15. **Playbook di risposta incompleti** — alert arriva, nessuno sa cosa fare.

### La "regola dei 3" da memorizzare

🔑 **Logging** = scrivere ciò che è successo.
🔑 **Monitoring** = guardare i log e le metriche.
🔑 **Alerting** = generare un segnale azionabile quando qualcosa va storto.
🔑 **Incident response** = la procedura per *agire* su quel segnale.

OWASP A09 vuole che tu abbia tutti e quattro.

---

## 5. Esempi di attacco (Example Attack Scenarios)

### Scenario #1 — Breach scoperto da terzi dopo 7 anni (sanità)

> *"A children's health plan provider couldn't detect a breach due to a lack of monitoring and logging. An external party informed the health plan provider that an attacker had accessed and modified thousands of sensitive health records of more than 3.5 million children. A post-incident review found...the data breach could have been in progress since 2013, a period of more than seven years."* — OWASP

L'app aveva vulnerabilità note non patchate (A03). **Senza logging/monitoring**, sette anni di accesso non autorizzato sono passati invisibili.

### Scenario #2 — Aviazione: notifica del breach dal vendor

> *"A major Indian airline had a data breach involving more than ten years' worth of personal data of millions of passengers...The data breach occurred at a third-party cloud hosting provider, who notified the airline of the breach after some time."* — OWASP

L'azienda non se n'è accorta da sé. Il vendor ha avvertito *dopo*. Conseguenze: dieci anni di PII passeggeri (passaporti, carte) compromessi senza alcun trigger interno.

### Scenario #3 — Aviazione europea: 400.000 record di pagamento + GDPR fine

> *"A major European airline suffered a GDPR reportable breach...attackers who harvested more than 400,000 customer payment records. The airline was fined 20 million pounds."* — OWASP

L'attacco è durato il tempo necessario per essere attivamente malevolo. Detection in tempo reale o quasi-reale lo avrebbe interrotto. La multa GDPR (£20M) è di fatto il **costo della mancanza di alerting**.

---

## 6. Pratiche / config vulnerabili vs sicure

### Esempio A — Logging strutturato (Node con pino)

❌ **Vulnerabile:**

```javascript
console.log('login failed for ' + email + ' from ' + req.ip);     // free-text, no correlation, log injection!
```

Problemi: niente struttura, niente livello, niente request ID, l'`email` non è encoded → un email tipo `\nALERT: superadmin logged in` falsifica il log.

✅ **Sicuro:**

```javascript
const pino = require('pino');
const logger = pino({ redact: ['req.headers.authorization', '*.password', '*.token'] });

logger.warn({
  event: 'login_failed',
  email,                          // pino fa il JSON-escape
  ip: req.ip,
  ua: req.get('User-Agent'),
  request_id: req.id,             // correlazione: stesso ID di richiesta in tutti i log
  attempt: counter,
}, 'login failed');
```

### Esempio B — Cosa NON loggare

```python
# ❌ MAI
logger.info(f"login user={email} password={password}")
logger.debug(f"jwt={token}")
logger.info(f"card={card_number}")

# ✅ ok
logger.info("login_attempt", extra={"email": email})
logger.debug("jwt_validated", extra={"jwt_id": jti(token)})       # solo l'id
logger.info("payment_completed", extra={"card_last4": card[-4:]})
```

Tipici redact:

- password, password_hash, OTP code, recovery code,
- token JWT/refresh, API key, session ID,
- PAN (numero carta intero), CVV,
- chiavi private, secret API,
- PII estesa (codice fiscale, indirizzo) → solo dove necessario, classificato.

### Esempio C — Integrità dei log

❌ Log scritti in `/var/log/app.log` su disco locale, modificabili da chi ottiene root.

✅ **Append-only** + **central forwarding**:

- Log inviati in tempo reale a un **SIEM** (Elastic, Splunk, Datadog, Sumo, Loki/Grafana, Wazuh) tramite **journald → fluent-bit → S3/SIEM**.
- Storage **WORM** (Write Once Read Many) per audit critici (S3 Object Lock).
- Hash chain o firma periodica del log (es. Auditbeat con HMAC, oppure rsyslog-cms).

### Esempio D — Use case di alert (esempi concreti)

Esempi di **detection rules** in pseudo-SIEM:

```yaml
- name: credential_stuffing
  condition: count(event=login_failed group_by=ip) > 50 in 5m
  severity: high
  action: alert_security_channel + temp_block_ip

- name: privilege_escalation_anomaly
  condition: event=role_changed AND new_role=admin AND actor!=cfg.admin_actor
  severity: critical
  action: page_oncall

- name: data_exfiltration
  condition: bytes_out_per_user > 100MB in 10m AND user.role != "support"
  severity: high
  action: alert + freeze_session

- name: deserialization_failure_burst
  condition: count(event=deserialization_error) > 20 in 1m
  severity: medium
  action: alert
```

---

## 7. Come prevenirlo (How to Prevent)

Mitigazioni dirette OWASP, raggruppate:

### Logging

1. **Login, access control e validation failures** vanno tutti loggati con **user context** sufficiente per riconoscere account sospetti.
2. **Retention** sufficiente per analisi forensi ritardate (settimane/mesi, dipende dal regolamento — GDPR ha vincoli precisi).
3. Tutto ciò che **contiene un controllo di sicurezza** logga sia **success** sia **failure**.
4. **Formato adatto al SIEM** — JSON strutturato è lo standard de facto.
5. **Encoding corretto** del log per prevenire **log injection** (se loggi user input, escapalo prima — newline, control chars).
6. **Audit trail** su tutte le transazioni con **integrity controls** (firma, hash chain, WORM).
7. Le transazioni che generano errore vengono **rolled back e ripartite** (collegamento con A10).
8. **Fail closed** sempre.

### Alerting

9. Se l'app o l'utente si comportano in modo sospetto → **emetti un alert**.
10. Linee guida per gli sviluppatori su come implementarlo, oppure **acquista** un sistema (Datadog, Splunk).
11. **DevSecOps + Security teams** definiscono **use case** di alerting **+ playbook**.
12. **SOC team**: i sospetti vengono detected e responded **rapidamente**.
13. **Honeytoken** sparpagliati nell'app come trappole (es. fake account "admin_legacy", se qualcuno ci accede è red flag immediata).
14. **Behavior analysis / AI** per ridurre falsi positivi.
15. **Incident response & recovery plan**: **NIST 800-61r2** è lo standard.
16. **Educare gli sviluppatori** su come si presentano gli attacchi e gli incidenti.

### Modello pratico: la "piramide di rilevazione"

```
        ┌─────────────────────┐
        │  Incident Response  │  ← cosa fai quando suona
        ├─────────────────────┤
        │      Alerting       │  ← regole, threshold, severity, deduplication
        ├─────────────────────┤
        │     Monitoring      │  ← dashboard, metriche, anomaly detection
        ├─────────────────────┤
        │       Logging       │  ← cosa, dove, quanto, integrità
        └─────────────────────┘
```

Costruisci dal basso, ma **non fermarti al primo livello**. La maggior parte delle org si ferma a "logging" e A09 li punisce.

---

## 8. CWE rilevanti

| CWE | Nome |
|-----|------|
| **CWE-117** | Improper Output Neutralization for Logs (**log injection**) |
| **CWE-221** | Information Loss of Omission |
| **CWE-223** | Omission of Security-relevant Information |
| **CWE-532** | Insertion of Sensitive Information into Log File |
| **CWE-778** | Insufficient Logging |

---

## 9. Lab pratico

### Lab consigliati

1. **Elastic Security Lab** — <https://github.com/elastic/detection-rules>: studia le detection rule reali.
2. **HELK** (Hunting ELK) — stack ELK + Kafka + Spark per detection lab in casa.
3. **TheHive Project** — case management open source.
4. **Atomic Red Team** — <https://github.com/redcanaryco/atomic-red-team>: esegue tecniche MITRE ATT&CK in lab per testare le detection.
5. **OWASP AppSensor** — <https://owasp.org/www-project-appsensor/>: framework per detection in-app.

### 🧪 Esercizio guidato — Da `console.log` a logging maturo

1. Prendi una mini-app Express. Aggiungi `pino` e fai logging strutturato di:
   - login (success/failed) con email, ip, user-agent, request_id;
   - access control failure (ogni 403 o 404 sui dettagli risorsa);
   - errori 5xx con stack trace **solo lato server**.
2. Aggiungi `pino-http` per logging delle request, **redact** del header `Authorization`.
3. Forwarda i log su **stdout** in JSON.
4. (Lab) **Loki + Grafana** in Docker:
   ```bash
   docker run -d --name loki -p 3100:3100 grafana/loki
   docker run -d --name grafana -p 3000:3000 grafana/grafana
   ```
   Configura un datasource Loki, crea una dashboard "login_failed per IP".
5. Definisci una rule: *"se più di 30 login_failed in 5m da uno stesso IP, allerta su Slack"*.
6. Lancia un piccolo script che simula 100 login falliti dallo stesso IP. Vedi l'alert?

✅ **Hai completato** se: hai un alert reale che ti suona quando simuli un brute force.

---

## 10. Quiz di autovalutazione

1. **Logging**, **monitoring**, **alerting**, **incident response**: spiegali in una frase ciascuno.
2. Cosa è **log injection**? Esempio?
3. Tre cose che **non devi** loggare e perché.
4. Cosa è **WORM storage** e perché aiuta l'integrità dei log?
5. **Honeytoken** come si usano in pratica?
6. Cosa significa **"fail closed"**? Quando faresti il contrario?
7. Detection rule "**count(login_failed) > 50 in 5m group by ip**" — quale attacco mira a rilevare?
8. Perché un **eccesso di falsi positivi** è una falla di sicurezza, non un fastidio operativo?
9. Cosa è **NIST 800-61** e a cosa serve concretamente?

<details>
<summary>📖 Soluzioni</summary>

1. **Logging** = registrare gli eventi. **Monitoring** = osservarli (dashboard, metriche). **Alerting** = generare segnali azionabili quando qualcosa è anomalo. **Incident response** = la procedura strutturata per agire su quei segnali.
2. È quando l'attaccante inserisce caratteri di controllo (newline, ANSI escape) in un input che finisce nel log, **falsificando** o **camuffando** righe di log. Es.: registrazione con email `attacker\nINFO admin logged in successfully` — chi legge vede una riga "admin logged in" che non è mai successa. Mitigazione: **escape**/encoding del log e formato strutturato (JSON).
3. (a) Password / OTP / recovery code → riusabili da chi legge il log. (b) Token JWT / API key / session ID → permettono impersonation se leakati. (c) PAN/CVV / dati sanitari → violazione GDPR/PCI DSS, alimentano breach a cascata.
4. *Write Once Read Many* — storage che permette scrittura ma **non modifica/cancellazione** prima di una retention. Es. **S3 Object Lock**. Fa sì che un attaccante che ottenga accesso non possa "ripulire" i log per nascondere le proprie tracce.
5. Sono **trappole**: account fake "admin_legacy", file `passwords.txt` finto, chiave API fake hardcoded. Nessun utente legittimo li tocca → un accesso = **alert critico** quasi senza falsi positivi. Bassissimo costo, altissimo segnale.
6. **Fail closed** = se qualcosa va storto, **nega** l'azione (deny). **Fail open** = consenti per default in caso di errore (pericoloso). Eccezione: alcuni controlli di availability (es. captcha service down) possono essere "fail open" temporaneo per non bloccare gli utenti — purché loggato e alerting attivo.
7. Tipicamente **credential stuffing** o **brute force** distribuito su un singolo IP. Variazione utile: per **password spraying** la query è invertita (poche password, tanti utenti, IP diversi → group by user-agent / sequenza).
8. Perché allena gli operatori a **ignorare** gli alert. Quando arriva quello vero, viene chiuso come "rumore". È il classico "**alert fatigue**". Ridurre i falsi positivi è investimento di sicurezza, non di comodità.
9. *NIST SP 800-61* — la guida federale USA su come strutturare un **incident response program**: ruoli, fasi (Preparation → Detection → Containment → Eradication → Recovery → Lessons learned), comunicazione, raccolta evidenze. Concretamente: lo usi come scaffolding per costruire i tuoi runbook.

</details>

---

## 11. Cheat sheet — A09 in 60 secondi

- 📝 **Logga** auth, access control, validation failures, transazioni alte, cambi privilegio.
- 🚫 **NON loggare** password, token, OTP, PAN/CVV, dati sanitari.
- 🧱 **Strutturato**: JSON con livello, request_id, user_id (mai email/password!), timestamp.
- 🛡️ **Integrità**: forward to SIEM, append-only, WORM per audit critici.
- 🔥 **Alerting** con use case definiti: credential stuffing, privilege escalation, exfiltration, deserialization burst.
- 🍯 **Honeytoken** = ROI altissimo.
- 🩺 **Riduci falsi positivi** o gli alert si ignorano (alert fatigue).
- 📋 **Playbook + IR plan** (NIST 800-61) per ogni alert.
- 🔁 **DAST/pentest** devono triggerare alert: se non li trigger, non triggererai veri attacchi.
- 🚪 **Fail closed**, sempre. Logga il fallimento.

---

## 12. Risorse e approfondimenti

- 🌐 [Pagina OWASP A09:2025](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)
- 📘 [OWASP Cheat Sheet — Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- 📘 [OWASP Cheat Sheet — Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)
- 📘 [OWASP AppSensor](https://owasp.org/www-project-appsensor/) — detection in-application
- 📖 [NIST SP 800-61r2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r2/final)
- 📖 [NIST SP 800-92 — Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final)
- 🛠️ [pino (Node)](https://getpino.io/), [structlog (Python)](https://www.structlog.org/), [Logback/SLF4J + JSON](https://logback.qos.ch/)
- 🛠️ [Loki + Grafana](https://grafana.com/oss/loki/) — stack open source
- 🛠️ [Wazuh](https://wazuh.com/), [Elastic Security](https://www.elastic.co/security), [Splunk](https://www.splunk.com/)
- 🛠️ [TheHive](https://thehive-project.org/) — case management IR
- 🎯 [MITRE ATT&CK](https://attack.mitre.org/) — tassonomia di tattiche/tecniche per detection rules
- 🔬 [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — test detection lab

---

⬅ Modulo precedente: [08_software_or_data_integrity_failures.md](08_software_or_data_integrity_failures.md)
➡ Prossimo: [10_mishandling_of_exceptional_conditions.md](10_mishandling_of_exceptional_conditions.md)
