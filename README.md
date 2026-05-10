# Corso OWASP Top 10:2025 — Guida approfondita (IT/EN)

Benvenuto. Questo è un corso self-paced **bilingue** (italiano + termini chiave in inglese) pensato per **principianti** che vogliono imparare a fondo le 10 categorie di rischio più importanti della sicurezza applicativa secondo OWASP 2025.

> Fonte ufficiale: <https://owasp.org/Top10/2025/0x00_2025-Introduction/>

---

## Indice del corso

| # | File | Argomento | Tempo stimato |
|---|------|-----------|---------------|
| 0 | [00_introduzione.md](00_introduzione.md) | Cos'è OWASP, metodologia 2025, prerequisiti tecnici (HTTP, sessioni, autenticazione) | 30-45 min |
| 1 | [01_broken_access_control.md](01_broken_access_control.md) | **A01** — Broken Access Control | 60 min |
| 2 | [02_security_misconfiguration.md](02_security_misconfiguration.md) | **A02** — Security Misconfiguration | 50 min |
| 3 | [03_software_supply_chain_failures.md](03_software_supply_chain_failures.md) | **A03** — Software Supply Chain Failures | 60 min |
| 4 | [04_cryptographic_failures.md](04_cryptographic_failures.md) | **A04** — Cryptographic Failures | 60 min |
| 5 | [05_injection.md](05_injection.md) | **A05** — Injection (SQLi, XSS, Command, LLM Prompt) | 75 min |
| 6 | [06_insecure_design.md](06_insecure_design.md) | **A06** — Insecure Design (threat modeling) | 50 min |
| 7 | [07_authentication_failures.md](07_authentication_failures.md) | **A07** — Authentication Failures | 60 min |
| 8 | [08_software_or_data_integrity_failures.md](08_software_or_data_integrity_failures.md) | **A08** — Software or Data Integrity Failures | 50 min |
| 9 | [09_security_logging_and_alerting_failures.md](09_security_logging_and_alerting_failures.md) | **A09** — Security Logging & Alerting Failures | 45 min |
| 10 | [10_mishandling_of_exceptional_conditions.md](10_mishandling_of_exceptional_conditions.md) | **A10** — Mishandling of Exceptional Conditions ✨ NUOVA | 50 min |
| 99 | [99_glossario.md](99_glossario.md) | Glossario IT↔EN dei termini chiave | consultazione |
| 99 | [99_cheatsheet_finale.md](99_cheatsheet_finale.md) | Sintesi globale + checklist deploy-ready | 20 min |

**Totale:** ~10 ore di studio attivo (esclusi i lab pratici, che possono richiedere altre 10-15 ore).

---

## Come usare questo corso

1. **Parti sempre da [00_introduzione.md](00_introduzione.md).** Anche se hai già fatto sviluppo web, contiene il vocabolario condiviso e la metodologia OWASP 2025.
2. **Procedi in ordine A01 → A10.** Le categorie sono ordinate per *prevalenza × impatto*, dalla più critica alla meno critica. I moduli finali (A09, A10) presuppongono concetti incontrati nei precedenti.
3. **Per ogni modulo segui le 12 sezioni:**
   - Sezioni 1-5 → leggi e capisci.
   - Sezione 6 (codice vulnerabile vs sicuro) → riscrivi tu il fix prima di guardare la soluzione.
   - Sezione 9 (lab pratico) → fallo davvero, non saltarlo. È dove si interiorizza la conoscenza.
   - Sezione 10 (quiz) → prima rispondi, poi controlla.
4. **Conserva [99_cheatsheet_finale.md](99_cheatsheet_finale.md) come reference** dopo il corso, prima di ogni deploy.

---

## Struttura di ogni modulo (A01–A10)

Ogni file di categoria ha **12 sezioni fisse**, in modo che tu sappia sempre dove cercare:

1. **Obiettivi della lezione** — cosa saprai fare alla fine
2. **Prerequisiti** — cosa serve sapere prima
3. **Background OWASP** — statistiche e dati ufficiali
4. **Descrizione** — cos'è la vulnerabilità in linguaggio semplice
5. **Esempi di attacco** — i 3 scenari OWASP raccontati passo-passo
6. **Codice vulnerabile vs codice sicuro** — snippet a confronto
7. **Come prevenirlo** — mitigazioni concrete
8. **CWE rilevanti** — i 5-8 CWE più importanti
9. **Lab pratico** — esercizio con link a piattaforma
10. **Quiz di autovalutazione** — 6-8 domande con soluzioni
11. **Cheat sheet** — riassunto in 60 secondi
12. **Risorse e approfondimenti** — link OWASP e oltre

---

## Convenzioni

- **Bilingue:** i titoli sono nel formato `Italiano (English)`. Termini tecnici standard (XSS, CSRF, JWT, TLS, hashing…) restano in inglese: li troverai così in ogni documentazione, tool e CVE.
- **Codice:** uso di Node.js, Python (Flask) e Java (Spring) a rotazione, per esposizione varia. I principi sono linguaggio-agnostici.
- **Box speciali:**
  - ⚠️ **Trappola comune** — errori che fanno tutti
  - 💡 **Buona pratica** — pattern da imitare
  - 🔑 **Concetto chiave** — da memorizzare
  - 🧪 **Esercizio rapido** — da fare al volo

---

## Prerequisiti tecnici minimi

- Saper leggere codice di base in almeno un linguaggio (Python, JS o Java).
- Familiarità con il concetto di "applicazione web" (browser ↔ server).
- Tutto il resto (HTTP, sessioni, autenticazione, hashing, TLS) viene spiegato in [00_introduzione.md](00_introduzione.md) e nei singoli moduli.

Non serve sapere già nulla di sicurezza: questo corso parte da zero.

---

## Licenza dei contenuti

I contenuti **derivati da OWASP** (descrizioni, scenari di attacco, mitigazioni, statistiche) sono ripresi da <https://owasp.org/Top10/2025/> e rilasciati sotto **Creative Commons Attribution 3.0 Unported License**. Le rielaborazioni in italiano, gli esempi di codice, i quiz e i lab di questo corso sono materiale didattico originale.
