# tlwe2021-krypto-3

tech:lounge Winter Edition 2021 // Verschlüsselung: Zertifikate verstehen und anwenden

## Passwörter speichern

### Passwörter im Klartext

username | password
---------|-------------
jane.doe | secret
john.doe | 12345

Nachteil: Passwörter liegen im Klartext vor (insbesondere in Verbindung mit E-Mail-Adressen)

### Verschlüsselte Passwörter

username | encryptedPassword
---------|------------------
jane.doe | hvreuheirwuf4
john.doe | fh347fh3489hf4h9

Nachteil: Passender Schlüssel muss vorliegen (und zwar im Klartext!)

### Gehashte Passwörter

username | hashedPassword
---------|---------------------------------
jane.doe | b769ff1cd964460a8273c906012c7281
john.doe | bc6616e06c174cd7b75945b2fdeba726

Nachteil: Lässt sich mit Rainbow-Tables, die auf Wörterbüchern basieren, indirekt brechen

### Gehashte und gesalzene Passwörter

username | salt | hashedAndSaltedPassword
---------|----------------------------------------
jane.doe | ftu6 | b362785611bd49d5924b7fe0f869e0b7
john.doe | t68f | 94a2b9d3add14f3b97a54e8f53bf9f5d

Nachteil: Massive Rechenleistung durch Cloud verfügbar

### Hash vom Hash vom Hash vom …

username | salt | iterations | hashedHashedHashedAndSaltedPassword
---------|--------------------------------------------------------
jane.doe | ftu6 |      50000 | b362785611bd49d5924b7fe0f869e0b7
john.doe | t68f |     100000 | 94a2b9d3add14f3b97a54e8f53bf9f5d

Nachteil: Nicht alle Hash-Funktionen sind sicher dafür

### Spezialisierte Algorithmen

- Machen "im Prinzip" genau das unter der Haube
- Sind kryptografisch sicher

- Algorithmen
  - Fokus auf Rechenleistung
    - pbkdf2 (Password-based key derivation function)
    - bcrypt
  - Fokus auf Speicher / RAM
    - scrypt
  - Gemischt (Rechenleistung, Speicher, …)
    - argon2

## Diffie-Hellman-Key-Exchange (DHKE)

- Kein sicherer Kanal zwischen zwei Parteien
- Man braucht aber (ad-hoc) einen gemeinsamen Schlüssel

### Anschaulich

Noah                                       Golo
                    gelb (öffentlich)
blau (privat)                              rot (privat)
grün = gelb+blau                           orange = gelb+rot
        ---------------- öffentlich -----> grün (= gelb+blau)
orange (= gelb+rot) <--- öffentlich -----------
orange + blau                              grün + rot
= gelb + rot + blau                        = gelb + blau + rot
= ocker                                    = ocker

Angreifer:
- gelb
- grün
- orange

### Mathematisch

Noah                                        Golo
                g = <p, p = Primzahl
a (privat)                                  b (privat)
A = g ^ a mod p                             B = g ^ b mod p
          --------------------------------> A
        B <--------------------------------
Key = B ^ a mod p                           Key = A ^ b mod p
      = (g^b mod p)^a mod p                 = (g^a mod p)^b mod p

                      g = 3, p = 7
a = 2                                       b = 3
A = 3 ^ 2 mod 7                             B = 3 ^ 3 mod 7
  = 2                                         = 6
          --------------------------------> A = 2
    B = 6 <--------------------------------

Key = 6 ^ 2 mod 7                           Key = 2 ^ 3 mod 7
    = 1                                         = 1

## Das HTTPS-Protokoll

- HTTPS = HTTP + SSL (beziehungsweise TLS)
  - Verschlüsselung zwischen Client und Server
    - Symmetrische Verschlüsselung
    - Diffie-Hellman-Key-Exchange-Verfahren (DHKE)
  - Identität des Servers validieren
    - Zertifikate FTW :-)

Client                                    Server
- public key des Servers                  - private key
                                          - public key
                                            - Domainname: example.com
                                            - Ablaufdatum
                                            - Digitale Signatur inkl Hash

              Vertrauenswürdiger Dritter (Certificate Authority)
                            - private key
                            - public key
                              - Domainname: my-ca.com
                              - Ablaufdatum
                              - Digitale Signatur inkl Hash

              Vertrauenswürdiger Vierter (Certificate Authority)
                ...

              Vertrauenswürdiger X-ter (Root Certificate Authority)
                ...

Zertifikat = Public Key + Metadaten + Hash + Signatur

## OpenSSL

```shell
# Privaten Schlüssel generieren
$ openssl genrsa -out privateKey.pem 4096

# Öffentlichen Schlüssel extrahieren
$ openssl rsa -in privateKey.pem -pubout > publicKey.pem

# CSR inklusive privatem Schlüssel generieren
$ openssl req -out certificateSigningRequest.pem -new -newkey rsa:4096 -nodes -keyout privateKey.pem
```

## Alternativen für eine eigene CA

- [Vault](https://www.vaultproject.io/)
- [Let's Encrypt](https://letsencrypt.org/)

## Was schützt HTTPS?

- HTTP-Header und HTTP-Daten, die übertragen werden
- Verifikation der Identität des Servers

Was nicht geschützt wird:

- Mit welchem Server (Domain) man spricht
- DNS-Abfragen (dafür gibt es inzwischen zB DNS-over-HTTPS)
- Häufigkeit / Länge von Sessions

## Authentifizierung und Autorisierung

- Authentifizierung
  - Wer ist jemand?
- Autorisierung
  - Was darf jemand?

## OAuth (2.0)

- Für Autorisierung
- Rechtevergabe über Dienstgrenzen hinweg
- Access Token
  - Nachweis, dass jemand (Dienst, …) berechtigt ist, Daten für mich abzufragen, zu erstellen, zu ändern, …
  - Enthält keine Daten über die Anwenderin oder den Anwender
  - Natürlich muss *ich* mich gegenüber dem Token ausgebenden Dienst authentifizieren (und autorisieren ;-)), aber in dem Access Token stecken keine Daten über diese Authentifizierung
- Access Token wurde erweitert um diese Identitätsdaten
  - Widerspricht eigentlich OAuth-Standard
  - Hat zu neuem Standard geführt: OpenID Connect
- Rollen
  - Resource Owner: Endnutzer:in
  - Client: Die Anwendung, die für Endnutzer:in auf geschützte Daten zugreifen will
  - Resource Server: Die API, von dem man Daten abfragen will, wofür man aber eine Berechtigung braucht
  - Authorization Server: Die Stelle, wo sich Endnutzer:in anmeldet und Access Token erhält (das ist der zentrale OAuth-Server)
- Es gibt verschiedene OAuth-"Strategien" (sogenannte Grants)
  - In OpenID Connect heißen die Grants dann Flows …
  - Die Zugangsdaten bleiben immer beim Resource Owner
  - OAuth gibt nicht immer Vollzugriff, kann auch eingeschränkter Zugriff sein
- Access Token hat keine Semantik
  - Im Prinzip ist das Access Token nur ein Zufallsstring
  - Der Resource Server muss beim Authorization Server nachfragen bezüglich Validität, Rechten, …
  - Daher hat sich das Format JWT durchgesetzt, was (vereinfacht gesagt) ein JSON-Objekt mit Signatur ist (die dann auch dezentral verifiziert werden kann)
- PKCE-Verfahren (Proof Key for Code Exchange)
  - Als Client ein Secret überlegen (kann/sollte zufällig sein)
  - Einen Hash-Algorithmus auswählen, zB SHA256
  - Secret hashen und den Hash an den Authorization-Server senden
  - Später, beim Eintauschen des Codes gegen ein Access-Token, ein Secret mitschicken
  - So kann der Authorization-Server den Hash verifizieren
- Der wichtigste Grant
  - Authorization Code Grant
  - Am besten im RFC nachlesen und die PKCE-Extension angucken

## OpenID Connect (OIDC)

- Allgemeines
  - Für Authentifizierung
  - Entspricht zu >90% OAuth, basiert auf OAuth
  - Erweitert OAuth um Daten über die Anwenderin beziehungsweise den Anwender
- Ergänzt OAuth um das sogenannte "Identity Token"
  - Erhält man zusätzlich zum Access Token
  - Dient der Authentifizierung
  - Sind im Format JWT
