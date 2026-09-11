# ioBroker.netwatch

Deutsch | [English](README.md)

`ioBroker.netwatch` ist ein passiver Netzwerkmonitor für Linux. Er zeichnet
Netzwerkpakete mit `dumpcap` im PCAPNG-Format auf und lässt sie von `tshark`
dekodieren. Dadurch steht ein großer Teil der Wireshark-Protokollerkennung zur
Verfügung, ohne die Protokolle unsicher oder unvollständig in JavaScript
nachzubauen.

> Netzwerkaufzeichnungen können Kennwörter, Cookies, Gerätekennungen und andere
> sensible Inhalte enthalten. Netwatch überträgt keine Captures an Cloud-Dienste
> und enthält keine Firewall-, MITM- oder Manipulationsfunktionen.

## Funktionen

- Live-Paketliste mit Quelle, Ziel, Protokoll, Ports, Länge und Information
- Wireshark-Display-Filter und getrennte BPF-Capture-Filter
- vollständige Paketdetails bei Auswahl eines Pakets
- Hex- und ASCII-Ansicht
- PCAP-/PCAPNG-Import, Speicherung, Download, Analyse und Löschen
- Conversations, Endpoints, Geräte und Protokollstatistiken
- begrenzter RAM-Ringpuffer und begrenzbarer Festplattenspeicher
- WebSocket-Batches statt Polling für jedes einzelne Paket
- automatische Prüfung von `tshark`, `dumpcap` und Capture-Rechten
- geführte Systemeinrichtung mit kopierbaren Linux-Befehlen
- sicherer Shutdown aller Capture- und Analyseprozesse
- neues Netwatch-Symbol für die ioBroker-Adapterübersicht

## Unterstützte Systeme

- Debian
- Ubuntu
- Raspberry Pi OS
- vergleichbare Linux-Installationen mit ioBroker
- Node.js 20 oder neuer
- ioBroker js-controller 6.0.11 oder neuer

Windows und ein automatischer Docker-Betrieb gehören noch nicht zu Version 1.

## Installation aus GitHub

In ioBroker Admin unter **Adapter → Adapter aus eigener URL installieren**
folgende Adresse eintragen:

```text
https://github.com/TheBam1990/ioBroker.netwatch
```

Danach eine Instanz von `netwatch` anlegen. Die Node.js-Abhängigkeiten werden
von ioBroker automatisch installiert. Linux-Systempakete und privilegierte
Capture-Rechte werden aus Sicherheitsgründen nicht automatisch verändert.

## Einmalige Linux-Systemeinrichtung

Nach der Adapterinstallation die Netwatch-Weboberfläche öffnen und dort
**Einstellungen → Systemeinrichtung** auswählen. Die Seite prüft:

1. Ist `tshark` installiert?
2. Ist `dumpcap` installiert?
3. Darf der Benutzer `iobroker` Netzwerkinterfaces mitschneiden?

Für Debian, Ubuntu und Raspberry Pi OS werden diese Befehle angezeigt:

```bash
sudo apt update
sudo apt install -y tshark
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark iobroker
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
sudo systemctl restart iobroker
```

Bei der Paketabfrage muss die Paketerfassung für Benutzer ohne Root-Rechte
zugelassen werden. Anschließend kann die Einrichtung geprüft werden:

```bash
getcap /usr/bin/dumpcap
sudo -u iobroker dumpcap -D
```

Erwartet wird bei `getcap` mindestens:

```text
/usr/bin/dumpcap cap_net_admin,cap_net_raw=eip
```

Der komplette ioBroker-Adapter darf und muss nicht als root laufen. Nur
`dumpcap` erhält die eng begrenzten Linux-Capabilities zum Mitschneiden.

## Weboberfläche

Netwatch verwendet für die großen Live-Datenmengen eine eigene Weboberfläche.
Standardmäßig bindet sie ausschließlich an `127.0.0.1`. Für Zugriff aus dem LAN
kann in der Adapterkonfiguration `0.0.0.0` eingestellt werden. In diesem Fall
müssen ein Benutzername und ein starkes Kennwort gesetzt werden. In nicht
vertrauenswürdigen Netzen empfiehlt sich zusätzlich ein TLS-Reverse-Proxy.

Wichtige Einstellungen:

- **Capture Interface:** normalerweise `eth0`, `enp…` oder `wlan0`
- **Auto Start:** Capture nach Adapterstart automatisch beginnen
- **Memory Packet Limit:** maximale Zahl der Tabellenpakete im RAM
- **Capture Directory:** Speicherort der PCAPNG-Dateien
- **Maximum Capture Size:** Größenlimit einer Sitzung
- **Maximum Total Storage:** Gesamtlimit aller Capture-Dateien
- **Retention Days:** automatische Aufbewahrungsdauer
- **Web Bind/Port:** Adresse und TCP-Port der Oberfläche
- **Web Username/Password:** Zugangsschutz der Oberfläche

## Capture starten

1. Unter **Live Capture** ein Interface auswählen.
2. Optional einen BPF-Capture-Filter eintragen.
3. Optional einen Wireshark-Display-Filter eintragen und prüfen.
4. **Start** drücken.
5. Mit **Pause**, **Weiter** oder **Stop** die Sitzung steuern.

Jede Sitzung wird als PCAPNG gespeichert. Einzelne Pakete werden nicht als
ioBroker-States angelegt; nur zusammengefasste Statistiken erscheinen in den
States.

## Capture-Filter und Display-Filter

Ein Capture-Filter reduziert bereits beim Mitschneiden die Datenmenge. Er nutzt
BPF-Syntax:

```text
host 192.168.1.50 and tcp
port 2404
tcp port 502
```

Ein Display-Filter lässt die PCAPNG-Datei unverändert und filtert nur die von
`tshark` dekodierte Anzeige:

```text
ip.addr == 192.168.1.55
tcp.port == 2404
modbus
mqtt.topic contains "zigbee2mqtt"
tcp.port == 443 && tls
```

Ungültige Display-Filter werden vor der Anwendung geprüft und beenden einen
laufenden Capture nicht.

## Welche Netzwerkpakete sind sichtbar?

Ein Rechner an einem normalen Switch sieht hauptsächlich seinen eigenen
Verkehr sowie Broadcasts und Multicasts. Für den Verkehr anderer Geräte wird
üblicherweise benötigt:

- ein SPAN-/Mirror-Port eines Managed Switches,
- ein Capture direkt auf Router oder Gateway oder
- ein Netzwerk-TAP.

Ohne diese Einrichtung ist der Adapter nicht defekt; der gewünschte fremde
Unicast-Verkehr erreicht lediglich das Capture-Interface nicht.

## Fehlerbehebung

- **tshark/dumpcap rot:** Pakete über die Systemeinrichtung installieren.
- **Capture-Rechte rot:** Gruppe und Capabilities prüfen, danach ioBroker neu starten.
- **Keine fremden Geräte sichtbar:** Mirror-/SPAN-Port prüfen.
- **Webseite nicht erreichbar:** Bind-Adresse, Port und Firewall prüfen.
- **Anmeldung erscheint:** konfigurierten Web-Benutzer und das Kennwort verwenden.
- **Ungültiger Filter:** BPF- und Wireshark-Display-Filter nicht verwechseln.
- **Interface verschwunden:** Capture stoppen, Interface neu auswählen und starten.

## Datenschutz und Sicherheit

- keine Telemetrie und keine Cloud-Übertragung
- keine Shell-Konkatenation von Benutzereingaben
- keine Firewalländerungen oder Paketmanipulation
- kein TLS-MITM und keine Zertifikatsinjektion
- keine Payloads im normalen ioBroker-Log
- Capture-Dateien nur in einem kontrollierten Adapterverzeichnis
- Pfadprüfung gegen `../` und absolute Upload-Pfade

## Entwicklung und Tests

```bash
npm ci
npm run check
npm pack
```

`npm run check` führt TypeScript-Compiler, Unit-Tests und ESLint aus. GitHub
Actions prüft Node.js 20 und 22 bei Pushes und Pull Requests.

## Lizenz

MIT License, Copyright TheBam1990
