# ioBroker.netwatch

[Deutsch](READMEde.md) | English

`ioBroker.netwatch` ist ein passiver Netzwerkmonitor für Linux. Der Adapter nutzt **dumpcap** für die Paketerfassung, **PCAPNG** als Rohformat und **tshark** für Wireshark-kompatible Protokolldekodierung. Einzelne Pakete werden bewusst nicht als ioBroker-States angelegt.

> Netzwerk-Captures können Kennwörter, Cookies, Gerätekennungen und andere sensible Inhalte enthalten. Netwatch sendet keine Daten an Cloud-Dienste und enthält weder Firewall-, MITM- noch Manipulationsfunktionen.

## Funktionen

- Interface-Erkennung mit IPv4/IPv6, MAC, Status und RX/TX-Zählern
- Start, Pause, Fortsetzen und Stoppen eines Captures
- BPF-Capture-Filter und validierte Wireshark-Display-Filter
- Live-Übertragung als gebündelte WebSocket-Nachrichten
- begrenzter Paket-Ringbuffer im RAM
- Fast Path mit kleinen Tabellenzeilen; vollständige tshark-Details nur auf Auswahl
- hierarchische tshark-JSON-Daten und Hex/ASCII-Dump
- PCAPNG-Aufzeichnung, Download, sicherer Import, Analyse und bestätigtes Löschen
- Conversations, Endpoints, Geräte und dynamische Protokollstatistik
- zusammengefasste ioBroker-States
- Größen-, Gesamtstorage- und Retention-Limits
- zentraler Shutdown für dumpcap, tshark, HTTP, WebSocket und Timer
- Dark/Light Mode und responsive Oberfläche

Die Protokollerkennung erfolgt über tshark. Damit können neben Ethernet, IPv4/IPv6, TCP, UDP und ICMP auch vorhandene Wireshark-Dissektoren wie DNS, DHCP, HTTP, TLS, MQTT, CoAP, NTP, SSDP, Modbus, BACnet, SNMP, SMB, RTP, RTSP, IEC 60870-5-103 und IEC 61850 sichtbar werden, sofern Wireshark den jeweiligen Verkehr dekodieren kann. Ein Port wird nicht pauschal einem Anwendungsprotokoll zugeordnet.

## Wichtiger Hinweis zum sichtbaren Verkehr

Ein normaler Rechner sieht in einem modernen geswitchten Ethernet-Netz überwiegend eigenen Verkehr, Broadcasts und Multicasts. Für die Analyse des gesamten Netzes ist typischerweise ein **SPAN/Mirror-Port** eines Managed Switches, ein Capture direkt auf Router/Gateway oder ein Netzwerk-TAP nötig.

## Voraussetzungen

- Linux (Debian, Ubuntu, Raspberry Pi OS)
- Node.js 20 oder neuer
- ioBroker js-controller 6 oder neuer
- `tshark` und `dumpcap`

Netwatch 0.1.1 includes a guided **System setup** page. It checks `tshark`,
`dumpcap`, and whether the unprivileged ioBroker user can list capture
interfaces. Missing steps are displayed as copyable commands. The adapter
never executes these privileged commands automatically.

Installation auf Debian/Ubuntu/Raspberry Pi OS:

```bash
sudo apt update
sudo apt install tshark
```

### Sichere dumpcap-Rechte

Der Adapter darf **nicht als root** laufen. Debian-Pakete können nicht-root Captures über die Gruppe `wireshark` und Linux-Capabilities erlauben. Die genaue Paketabfrage kann erneut geöffnet werden mit:

```bash
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark iobroker
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
getcap /usr/bin/dumpcap
sudo systemctl restart iobroker
```

Diese Rechte werden vom Adapter niemals automatisch gesetzt. Prüfen Sie die Befehle passend zu Ihrem System. `dumpcap` erhält nur die Capture-Capabilities; der ioBroker-Adapter bleibt unprivilegiert.

## Installation

Install directly from GitHub in ioBroker Admin using the custom URL:

```text
https://github.com/TheBam1990/ioBroker.netwatch
```

Create an instance, open its web UI, and select **Settings → System setup**.
When all three checks are green, select the capture interface and start a
capture. The default bind address is `127.0.0.1`; exposing the separate web UI
to a LAN must be an explicit configuration choice and requires authentication.

Entwicklungspaket bauen:

```bash
npm ci
npm run check
npm pack
```

Danach die erzeugte `.tgz` über ioBroker Admin **Adapter → Aus eigener URL/Datei** installieren oder auf dem Host:

```bash
sudo -u iobroker iobroker url /pfad/iobroker.netwatch-0.1.0.tgz
sudo -u iobroker iobroker add netwatch
```

## Konfiguration

- **Capture Interface:** z. B. `eth0`
- **Auto Start:** beim Adapterstart mitschneiden
- **Memory Packet Limit:** 10.000, 50.000 oder 100.000 Tabellenpakete
- **Capture Directory:** leer verwendet das ioBroker-Datenverzeichnis
- **Maximum Capture Size / Total Storage / Retention:** harte Speichergrenzen
- **Web Bind:** standardmäßig `127.0.0.1`; LAN-Zugriff bewusst z. B. mit `0.0.0.0`
- **Web Port:** standardmäßig `8110`
- **Web Username / Password:** bei LAN-Bindung zwingend ein starkes Kennwort setzen

Eine separate Schnittstelle ist nötig, weil Paket-Livedaten nicht als ioBroker-States transportiert werden. Sie nutzt HTTP Basic Authentication und öffnet standardmäßig **keinen** unauthentifizierten Port auf allen Interfaces. Nutzen Sie für nicht vertrauenswürdige Netze zusätzlich einen TLS-Reverse-Proxy.

## Filter

Capture Filter sind BPF-Ausdrücke und reduzieren die Daten bereits vor der Speicherung:

```text
host 192.168.1.50 and tcp
port 1883
```

Display Filter werden von tshark validiert und filtern die dekodierte Anzeige:

```text
ip.addr == 192.168.1.55
tcp.port == 443 && tls
mqtt.topic contains "zigbee2mqtt"
```

Ein ungültiger Display Filter beendet keinen bestehenden Capture. Der tshark-Fehler wird in der Oberfläche angezeigt.

## Capture-Dateien

Jede Sitzung erhält eine zufällige ID und eine eigene `.pcapng`. Dateien können in der Seite **Captures** heruntergeladen, analysiert, importiert und nach Bestätigung gelöscht werden. Imports akzeptieren ausschließlich `.pcap`/`.pcapng`, begrenzen die Größe und verhindern absolute Pfade sowie `../`-Traversal.

## Fehlerbehebung

- **tshark/dumpcap fehlt:** `sudo apt install tshark`
- **Permission denied:** Gruppenmitgliedschaft und `getcap /usr/bin/dumpcap` prüfen; danach ioBroker neu starten
- **Andere Geräte fehlen:** Mirror-Port/Router/TAP verwenden
- **Filter ungültig:** zwischen BPF Capture Filter und Wireshark Display Filter unterscheiden
- **Webseite nicht erreichbar:** Bind-Adresse, Port, Firewall und Adapterlog prüfen
- **Interface verschwand:** Capture stoppen, Interface neu auswählen und erneut starten
- **System setup remains red:** Run the displayed verification commands as the
  `iobroker` user and restart the complete ioBroker service after changing group
  membership.

## Entwicklung und Tests

```bash
npm run build
npm test
npm run lint
```

Tests decken Pfad-/Filtervalidierung, Parser, Normalisierung, Ringbuffer sowie Conversation- und Device-Aggregation ab. Testdaten sind synthetisch; private Captures gehören nicht ins Repository.

## Noch nicht vollständig in 0.1.0

Die spezialisierten DNS-, MQTT-, TLS- und HTTP-Seiten zeigen zunächst die von tshark erkannten Pakete über Live-Tabelle und Detailpfad; eigene historisierte Feldtabellen und SQLite-Metadatenpersistenz sind für die nächste Ausbaustufe vorgesehen. Rohdaten und vollständige Dekodierung sind bereits über PCAPNG und den Detailpfad verfügbar. Spaltenbreiten und serverseitige Sortierung sehr großer Offline-Captures sind ebenfalls noch nicht persistent.

## Datenschutz und Sicherheit

- keine Telemetrie
- keine Cloud- oder Drittanbieterübertragung
- keine Shell-Konkatenation; Prozesse werden mit getrennten Argumentarrays gestartet
- keine Firewalländerungen, Paketblockierung, TLS-Entschlüsselung oder Zertifikatsinjektion
- keine kompletten Payloads im ioBroker-Log

## Lizenz

MIT
