# Kinfold

Ein **experimenteller, selbst hostbarer IPv4-/IPv6-Overlay-Prototyp**. Er implementiert ein eigenes Protokoll und ist mit keinem anderen VPN- oder Overlay-Produkt kompatibel.

> **Nicht für den Produktiveinsatz oder den Schutz vertraulicher Daten verwenden.** Es gibt keinen unabhängigen Sicherheitsaudit, keine Hochverfügbarkeit und noch wichtige Einschränkungen beim Betrieb und Widerruf. Insbesondere ist der Controller eine vollständige Vertrauensinstanz.

## Aktueller Stand

- Ein privates IPv4-Netz und optional ein IPv6-ULA-Netz mit bis zu 32 explizit freigegebenen Geräten; ein Linux-TUN-Interface pro Gerät.
- Selbst hostbarer Controller und TCP-Relay, keine Registrierung bei einem externen Dienst.
- Controller- und Geräteidentitäten über Zertifikate; Controllerverbindung mit gegenseitigem TLS 1.3.
- Zusätzliche, gegenseitig authentifizierte TLS-1.3-Verbindung **zwischen den Geräten** durch das Relay. Zertifikate werden gegen die vom Controller gelieferte Mitgliederliste geprüft.
- Etablierte Peer-Verbindungen erhalten eine I/O-Frist für das früheste Ablaufdatum der verwendeten Geräte-, Controller- und CA-Zertifikate; auch bereits TLS-gepufferte Daten werden nach Ablauf nicht mehr an den Paketparser geliefert. Danach wird neu verbunden. Diese lokale Frist ist keine manipulationssichere Uhr oder Widerrufsgarantie.
- IPv4- und optionale IPv6-Unicast-Pakete nur zwischen den zugewiesenen Geräteadressen; Prüfung von Quell- und Zieladresse gegen Spoofing. Automatische Wiederverbindung nach Verbindungsabbruch.
- Die feste Tunnel-MTU beträgt 1280 Bytes. Größere ausgehende Pakete werden verworfen; ein eingehender Frame über dieser Grenze beendet die betreffende Peer-Session.
- Verbindungswiederholungen nutzen exponentielles Backoff mit zufälliger Streuung bis höchstens 30 Sekunden; nach 30 Sekunden stabiler Verbindung wird das Backoff zurückgesetzt.
- Bei einem Schreibfehler am Tunnelgerät beendet der Client den Tunnel mit einem Fehler statt nur die betroffene Peer-Verbindung neu aufzubauen.
- Beim Controller-Shutdown werden Relay-Sessions sofort beendet und laufende HTTP-Anfragen bis zu fünf Sekunden abgewartet; bei Überschreitung wird der Fehler gemeldet und der Server geschlossen.
- Controllerzustand, Zugangsdaten und empfangene Konfiguration werden streng eingelesen: unbekannte oder doppelte JSON-Felder, übergroße Dokumente und angehängte Daten werden zurückgewiesen.
- Antwort-Header des Controllers sind beim Konfigurationsabruf und beim Relay-Verbindungsaufbau auf 16 KiB begrenzt.
- Der Controller prüft beim Laden zusätzlich die CA- und Server-Schlüsselpaare, das Serverzertifikat einschließlich Hostname und Gültigkeit sowie die CA-Signaturen der eingetragenen Gerätezertifikate.
- Unterschiedliche Geräte dürfen auch bei verschiedenen Zertifikaten keinen gemeinsamen öffentlichen Schlüssel verwenden; inkonsistente Konfigurationen werden abgelehnt.
- Neue Netzwerke sperren standardmäßig den Datenverkehr zwischen Geräten; statische gerichtete Freigaben können über die CLI gesetzt werden.
- Relay und aktuelle Clients bauen nur für Gerätepaare mit mindestens einer gerichteten Freigabe eine Peer-Session auf; der Datenverkehr bleibt pro Richtung separat geprüft.
- CLI zum Erstellen, Hinzufügen und Entfernen von Geräten sowie Anzeigen der Mitglieder.
- Optionales Offline-Enrollment: Das Gerät erzeugt seinen privaten Schlüssel selbst; der Administrator prüft und genehmigt einen signierten Zertifikatsantrag.

Die Mitgliederliste wird beim Start über authentifiziertes TLS geladen, **nicht separat signiert**. Der Controller kontrolliert die Mitgliederliste und besitzt den CA-Schlüssel. Beim älteren `add-peer` erzeugt er außerdem den Geräteschlüssel; beim unten beschriebenen Offline-Enrollment entsteht der Schlüssel auf dem Gerät. Ein kompromittierter Controller kann Geräte zulassen und Verbindungen durch Austausch von Zertifikaten manipulieren. Ein Relay, das nur Pakete weiterleitet und dessen Controller/CA nicht kompromittiert ist, sieht den Inhalt der inneren TLS-Verbindung nicht; es sieht aber Metadaten wie beteiligte Geräte und Datenvolumen.

Es gibt **noch keine** direkten Peer-Verbindungen, NAT-Hole-Punching, UDP-Transport, Ethernet/Bridging, Multicast, Subnetz-Gateways, zustandsbehaftete ACLs, GUI oder Interoperabilität mit anderen VPN-Produkten. `status` zeigt die autorisierte Mitgliederliste, nicht den Live-Verbindungszustand. Die Architekturentscheidungen stehen in [ENTSCHEIDUNGEN.md](ENTSCHEIDUNGEN.md).

Das [Sicherheitsmodell](SICHERHEITSMODELL.md) trennt die Eigenschaften des Prototyps von noch offenen Produktionsanforderungen, insbesondere zu Vertrauen, Policy und zeitgebundenem Widerruf.

## Hinweis zur Umbenennung

Das Projekt hieß bis Version `v0.1-copilot` `my-zerotier`. Mit der Umbenennung in Kinfold haben sich das Binary (`kinfold`), der Standardname des TUN-Interfaces (`kf0` statt `mzt0`), die Variable `KINFOLD_TEST_IMAGE` und der interne HTTP-Header für die Konfigurationsrevision geändert. Wegen des Headers sind ältere Clients nicht mit einem neuen Controller kompatibel und umgekehrt: Controller und **alle Clients** gemeinsam aktualisieren. Bestehende Controllerzustände und Zugangsdaten bleiben gültig; neu erzeugte CAs heißen `Kinfold CA`.

## Schnellvorführung mit Docker

Voraussetzungen: Go 1.24 oder neuer, Docker mit Linux-Containern, `NET_ADMIN` und `/dev/net/tun`. Das Skript verwendet standardmäßig das Docker-Image `alpine/socat:latest` und kann es bei Bedarf herunterladen. Über `KINFOLD_TEST_IMAGE` lässt sich ein geeignetes vorhandenes Image mit Shell, `ip`, `ping`, `ping6`, `nc` und `socat` wählen.

```sh
sh scripts/integration-docker.sh
```

Das Skript baut ein Linux-Binary, erstellt temporäre Zugangsdaten und ein isoliertes Docker-Netzwerk, startet drei Clients und prüft IPv4/IPv6-ICMP und TCP, Policy, Wiederverbindung und Widerruf. Es entfernt seine eigenen Container, sein Netzwerk und die temporären Dateien beim Beenden. Es verändert keine bestehenden Container.

## Manuelle Inbetriebnahme

Der Controller läuft auf Linux oder macOS; der VPN-Client benötigt derzeit **Linux**, `/dev/net/tun`, das Kommando `ip` aus iproute2 bzw. BusyBox und Administratorrechte bzw. `CAP_NET_ADMIN`. Das virtuelle Netz darf sich nicht mit vorhandenen lokalen Netzen oder Routen überschneiden.

1. Auf dem Controller bauen und initialisieren. `vpn.example.com:8443` ist durch den von allen Clients erreichbaren DNS-Namen bzw. die IP-Adresse und den TCP-Port des Controllers zu ersetzen. Der Name wird im Serverzertifikat hinterlegt und muss zum verwendeten Namen passen.

   ```sh
   go build -o kinfold .
   ./kinfold init -data controller-data \
     -server vpn.example.com:8443 -network 10.77.0.0/24
   mkdir -m 700 credentials
   ./kinfold add-peer -data controller-data \
     -id alice -ip 10.77.0.1 -out credentials/alice.json
   ./kinfold add-peer -data controller-data \
     -id bob -ip 10.77.0.2 -out credentials/bob.json
   ./kinfold allow -data controller-data -from alice -to bob
   ./kinfold allow -data controller-data -from bob -to alice
   ./kinfold serve -data controller-data -listen :8443
   ```

2. Für die Linux-Geräte ein Binary passender Architektur bauen, beispielsweise:

   ```sh
   GOOS=linux GOARCH=amd64 go build -o kinfold-linux .
   ```

   Für Linux ARM64 `GOARCH=arm64` verwenden. Das Binary und **jeweils nur die passende** Zugangsdaten-Datei über einen vertrauenswürdigen, verschlüsselten Kanal auf das jeweilige Gerät übertragen. Die Datei enthält den privaten Geräteschlüssel und muss vertraulich bleiben.

3. Auf Alice und Bob jeweils mit ihrer eigenen Zugangsdaten-Datei starten:

   ```sh
   sudo ./kinfold-linux run -credential alice.json
   # Auf Bob stattdessen: -credential bob.json
   ```

   Nach dem Verbindungsaufbau sollte auf Alice `ping 10.77.0.2` funktionieren und auf Bob `ping 10.77.0.1`. Die lokale Firewall muss ICMP bzw. die verwendeten Anwendungsports zulassen. Der Controller muss von beiden Geräten über TCP erreichbar sein. `Ctrl-C` beendet den Client; das nicht persistente TUN-Interface wird dabei entfernt.

Mit `./kinfold-linux status -credential alice.json` lässt sich die Konfiguration abfragen. `kinfold help` und `kinfold <Befehl> -h` zeigen die verfügbaren Optionen.

Administratoren können mit `./kinfold check-config -data controller-data -credential admin-peer.json` prüfen, ob der authentifizierte Controller dieselbe Konfiguration geladen hat wie ein lokaler Snapshot der Zustandsdatei. Die Zugangsdaten müssen zu einem weiterhin autorisierten Gerät gehören. Der Befehl gibt beide Konfigurations-Hashes aus und liefert bei Abweichung oder Erreichbarkeitsfehler einen Fehler. Ein Treffer bestätigt weder die Aktualisierung aller Clients noch die Durchsetzung auf manipulierten Geräten; gleichzeitige Änderungen nach dem Lesen sind nicht ausgeschlossen.

## Optionales IPv6

Vor der Aktivierung **alle Clients und den Controller aktualisieren**: Ältere Binaries mit striktem JSON-Decoder können die zusätzlichen Felder ablehnen. Auf dem Controller ein nicht mit anderen Netzen kollidierendes ULA-`/64` und eindeutige Geräteadressen konfigurieren:

```sh
./kinfold ipv6-network -data controller-data -network fd77::/64
./kinfold ipv6-assign -data controller-data -id alice -ip fd77::1
./kinfold ipv6-assign -data controller-data -id bob -ip fd77::2
```

Nach asynchronem Neuladen und Verbindungsaufbau sollte `ping -6 fd77::2` auf Alice funktionieren. IPv6 setzt ein funktionierendes IPv4-Overlay voraus; ein Gerät ohne IPv6-Zuweisung bleibt IPv4-only. Die vorhandenen gerichteten Freigaben gelten für beide Adressfamilien. Zum Entfernen `ipv6-assign -id alice -ip none` verwenden und erst nach Entfernen aller Zuweisungen mit `ipv6-network -network none` das IPv6-Netz deaktivieren. Ein Präfixwechsel wird abgelehnt, solange Zuweisungen nicht in das neue Netz passen.

## Offline-Enrollment mit lokalem Schlüssel

Alternativ zu `add-peer` kann ein Gerät seinen privaten Schlüssel selbst erzeugen. Das Verfahren ist **experimentell und offline**: Der Antrag beweist den Besitz des Schlüssels, authentifiziert aber nicht die Person oder das Gerät. Antrag und CA müssen unabhängig authentifiziert und verglichen werden; es gibt noch keine Einmal-Tokens, Ablaufprüfung des Antrags oder Online-Freigabe.

Die CLI begrenzt beim Einlesen Anträge, private Schlüssel und Zertifikatsdateien auf jeweils 64 KiB; größere Dateien werden zurückgewiesen.

1. Auf dem Gerät:

   ```sh
   ./kinfold-linux keygen -id alice -key alice.key -request alice.csr
   shasum -a 256 alice.csr
   ```

   Nur `alice.csr` an den Administrator senden. Den SHA-256-Wert des Antrags über einen unabhängigen vertrauenswürdigen Kanal vergleichen und die Geräteidentität prüfen. **`alice.key` niemals übertragen.**

2. Auf dem Controller nach Prüfung der Identität und des Fingerprints:

   ```sh
   shasum -a 256 alice.csr
   ./kinfold approve -data controller-data -id alice \
     -ip 10.77.0.1 -request alice.csr -out alice.crt
   ./kinfold export-ca -data controller-data -out ca.crt
   openssl x509 -in ca.crt -noout -fingerprint -sha256
   ```

   `alice.crt` und `ca.crt` an das Gerät übertragen und den CA-Fingerprint unabhängig und vertrauenswürdig mitteilen. Die Controllerdatei wird wie bei `add-peer` geändert; Controller und aktuelle Clients laden Änderungen asynchron.

3. Auf dem Gerät den CA-Fingerprint vergleichen und die private Credential-Datei erzeugen:

   ```sh
   openssl x509 -in ca.crt -noout -fingerprint -sha256
   ./kinfold-linux enroll -server vpn.example.com:8443 \
     -key alice.key -cert alice.crt -ca ca.crt -out alice.json
   sudo ./kinfold-linux run -credential alice.json
   ```

   `enroll` prüft, dass Zertifikat und privater Schlüssel zusammenpassen und das Zertifikat von der angegebenen CA stammt. Der Vergleich des CA-Fingerprints durch den Benutzer ist trotzdem erforderlich. Sowohl `alice.key` als auch `alice.json` enthalten private Schlüsseldaten und müssen vertraulich bleiben; neue Dateien werden mit Modus `0600` erstellt und nicht überschrieben.

## Änderungen und Widerruf

`add-peer`, `approve`, `rotate-peer`, `remove-peer`, `policy-enable`, `allow`, `deny`, `ipv6-network` und `ipv6-assign` bearbeiten die Controllerdatei. Unter Linux und macOS verhindert eine advisory Dateisperre gleichzeitige Änderungen durch diese CLI-Befehle; ein konkurrierender Befehl scheitert und muss erneut ausgeführt werden. Die Datei `.state.lock` darf während des Betriebs nicht gelöscht werden. Manuelle Änderungen, ältere Binaries und Dateisysteme ohne zuverlässiges `flock` umgehen diesen Schutz; er ersetzt keine transaktionale Datenbank. Der laufende Controller prüft die Datei ungefähr einmal pro Sekunde und beendet bei Änderungen alle aktiven Relay-Verbindungen. Aktuelle Clients fragen die Konfiguration periodisch ab und erstellen den Tunnel bei Änderungen neu. Bei einem fehlgeschlagenen Abruf schließen sie ihren Tunnel und versuchen es erneut; das kann bei vorübergehenden Verbindungsproblemen die VPN-Verbindung unterbrechen. Die CLI bestätigt nur das Schreiben der Datei, **nicht** das Einlesen oder die vollständige Durchsetzung. Bei beschädigter, kryptografisch inkonsistenter oder nicht lesbarer Datei sowie bei ungültigem Serverzertifikat schließt der Controller Verbindungen und lehnt neue Anfragen ab, bis der Zustand wieder gültig ist. Änderungen an CA oder Serverzertifikat erfordern einen Controller-Neustart.

Datei und Verzeichniseintrag werden synchronisiert; das setzt ein Dateisystem mit funktionierendem `fsync` voraus. Falls die Synchronisierung nach dem Schreiben fehlschlägt, kann die Änderung bereits sichtbar sein, ihre Dauerhaftigkeit ist aber ungewiss. Zustand und Ausgabedateien vor einem erneuten Versuch prüfen. Mehrere Dateien werden nicht als Transaktion geschrieben.

Neue Netzwerke verwenden eine Default-Deny-Policy. `allow -from alice -to bob` erlaubt ohne den optionalen Service-Filter sämtliche IPv4- und IPv6-Pakete von Alice zu Bob; Antwortpakete benötigen die umgekehrte Freigabe. `deny` entfernt eine Freigabe. Die grundlegende Policy gilt auf Sender und Empfänger, ist aber keine zustandsbehaftete Firewall und filtert selbst weder Ports noch Protokolle. Bestehende Netzwerke ohne Policy behalten aus Kompatibilitätsgründen zunächst ihr bisheriges Allow-All-Verhalten und melden eine Warnung. `policy-enable -data controller-data` aktiviert Default-Deny für ein solches Netzwerk; anschließend müssen die gewünschten Regeln gesetzt werden.

### Experimentelle Service-Filter

Optional ergänzt `service-enable -data controller-data` die Gerätefreigaben um eine **zusätzliche Default-Deny-Filterung für alle Richtungen**; unmittelbar nach Aktivierung wird sämtlicher Verkehr verworfen. Vorher Controller und **alle Clients** aktualisieren: ältere strikte Decoder verstehen das zusätzliche Feld nicht. Änderungen werden asynchron wirksam; bestehende Sessions werden nach Übernahme getrennt.

Alternativ aktiviert oder ersetzt `service-apply` den vollständigen Regelsatz in einem atomaren Schreibvorgang. Beispiel für die Datei `services.json`:

```json
{"allowed":[
  {"from":"alice","to":"bob","protocol":"icmp"},
  {"from":"bob","to":"alice","protocol":"icmp"},
  {"from":"alice","to":"bob","protocol":"udp","port":53}
]}
```

```sh
./kinfold service-apply -data controller-data -rules services.json
```

Das Format enthält ausschließlich das erforderliche Array `allowed`; `{"allowed":[]}` sperrt alle Services. Ungültige, doppelte oder nicht durch eine Gerätefreigabe gedeckte Regeln werden vor dem Schreiben zurückgewiesen. Die atomare Ersetzung betrifft nur die lokale Datei, nicht die gleichzeitige Durchsetzung auf allen Clients.

Für schrittweise Änderungen:

```sh
./kinfold service-enable -data controller-data
./kinfold service-allow -data controller-data -from alice -to bob -protocol udp -port 53
./kinfold service-allow -data controller-data -from alice -to bob -protocol icmp
./kinfold service-allow -data controller-data -from bob -to alice -protocol icmp
./kinfold service-allow -data controller-data -from alice -to bob -protocol icmp6
./kinfold service-allow -data controller-data -from bob -to alice -protocol icmp6
```

Jede Service-Regel setzt die entsprechende Gerätefreigabe voraus; maximal 4096 Regeln sind zulässig. `service-deny` mit denselben Parametern entfernt sie; `deny` oder `remove-peer` entfernt dazugehörige Service-Regeln. TCP und UDP verwenden exakte **Zielports** (1–65535); `icmp` und `icmp6` erlauben alle jeweiligen ICMP-Typen ohne Port. Andere Protokolle, IPv4-Fragmente und -Optionen sowie IPv6-Erweiterungsheader einschließlich Fragmenten werden verworfen. Es gibt keine automatische Rückverkehrsregel: TCP-/UDP-Antworten an wechselnde Clientports erfordern explizite umgekehrte Regeln und sind daher praktisch eingeschränkt. ICMP-Fehler sind nicht verbindungsbezogen gefiltert. Betriebssystem-Firewalls bleiben erforderlich.

Die Regeln gelten auf aktuellen Sendern und Empfängern, nicht im verschlüsselten Relay. Ein manipulierter Endpunkt kann seine lokalen Regeln umgehen; korrekte Empfänger prüfen unabhängig. Es gibt bewusst keinen CLI-Schalter zum Zurückfallen auf die weniger restriktive alte Policy. Diese experimentelle Funktion ist kein produktionsreifer Ersatz für eine zustandsbehaftete Firewall oder einen Widerrufsnachweis.

Ein aktualisierter Relay lehnt Sessions zwischen zwei Geräten ab, wenn in keiner Richtung eine Freigabe existiert; aktuelle Clients versuchen solche Verbindungen nicht. Eine Freigabe in nur einer Richtung reicht für die gemeinsame Session, erlaubt aber keinen Rückverkehr. Diese zusätzliche Relay-Prüfung ersetzt nicht die Richtungsprüfung auf dem Empfänger und begrenzt keine Bandbreite.

**Wichtige Grenze:** Ältere Client-Binaries ignorieren die Policy. Bei aktivierter Policy fordert der Relay bei Verbindungsaufbau den Hash der aktuellen Konfiguration und lehnt unveränderte alte Clients und Clients mit veralteter Konfiguration ab. Der Hash ist **kein Integritätsnachweis für die Client-Software**: Ein manipulierter Client kann ihn nachbilden. Bei alten Netzwerken ohne Policy gibt es diese Prüfung nicht. Alle Teilnehmer müssen aktualisiert werden; bestehende Sessions werden erst nach dem asynchronen Einlesen beendet. Diese Policy erfüllt noch nicht die Anforderungen an produktionsreife Zugriffskontrolle oder zeitgebundenen Widerruf.

```sh
./kinfold remove-peer -data controller-data -id bob
# Controller und aktuelle Clients übernehmen die Änderung asynchron.
```

Den Controllerzustand und die Zugangsdaten nicht einchecken oder weitergeben. Der Ordner `controller-data` enthält insbesondere den CA-Privatschlüssel; `credentials` enthält die Geräteschlüssel. Die Standardpfade sind in `.gitignore` eingetragen, beliebige andere Pfade nicht. Den Controllerzustand verschlüsselt sichern. Das Löschen oder der Verlust des CA-Schlüssels macht eine Neuerstellung und erneute Verteilung der Zugangsdaten notwendig.

`add-peer`, `approve` und `rotate-peer` schreiben zuerst die neue Credential- bzw. Zertifikatsdatei und aktualisieren danach den Controllerzustand. Die beiden Dateien bilden keine Transaktion: Bei einem Fehler kann eine Ausgabedatei ohne zugehörigen Eintrag im Controllerzustand bestehen bleiben. Vor einem erneuten Versuch Zustand und Ausgabedatei prüfen; nicht davon ausgehen, dass eine erzeugte Datei bereits zugelassen ist.

## Geräteschlüssel offline wechseln

Ein vorhandenes Gerät kann mit `keygen` einen **neuen** lokalen Schlüssel und Antrag erzeugen. Der Administrator muss Identität und Antragsfingerprint wie beim Offline-Enrollment unabhängig prüfen. Auf dem Controller wird dann das Zertifikat ersetzt; IPv4-/IPv6-Adressen und Freigaben bleiben erhalten:

```sh
# Auf dem Gerät:
./kinfold-linux keygen -id alice -key alice-new.key -request alice-new.csr
# Nach Identitäts- und Fingerprintprüfung auf dem Controller:
./kinfold rotate-peer -data controller-data -id alice -request alice-new.csr -out alice-new.crt
# Auf dem Gerät, nach unabhängiger Prüfung der CA:
./kinfold-linux enroll -server vpn.example.com:8443 \
  -key alice-new.key -cert alice-new.crt -ca ca.crt -out alice-new.json
sudo ./kinfold-linux run -credential alice-new.json
```

Nach Übernahme des Zustands wird das alte Zertifikat nicht mehr zugelassen und aktive Relay-Sessions werden beendet. Das Gerät muss den alten Client stoppen und mit den neuen Zugangsdaten starten; eine unterbrechungsfreie Rotation oder eine garantierte Widerrufsfrist gibt es nicht. Der Controller übernimmt Änderungen asynchron; eine Schreibbestätigung ist kein Durchsetzungsnachweis. Ein altes Backup kann den früheren Schlüssel wieder autorisieren, da Rollback-Schutz fehlt.

Der Controller speichert Fingerprints bereits vergebener öffentlicher Geräteschlüssel und lehnt deren erneute Verwendung auch nach Rotation oder Entfernung ab. Die Historie beginnt bei bestehenden Zuständen mit den zum Zeitpunkt einer entsprechenden Änderung noch eingetragenen Geräten; früher entfernte oder rotierte Schlüssel sind nicht bekannt. Sie ist auf 32.768 Einträge begrenzt; danach werden neue Schlüssel abgelehnt. Anträge selbst sind nicht zeitlich begrenzt oder vor ihrer ersten Freigabe einmalig. Bei Rückspielung eines alten Backups, manueller Manipulation oder Verlust der Historie können frühere Schlüssel wieder zugelassen werden. Administratoren müssen jeden Antrag weiterhin unabhängig auf Aktualität und Authentizität prüfen.

Der Controllerzustand enthält nach der ersten Schlüsselvergabe oder Migration ein neues JSON-Feld. **Vor Änderungen Controller und administrative CLI aktualisieren:** Ältere Binaries mit strengem JSON-Decoder können den aktualisierten Zustand nicht lesen. Die neue Historie enthält öffentliche Schlüssel-Fingerprints, keine privaten Schlüssel.

## Bekannte Grenzen

- Controller und aktuelle Clients prüfen Änderungen periodisch und schließen bei Fehlern ihre Verbindungen. Die CLI bestätigt kein erfolgreiches Laden. Für einen Widerruf gibt es keine garantierte Frist und keinen Schutz durch signierte kurzlebige Leases oder einen abgesicherten Zeitgeber; ein kompromittierter Controller oder Client kann die Policy umgehen.
- Das Relay ist ein zentraler Ausfallpunkt. Der TCP-basierte Tunnel kann bei Verlust oder Überlastung zusätzliche Latenz und Head-of-Line-Blocking verursachen. Der Listener nimmt höchstens 1.152 gleichzeitige TCP-Verbindungen einschließlich TLS-Handshakes an. Pro Relay sind höchstens 1.024 wartende oder aktive Verbindungsendpunkte zugelassen, höchstens 32 pro authentifiziertem Gerät und einer pro gerichtetem Gerätepaar. Die Grenzen sind nicht konfigurierbar; bei Listener-Auslastung warten neue Verbindungen im Betriebssystem-Backlog, bei Relay-Auslastung werden sie abgelehnt. Bandbreitenquoten und Betriebsmetriken fehlen.
- Wartende Relay-Endpunkte laufen nach 30 Sekunden ab. Ein vorheriger Verbindungsabbruch wird beim Warten nicht unmittelbar erkannt und kann bis zum Ablauf weiterhin einen Platz belegen; diese Begrenzung ist kein vollständiger Schutz vor Ressourcenmissbrauch.
- Nur Kommunikation zwischen den explizit zugewiesenen IPv4- bzw. IPv6-Adressen funktioniert. IPv6 ist auf ein ULA-`/64` beschränkt; Multicast, NDP, Jumbograms, Weiterleitung zu anderen Subnetzen und Internet-Exit-Nodes werden nicht unterstützt.
- Server- und Gerätezertifikate gelten höchstens ein Jahr und nicht länger als die CA; die CA gilt zehn Jahre. Bestehende Peer-Sessions sind lokal auf das früheste Ablaufdatum der verwendeten Zertifikate begrenzt. Bei falscher Uhr, Zeitsprüngen, Suspend oder manipulierten Clients ist das kein Nachweis einer zeitgebundenen Sperre; das Relay setzt diesen Ablauf nicht selbst durch. Serverzertifikate und Geräteschlüssel können manuell erneuert werden; CA-Rotation und automatische Erneuerung fehlen. Ein Wechsel des Controller-Hostnamens erfordert derzeit eine neue Einrichtung und Verteilung der Zugangsdaten.

## Serverzertifikat erneuern

Auf dem Controller erneuert `./kinfold renew-server -data controller-data` das Serverzertifikat und den Serverschlüssel mit der bestehenden, noch gültigen CA. Das neue Zertifikat gilt höchstens ein Jahr und nicht länger als die CA. Der Controller muss danach neu gestartet werden; ein bereits laufender Controller schließt nach Erkennen der geänderten Identität seine Relay-Sessions und bleibt bis zum Neustart geschlossen. Der CA-Schlüssel und die Gerätezertifikate bleiben unverändert, daher müssen bei unveränderter CA und Adresse keine neuen Zugangsdaten verteilt werden. Ein bereits abgelaufenes Serverzertifikat kann erneuert werden; eine abgelaufene CA nicht. Die Dateisperre und die sonstigen Einschränkungen der Dateispeicherung gelten weiterhin.

Auch bei abgelaufenem Serverzertifikat kann `remove-peer` Geräte offline aus dem Zustand entfernen, solange die CA gültig und der übrige Zustand konsistent ist. Das ist nur eine lokale Änderung, kein bestätigter oder zeitgebundener Widerruf; der Controller bleibt wegen des abgelaufenen Zertifikats geschlossen, bis das Zertifikat erneuert und der Controller neu gestartet wurde.
- Die Verbindungslimits sind kein vollständiger Schutz vor Ressourcenmissbrauch: Insbesondere fehlen Bandbreitenbegrenzung sowie individuelle Ratenlimits für TLS-Handshakes und Verwaltungsanfragen. Ein Angreifer kann das globale Verbindungslimit auslasten. Keine automatische Sicherung, Paketinstallation, Dienstverwaltung oder gehärtete Rechteabtrennung.

## Entwicklung

```sh
go test -race ./...
go vet ./...
sh scripts/integration-docker.sh
# Zeitlich begrenzte Fuzz-Läufe für Paketparser, Framing, Relay-Antworten, Service-Filter und Konfiguration:
go test ./internal/agent -run '^$' -fuzz '^FuzzPacketAddresses$' -fuzztime 30s
go test ./internal/agent -run '^$' -fuzz '^FuzzPacketFraming$' -fuzztime 30s
go test ./internal/agent -run '^$' -fuzz '^FuzzRelayResponse$' -fuzztime 30s
go test ./internal/agent -run '^$' -fuzz '^FuzzServicePacket$' -fuzztime 30s
go test ./internal/core -run '^$' -fuzz '^FuzzDecodeConfig$' -fuzztime 30s
```

Es werden keine externen Go-Module benötigt. Die Docker-Integration benötigt die oben genannten Rechte und verwendet temporäre, nur für den Test erzeugte Schlüssel.
