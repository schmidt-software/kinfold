# Architekturentscheidungen

Stand: 2026-11-07. Die Entscheidungen beschreiben den aktuellen Prototyp, nicht eine Zusicherung von Produktionsreife.

## 1. Eigenständiges Layer-3-MVP

**Entscheidung:** Ein Linux-TUN-Interface pro Gerät mit IPv4 und optional IPv6. Die Implementierung ist eigenständig und nicht mit ZeroTier kompatibel.

**Begründung:** IP-Unicast ist deutlich kleiner als ein virtuelles Ethernet mit ARP/NDP, Broadcast, Multicast und Bridging. Das macht einen überprüfbaren ersten Meilenstein möglich.

**Folgen:** Kein Layer 2 oder Subnetz-Routing. macOS kann den Controller ausführen, aber keinen Client-Tunnel bereitstellen.

## 2. Standardbibliothek und TLS statt eigener Kryptografie

**Entscheidung:** Go ohne externe Module; TLS 1.3 der Go-Standardbibliothek für Controllerverbindungen und zusätzlich pro Gerätepaar. Die Gerätezertifikate werden exakt gegen die Controllerliste geprüft und zusätzlich gegen die eigene CA und den Verwendungszweck validiert.

**Begründung:** Es wird kein eigenes Verschlüsselungs- oder Handshake-Protokoll entworfen. TLS 1.3 stellt Sitzungsschlüssel mit Forward Secrecy bereit, sofern die Endpunkte und die TLS-Implementierung nicht kompromittiert sind.

**Folgen:** Das Relay transportiert verschlüsselte innere TLS-Streams. Weil der Controller die CA und die Mitgliederliste kontrolliert, kann er jedoch Identitäten ersetzen und Verbindungen aktiv manipulieren. Die Controllerverbindung ist gegenseitig authentifiziert; die Konfiguration hat keine davon unabhängige Signatur. Ein externer Sicherheitsaudit und ein genaueres Bedrohungsmodell stehen aus.

Etablierte Peer-Sessions erhalten lokal eine I/O-Frist anhand des frühesten Ablaufs der verwendeten Geräte-, Controller- und CA-Zertifikate. Damit bleiben sie bei gewöhnlichem Uhrverlauf nicht allein wegen eines früher erfolgreichen Handshakes unbegrenzt bestehen. Diese Frist ersetzt weder revokationsgebundene Leases noch eine abgesicherte Zeitquelle; insbesondere sind Suspend, Uhrfehler und manipulierte Clients nicht abgedeckt.

## 3. Zentrales Relay vor NAT-Traversal

**Entscheidung:** Geräte verbinden sich über TCP mit einem selbst hostbaren Controller/Relay. Für jedes Gerätepaar existiert eine eigene Ende-zu-Ende-TLS-Verbindung; das Netz ist auf 32 Geräte begrenzt.

**Begründung:** Der Pfad ist demonstrierbar, funktioniert ohne eingehende Client-Ports und lässt sich mit echten virtuellen Interfaces testen.

**Folgen:** Keine direkten Verbindungen und keine ZeroTier-typische UDP-NAT-Traversal-Optimierung. Volles Mesh skaliert quadratisch; TCP-over-TCP und der zentrale Relay verursachen Performance- und Verfügbarkeitsnachteile. Der Relay-Pfad ist nicht gegen Missbrauch durch autorisierte Geräte gehärtet.

Beim kontrollierten Herunterfahren werden Relay-Sessions unmittelbar geschlossen; für laufende HTTP-Anfragen wartet der Controller bis zu fünf Sekunden und meldet einen Timeout als Fehler. Der Konfigurations-Watcher wird beendet und abgewartet. Dies ist ein lokaler Lifecycle-Mechanismus, kein unterbrechungsfreier Failover.

## 4. Explizite, offline verwaltete Mitgliedschaft

**Entscheidung:** Der Administrator erzeugt die CA und vergibt feste Geräteadressen. Geräte können über `keygen`/`approve`/`enroll` ihren Schlüssel lokal erzeugen und einen signierten Antrag zur manuellen Freigabe übermitteln. Das ursprüngliche `add-peer` erzeugt den Geräteschlüssel weiterhin auf dem Controller. Ein Zertifikat allein reicht nicht: Es muss auch exakt in der gestarteten Controllerkonfiguration stehen.

**Begründung:** Für den ersten Meilenstein entfallen öffentliche Verwaltungsendpunkte, Benutzerkonten und automatische Einschreibungsprozesse.

**Folgen:** Bei `add-peer` sieht der Controller private Geräteschlüssel; beim Offline-Enrollment nicht. Ein signierter Antrag beweist nur Schlüsselbesitz, nicht die Geräteidentität; seine Authentizität und der CA-Fingerprint müssen unabhängig geprüft werden. Keine Einmal-Tokens oder Ablaufzeiten für Anträge. Controller und aktuelle Clients lesen Änderungen periodisch ein; bei Änderungen werden Relay-Verbindungen und Client-Tunnel neu erstellt. Bei Abruffehlern schließt der Client seinen Tunnel. Die CLI bestätigt nur die Dateischreibung. Es gibt keine signierten Leases oder Online-Erneuerung. Unter Linux und macOS verhindert eine advisory Dateisperre konkurrierende CLI-Schreibvorgänge; sie ersetzt keine transaktionale Datenbank und schützt nicht vor manuellen oder älteren Schreibern.

Der Controller prüft beim Laden seine Schlüsselpaare, das zum konfigurierten Host passende gültige Serverzertifikat sowie die Signatur der eingetragenen Geräte durch die eigene CA. Ein ungültiger Zustand schließt den Relay nach Erkennung. Die Prüfung schützt nicht vor einem Angreifer mit Zugriff auf gültigen CA-Schlüssel und Controllerzustand. `add-peer` synchronisiert die Credential-Datei vor der Zustandsänderung; beide Schreibvorgänge sind weiterhin nicht transaktional.

Zustandsdateien werden vor dem atomaren Rename synchronisiert; anschließend wird das übergeordnete Verzeichnis synchronisiert. Auch neu erzeugte Ausgabe- und Controllerverzeichniseinträge werden synchronisiert. Schlägt die Synchronisierung nach dem Erzeugen oder Ersetzen fehl, meldet die CLI ausdrücklich einen ungewissen Zustand: Die Änderung kann bereits sichtbar sein und muss vor einer Wiederholung geprüft werden. Dies setzt ein Dateisystem mit funktionierendem `fsync` voraus und bietet weder Quorum noch atomare Mehrdatei-Transaktionen oder Schutz vor Rollback.

Mit `renew-server` kann der Administrator auch ein bereits abgelaufenes Serverzertifikat unter einer weiterhin gültigen CA ersetzen; dabei wird der Serverschlüssel neu erzeugt und die Laufzeit durch die CA begrenzt. Ein laufender Controller schließt bei erkanntem Identitätswechsel und muss neu gestartet werden. Das erneuert weder Geräte noch CA und ist keine hochverfügbare Rotation.

Für Offline-Widerruf darf `remove-peer` einen ansonsten geprüften Zustand mit abgelaufenem Serverzertifikat laden; der Dienst selbst darf ihn nicht verwenden. Die CA muss weiterhin gültig sein. Die Dateischreibung bestätigt weder die Übernahme durch Controller und Clients noch die Einhaltung einer Widerrufsfrist.

`rotate-peer` ersetzt das Gerätezertifikat anhand eines unabhängig geprüften Offline-Antrags mit neuem lokalem Schlüssel. Adressen und Policy bleiben erhalten; nach asynchroner Übernahme wird die alte Identität nicht mehr zugelassen. Da es keine Transaktion zwischen Zertifikatsausgabe und Zustand, kein sicheres Rollback und keine garantierte Frist gibt, ist das keine Produktionsrotation.

Eine begrenzte Historie öffentlicher Geräteschlüssel-Fingerprints verhindert deren erneute Autorisierung über aktuelle CLI-Befehle, auch nach Entfernung und bei unterschiedlichen Anträgen. Migration erfasst nur noch vorhandene Schlüssel; ältere Backups oder manuelle Änderungen können die Historie zurücksetzen. Das ist weder ein manipulationssicherer Rollback-Schutz noch ein zeitlich begrenztes Einmal-Enrollment.

## 5. Paketzuordnung und Einschränkungen

**Entscheidung:** Ausgehende Pakete werden ausschließlich anhand der exakt zugewiesenen IPv4- oder IPv6-Zieladresse einem Peer zugeordnet. Eingehende Pakete müssen die dem authentifizierten Peer zugewiesene Quelle und die eigene Adresse als Ziel tragen. Neue Netzwerke verwenden zusätzlich statische gerichtete Default-Deny-Freigaben; alte Netzwerke behalten Allow-All, bis der Administrator die Policy aktiviert.

**Begründung:** Damit ist der erste Tunnel einfach zu testen und bietet grundlegenden Schutz gegen Adress-Spoofing.

**Folgen:** Kein Weiterleiten fremder Präfixe, keine Broadcasts oder granularen Portregeln. Eine Antwort benötigt eine eigene Freigabe. Alte Clients ignorieren Policies; das Relay lehnt sie bei aktivierter Policy wegen des fehlenden Konfigurationshashes ab, was jedoch keinen Schutz gegen manipulierbare Clients garantiert. Aktualisierungen erfolgen asynchron und ohne verbindliche Revocation-Garantie. Betriebssystem-Firewalls bleiben erforderlich.

Ein Geräte-Paar ohne Freigabe in irgendeiner Richtung erhält keine Relay-Session; aktuelle Clients sparen solche Verbindungsversuche aus. Eine einseitige Freigabe erlaubt den Aufbau der gemeinsamen Verbindung, nicht den Verkehr in beide Richtungen. Alte Konfigurationen ohne Policy behalten Allow-All.

Optional kann eine zusätzliche experimentelle Service-Policy aktiviert werden. Sie ist standardmäßig deny, benötigt bestehende gerichtete Gerätefreigaben und erlaubt TCP/UDP anhand exakter Zielports oder alle ICMP- beziehungsweise ICMPv6-Typen. Beide Endpunkte prüfen unabhängig. IPv4-Optionen und Fragmente sowie IPv6-Erweiterungsheader und Fragmente werden bei aktivierter Service-Policy abgelehnt; anderer Verkehr ebenfalls. Regeln sind zustandslos, es gibt keine automatische Antwortfreigabe, und ICMP-Fehler werden nicht einer Verbindung zugeordnet. Damit sind insbesondere TCP-Antworten an variable Clientports nur umständlich nutzbar. Änderungen invalidieren Sessions nach asynchronem Reload; alte strikte Decoder akzeptieren die neuen Felder nicht. Kein produktionsreifer Firewall-Ersatz.

`service-apply` übernimmt einen vollständigen, streng eingelesenen und gegen die aktuelle Gerätepolicy geprüften Regelsatz unter der bestehenden Schreibsperre mit einem atomaren Dateiersatz. Ein leeres Array sperrt alle Services; fehlerhafte Eingaben verändern den Zustand nicht. Dies verhindert ungewollte Zwischenstände beim lokalen Schreiben, garantiert aber weder atomare Umstellung aller Clients noch einen Quorum-Commit.
Die feste TUN-MTU beträgt 1280 Bytes. Ausgehende übergroße Pakete werden verworfen; bei eingehenden Frames über der Grenze wird die Session bereits nach dem Frame-Header geschlossen. Automatische PMTU-Ermittlung und eine adaptive MTU sind damit nicht implementiert.

Schreibfehler und unvollständige Schreibvorgänge am TUN-Gerät beenden den Agenten und werden an den Supervisor gemeldet; Netzwerk- und Peer-Fehler führen dagegen weiterhin zu Wiederverbindungsversuchen. Fehler infolge eines bereits eingeleiteten Agent-Shutdowns werden nicht als neue TUN-Schreibfehler ausgegeben.

Der Supervisor verwaltet den Lebenszyklus des Tunnelgeräts: Selbst bei vorzeitigem Agent-Ende wird das Gerät genau einmal geschlossen, und ein Fehler beim Schließen bleibt sichtbar. Das Schließen nach einem Fehler garantiert keine Wiederherstellung anderer Betriebssystem-Einstellungen.

Der periodische Konfigurationsabruf läuft neben der Überwachung des Agents; höchstens ein Abruf ist gleichzeitig aktiv und wird beim Shutdown abgebrochen. Dadurch verzögert ein langsamer Controller nicht die Meldung eines bereits ausgefallenen Agents. Abruf-Timeouts stellen keine zeitgebundene Widerrufsgarantie dar.

## Nächste Meilensteine

1. Sicherheitsmodell und unabhängigen Audit vorbereiten: lokal erzeugte Geräteschlüssel, getrennte Controller-/Relay-Rollen, signierte und versionierte Konfiguration, Schlüsselrotation, Ablauf und zeitlich begrenzter Widerruf.
2. Authentifizierte Online-Verwaltung mit kontrolliertem Konfigurationsupdate; verbindliche Tests für Revocation, Offline-Verhalten und Neustarts. Quoten, Limits, Metriken und sichere Dienstverwaltung ergänzen.
3. Separaten UDP-Datenpfad mit bewährter Transportimplementierung, Rendezvous und NAT-Traversal evaluieren; Relay als Fallback beibehalten. Direkt- und Relay-Pfade sowie NAT-Szenarien automatisch testen.
4. IPv6 über den experimentellen ULA-Unicast hinaus, Routen und Subnetz-Gateways; macOS- und Windows-Clients. Ethernet/Multicast/Bridging erst als eigenes, sorgfältig begrenztes Folgeprojekt.

## 6. Optionales IPv6 über bestehende Peer-Sessions

**Entscheidung:** Ein optionales ULA-`/64` mit expliziter, eindeutiger Adresse je Gerät ergänzt das obligatorische IPv4-Netz. Beide Adressfamilien teilen sich dieselbe authentifizierte Peer-Session und dieselben gerichteten Regeln; Pakete werden nur zwischen den jeweiligen Geräteadressen zugelassen.

**Folgen:** Der Linux-Client richtet beide Adressen am TUN ein und erstellt es bei Änderungen neu. Kein Multicast, NDP, Routing fremder Präfixe oder IPv6-Jumbograms. Aktivierung erfordert aktualisierte Controller und Clients, da ältere strikte JSON-Decoder zusätzliche Felder ablehnen können. Das bleibt ein experimenteller Relay-Pfad ohne Produktionsfreigabe.

## Vorläufige Prüfung des direkten Transports

- [WireGuard](https://www.wireguard.com/) transportiert IP-Pakete über UDP und authentifiziert Peers anhand ihrer Schlüssel. Verteilung der Schlüssel und Konfiguration sind ausdrücklich nicht Teil des Protokolls. NAT-Traversal, Relay-Auswahl und Richtlinienverwaltung müssen deshalb separat gelöst werden.
- [wireguard-go](https://pkg.go.dev/golang.zx2c4.com/wireguard) ist eine mögliche Go-Implementierung. Die Plattformintegration unterscheidet sich; auf Linux weist die Dokumentation auf den Kernel-Datenpfad hin. Lizenz- und Integrationsprüfung sind vor einer Übernahme erforderlich.
- [Pion ICE](https://pkg.go.dev/github.com/pion/ice/v4) stellt Bausteine für Kandidatensuche und Verbindungsaufbau bereit. Ob und wie ein darüber vermittelter Datagrammpfad mit dem gewählten VPN-Transport, Relay-Fallback, Schlüsselbindung und Widerruf kombiniert werden kann, ist noch nicht praktisch nachgewiesen.
- Die Plattformoberflächen für Apple-Geräte ([Packet Tunnel Provider](https://developer.apple.com/documentation/networkextension/packet-tunnel-provider)) und Android ([VpnService](https://developer.android.com/develop/connectivity/vpn)) erfordern eigene Integration und reale Gerätetests.

**Status:** Recherche, keine Auswahl oder Sicherheitsfreigabe. Vor einer produktiven Transportentscheidung fehlen insbesondere ein Ende-zu-Ende-Prototyp mit direktem und Relay-Pfad, NAT-/Mobilitätstests, Leistungsmessungen, Lizenzprüfung und unabhängige Sicherheitsbewertung.
