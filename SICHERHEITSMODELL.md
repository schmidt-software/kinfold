# Sicherheitsmodell und Produktionsanforderungen

Dieses Dokument beschreibt den experimentellen Stand und Anforderungen an eine
künftige Implementierung. Es ist **keine Sicherheitsfreigabe**. Protokoll,
Transport, Konsensverfahren, Uhrmodell und konkrete Lease-Dauer sind noch nicht
festgelegt. Eine unabhängige Prüfung und betriebliche Freigabe stehen aus.

## Schutzumfang und Vertrauensgrenzen

Geschützt werden sollen Nutzdaten zwischen berechtigten Geräten, deren
Schlüssel, die Integrität der Mitgliedschaft und Policy sowie die Isolation
zwischen Netzen. Verfügbarkeit ist ein Ziel, aber keine Garantie gegen einen
Angreifer, der Netzverbindungen oder Ressourcen vollständig unterbindet.

| Akteur oder Grenze | Annahme und Sicherheitsfolge |
| --- | --- |
| Netzwerk und Relay | Dürfen Pakete lesen, verzögern, verändern, duplizieren oder verwerfen. Ein Relay darf keine Nutzdaten entschlüsseln; es sieht mindestens beteiligte Endpunkte, Zeitpunkte und Datenmengen. |
| Gerät | Der lokale Betriebssystemkern und die VPN-Implementierung müssen für die Durchsetzung auf diesem Gerät vertrauenswürdig sein. Ein kompromittiertes Gerät kann seine eigenen Schlüssel und Daten preisgeben sowie lokale Regeln umgehen. Andere korrekte Geräte müssen es dennoch anhand ihrer eigenen aktuellen Autorisierung abweisen. |
| Controller und Signierer | Autorisieren Mitgliedschaft und Policy. Ein kompromittierter autorisierter Signierer kann bösartige gültige Konfigurationen ausstellen; Signaturen allein verhindern das nicht. Getrennte Rollen, Schlüssel und revisionsfähige Administration begrenzen das Risiko, beseitigen es aber nicht. |
| Administrator und Identitätsanbieter | Ein berechtigter kompromittierter Admin oder Identitätsanbieter kann missbräuchliche Aktionen autorisieren. MFA, minimale Rollen, Audit und kontrollierte Schlüsselrotation sind erforderlich; sie ersetzen keinen Schutz kompromittierter Berechtigungen. |
| Lokaler Betreiber | Wer den Controllerzustand oder dessen CA-Schlüssel lesen oder verändern kann, kann im Prototyp Identitäten ausstellen oder die Konfiguration ersetzen. Zugriff auf Credential-Dateien erlaubt Geräteimitation. |
| Plattform und Zeit | Speicher, sichere Schlüsselablage und Uhrvertrauen hängen von der jeweiligen Plattform ab. Manipulierbare Uhren oder zurückgerollter Zustand dürfen keine längere Autorisierung ermöglichen; ohne nachgewiesene Voraussetzungen ist die Fünf-Minuten-Garantie nicht erfüllbar. |

Ein kompromittierter Empfänger kann an ihn zugestellte Daten behalten oder
weitergeben. Weder Verschlüsselung noch lokale Policy erzwingen die Löschung
solcher Daten. Auch ein kompromittiertes Gerät kann gültige Pakete im Rahmen
seiner Rechte erzeugen; deren Inhalt ist nicht durch dieses VPN autorisiert.

## Bestehender Prototyp

Der Linux-Client bezieht eine Mitgliederliste über gegenseitig authentifiziertes
TLS vom Controller. Die zusätzliche TLS-Verbindung pro Peer prüft Zertifikate
gegen die gelieferte Liste und die CA. Die Liste ist nicht unabhängig signiert;
der Controller kontrolliert sie und den CA-Schlüssel. Das ältere `add-peer`
erzeugt Geräteschlüssel auf dem Controller, das Offline-Enrollment lokal.

Neue Netze haben gerichtete Gerätefreigaben mit Default-Deny. Sender und
Empfänger prüfen die jeweilige Richtung und exakte Peer-Adressen. Ein optionaler
experimenteller zusätzlicher Filter prüft Protokoll und exakte Zielports, ohne
zustandsbehaftete Rückverkehrsregel; Fragmentierung und IP-Erweiterungen werden
dabei verworfen. ICMP-Freigaben umfassen alle Typen. Ein manipuliertes
Gerät kann seine eigenen Prüfungen umgehen. Legacy-Konfigurationen ohne Policy
erlauben weiterhin den Verkehr. Der Relay-Konfigurationshash ist kein Nachweis
unveränderter Clientsoftware. Der Relay lehnt Gerätepaare ohne Freigabe in
beiden Richtungen ab; sobald mindestens eine Richtung erlaubt ist, kann er
den verschlüsselten Datenstrom nicht nach Richtung oder Paketinhalt filtern.
Die Richtungsprüfung bleibt deshalb Aufgabe der Endpunkte.

Ein Watcher liest die Zustandsdatei ungefähr jede Sekunde; Clients fragen
periodisch nach und schließen bei Abruffehlern ihren Tunnel. Änderungen und
defekter Zustand invalidieren Relay-Sessions nach Erkennung. Die CLI bestätigt
jedoch nur das lokale Schreiben, nicht das Einlesen oder einen konsistenten
Commit. Es gibt keine signierte Lease, keinen Rollback-Schutz und keinen
nachgewiesenen zeitgebundenen Widerruf. Der Client begrenzt etablierte
Peer-Sessions über eine lokale I/O-Frist auf das früheste Ablaufdatum der
verwendeten Geräte-, Controller- und CA-Zertifikate. Ein zusätzlicher Check
verhindert die Übergabe bereits im TLS-Buffer liegender Daten nach lokal
erkanntem Ablauf. Das schützt nicht vor
manipulierten Clients und ist bei falscher Uhr, Zeitsprüngen oder Suspend kein
Nachweis einer realzeitlichen Grenze; das Relay erzwingt sie nicht selbst.
Die bestehende Implementierung darf deshalb nicht als Grundlage für eine
Fünf-Minuten-Zusicherung ausgegeben werden.

## Produktionsvertrag: Identität, Policy und Netze

- Jedes Gerät erzeugt und schützt seinen privaten Schlüssel lokal; ein
  Enrollment-Nachweis ist kurzlebig, einmal verwendbar und an Schlüsselbesitz,
  Geräteidentität und Freigabe gebunden. Schlüsselwechsel und Widerruf sind
  explizite, auditierte Vorgänge.
- Eine Netzkennung ist unabhängig von IP-Adressen. Konfiguration, Schlüssel,
  Sessions und Policies binden sie kryptografisch; identische Adressen in
  verschiedenen Netzen dürfen weder Autorisierung noch Routing vermischen.
- Default-Deny gilt am empfangenden Gerät sowie bei jedem Gateway/Exit. Eine
  Regel bindet mindestens Netz, Quelle, Ziel, Richtung, Protokoll und Port.
  Priorität, Gruppenauflösung, Fragmentierung, ICMP und Rückverkehr müssen vor
  der Implementierung verbindlich spezifiziert werden. Fehlende, mehrdeutige
  oder unverifizierbare Regeln führen nicht zu Allow-All.
- Ein authentifizierter Transport bindet beide Geräteidentitäten und die
  Netzkennung. Direkt- und Relay-Pfad erhalten dieselbe Autorisierung und
  erfüllen denselben Widerruf; ein erfolgreicher Handshake allein ist keine
  dauerhafte Berechtigung.
- Konfigurationen und Autorisierungen sind versioniert, signiert und an
  Aussteller, Gerät, Netz und Gültigkeit gebunden. Ein gespeicherter
  Rollback-Schutz darf nicht durch Neustart oder Wiederherstellung älterer
  Backups unbemerkt aufgehoben werden. Schlüsselerneuerung und Notfallrotation
  benötigen einen gesonderten, überprüfbaren Vertrauensübergang.

Diese Anforderungen sind noch kein implementiertes Nachrichtenformat oder
komplettes Policy-Modell. Ein kryptografisches Design muss insbesondere
Kanonisierung, Algorithmusbindung, Schlüsselverteilung, Replay-Schutz und
Versionsmigration definieren und unabhängig geprüft werden.

## Widerruf und Zeit: verbindliche Nachweisbedingungen

Ein Widerruf gilt erst nach dauerhaftem, quorum-bestätigtem Commit als
bestätigt. Ab diesem Zeitpunkt dürfen korrekte Empfänger und Gateways nach
spätestens 300 Sekunden keine Pakete des widerrufenen Geräts mehr akzeptieren,
auch wenn sie den Controller nicht mehr erreichen. Dies gilt für bestehende und
neue Sessions, direkte und Relay-Pfade sowie Gateway- und Exit-Verkehr.

Ein möglicher Mechanismus sind kurzlebige signierte Autorisierungsleases,
ergänzt durch sofortige Online-Invalidierung. Dafür müssen mindestens folgende
Eigenschaften nachgewiesen werden:

1. Nach dem Commit darf kein Quorum eine das alte Recht verlängernde Lease
   ausstellen. Vorher ausgestellte und verspätet gelieferte Leases sind beim
   Worst-Case-Budget zu berücksichtigen; eine fehlende Quorum-Mehrheit darf
   keinen Erfolg vortäuschen und keine neuen Rechte verlängern.
2. Akzeptanz ist auch für bereits etablierte Sessions bis zum verifizierten
   Ablauf begrenzt. Eine Nachricht mit altem Stand darf weder nach Widerruf
   noch nach Reboot oder Snapshot-Rollback eine spätere Frist herstellen.
3. Die Summe aus maximaler Restgültigkeit vor Commit, zulässigem Zeitfehler
   und allen weiteren nachweisbaren Verzögerungen bis zur letzten akzeptierten
   Paketverarbeitung darf 300 Sekunden nicht überschreiten. Die genaue
   Herleitung hängt von Ausstellungs- und Uhrmodell ab; dafür wird hier kein
   unvalidierter Zahlenwert festgelegt.
4. Zeitrücksprung, eingefrorene Uhr, Verlust geschützten Zustands und nicht
   nachweisbare Uhrgenauigkeit müssen erkannt werden oder die Autorisierung
   fail-closed beenden. Eine monotone Uhr allein übersteht nicht zwangsläufig
   Neustart oder VM-Snapshot; für jede Plattform ist ein tragfähiges Modell
   und dessen Fehlerverhalten zu belegen.
5. Tests messen vom bestätigten Commit bis zum **letzten akzeptierten Paket**,
   nicht nur bis zum Schließen einer Verbindung. Sie umfassen Partition,
   verspätete Nachrichten, Replay, Uhrfehler, Neustart, Snapshot-Rollback,
   Leader-Wechsel und Relay-Failover für alle unterstützten Pfade.

Ohne vertrauenswürdige Zeit- und Rollback-Annahmen lässt sich unter beliebig
langen Partitionen nicht gleichzeitig unbegrenzte Offline-Verfügbarkeit und
eine feste reale Widerrufsfrist garantieren. Die Produktanforderung entscheidet
sich im Zweifel für fail-closed und damit Verfügbarkeitsverlust.

## Datenschutz und Betrieb

Voraussichtlich fallen Gerätekennungen, öffentliche Schlüssel, Netzzuordnung,
Administrationsereignisse, Verbindungszeitpunkte, Endpunktadressen und
Fehlerdaten an. Protokolle sollen weder Nutzdaten noch private Schlüssel oder
Enrollment-Nachweise enthalten. Zweck, Rechtsgrundlage, Zugriff, Speicherort,
Aufbewahrung, Löschung einschließlich Backups und gegebenenfalls
Auftragsverarbeitung müssen für den konkreten Betrieb festgelegt und rechtlich
geprüft werden. Diese Aufzählung ist keine DSGVO-Freigabe.

Vor Produktion sind außerdem nachvollziehbare Rollen, revisionsfähige
Administration, getestetes Backup/Restore, Schlüsselkompromittierungsverfahren,
Missbrauchsbegrenzung, Datenschutzfreigabe und unabhängige Sicherheitsprüfung
erforderlich. SLOs und die Infrastruktur müssen anhand von Messungen festgelegt
werden. Eine ISO-27001-Zertifizierung ist nicht Bestandteil des Projektziels.
