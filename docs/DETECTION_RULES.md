# Référentiel des Règles de Détection SIEM & MITRE ATT&CK — NetSentinel Enterprise

> Ce document détaille les règles de détection implémentées dans le moteur de corrélation SIEM (`backend/engine/correlator.py`), leurs fondements théoriques, leurs fenêtres glissantes et leurs mappages MITRE ATT&CK.

---

## Matrice Récapitulative des Règles

| Identifiant | Intitulé de la Règle | Technique MITRE | Sévérité | Fenêtre Glissante | Seuil de Déclenchement |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-R001** | SSH Credential Brute-Force | **T1110.001** (Password Guessing) | `CRITICAL` | 60 secondes | $\ge 5$ échecs d'authentification par IP source |
| **SEC-R002** | Horizontal Port Sweep | **T1046** (Network Service Discovery) | `HIGH` | 30 secondes | $\ge 10$ ports distincts sondés par IP source |
| **SEC-R003** | Volumetric SYN Flood DDoS | **T1498.001** (Direct Network Flood) | `CRITICAL` | Télémétrie en continu | Débit $\ge 800\text{ Mbps}$ OU $\ge 40\,000\text{ PPS}$ |
| **SEC-R004** | Unauthorized Rogue MAC Injection | **T1200** (Hardware Additions) | `CRITICAL` | Événement immédiat | Adresse MAC absente de la liste blanche d'entreprise |
| **SEC-R005** | Link Flapping & Packet Loss Burst | **NMS-NET-01** (Network Stability Anomaly) | `MEDIUM` | 60 secondes | $\ge 4$ transitions d'état OU perte $> 10\%$ et latence $> 200\text{ ms}$ |

---

## 1. Règle SEC-R001 : Détection d'Attaque par Force Brute SSH

### Contexte & Menace
Les attaques par force brute contre le protocole SSH consistent à tenter de manière automatisée une multitude de combinaisons d'identifiants/mots de passe dans le but d'obtenir un accès non autorisé à un serveur.

### Logique d'Implémentation
1. Chaque échec d'authentification reçu (`event_type: AUTH_FAILURE`) est horodaté et associé à l'adresse IP de l'attaquant :  
   `correlator.record_auth_event(source_ip, target_device_id, success=False, protocol="SSH")`.
2. Le moteur filtre les événements expirés en conservant uniquement ceux qui se situent dans la fenêtre temporelle :  
   $t_{\text{actuel}} - t_{\text{événement}} \le 60\text{ secondes}$.
3. Dès que le nombre d'échecs pour une même IP source atteint ou dépasse le seuil configuré ($N \ge 5$), une alerte est levée.
4. Pour éviter le spam d'alertes répétitives, une clé de déduplication `(source_ip, target_device_id, "SEC-R001")` est enregistrée avec un temps de recharge (cooldown).

---

## 2. Règle SEC-R002 : Détection de Balayage Horizontal de Ports

### Contexte & Menace
Avant de lancer une attaque ciblée, les adversaires procèdent généralement à une phase de reconnaissance en sondant une plage de ports sur les machines de la DMZ pour cartographier les services en écoute.

### Logique d'Implémentation
1. Chaque tentative de connexion vers un port TCP (`event_type: PORT_ATTEMPT`) est enregistrée avec le couple `(source_ip, port)` et un horodatage.
2. Le moteur évalue les événements survenus dans les **30 dernières secondes**.
3. Il calcule le nombre de **ports distincts et uniques** sondés par chaque adresse IP source :  
   $|\{ \text{port} \mid (s, p, t) \in \text{fenêtre} \land s = \text{IP}_{\text{attaquant}} \}| \ge 10$.
4. Si le nombre de ports uniques est $\ge 10$, une alerte de sévérité `HIGH` est générée.

---

## 3. Règle SEC-R003 : Détection d'Anomalie Volumétrique de Trafic (DDoS)

### Contexte & Menace
Une attaque par déni de service distribué (DDoS) de type SYN Flood sature les ressources réseau du pare-feu de périmètre par l'envoi massif de paquets TCP SYN avec adresses IP forgées.

### Logique d'Implémentation
1. Le collecteur télémétrique interroge les interfaces réseau en continu.
2. Pour chaque échantillon reçu d'un équipement périmétrique, le moteur vérifie deux seuils critiques :
   - Bande passante entrante : $\text{Bandwidth}_{\text{in}} \ge 800\text{ Mbps}$
   - Débit de paquets : $\text{Packets Per Second} \ge 40\,000\text{ PPS}$
3. Si l'un des seuils est franchi, l'alerte `SEC-R003` est instantanément transmise avec preuve télémétrique (débit mesuré et paquets par seconde).

---

## 4. Règle SEC-R004 : Détection d'Équipement Illégitime (Rogue MAC Address)

### Contexte & Menace
L'introduction d'un équipement pirate (ex. Raspberry Pi pirate, point d'accès Wi-Fi sauvage) branché directement sur une prise murale ou un commutateur de distribution interne permet de contourner les défenses périmétriques.

### Logique d'Implémentation
1. NetSentinel maintient une table d'approbation d'entreprise des adresses MAC légitimes (`AUTHORIZED_ENTERPRISE_MACS`), initialisée à partir des actifs inventoriés :
   - `00:1B:17:A1:01:01` (Pare-feu Palo Alto)
   - `00:1A:A0:D4:02:01` (Cisco Nexus Spine 01)
   - `00:50:56:B2:05:0A` (Serveur de Base de Données Principal)
   - etc.
2. Lors de l'ingestion d'une observation de trame (`event_type: MAC_OBSERVED`) sur un VLAN sensible (ex. `VLAN-10-CORE`), le moteur normalise l'adresse MAC (mise en majuscules, suppression des tirets/espaces).
3. Si l'adresse MAC n'apparaît pas dans la liste blanche, l'incident `SEC-R004` est levé et le switchport associé est marqué pour isolation.

---

## 5. Règle SEC-R005 : Détection d'Instabilité de Liaison (Link Flapping & Loss Burst)

### Contexte & Menace
Les battements répétitifs d'interfaces (passage rapide de l'état `UP` à `DOWN` et inversement) sont révélateurs d'un transmetteur optique SFP défaillant, d'une boucle de niveau 2 (Spanning Tree) ou d'une perturbation physique sur la dorsale de transmission.

### Logique d'Implémentation
1. Le moteur enregistre chaque transition d'état d'interface (`correlator.record_link_transition(device_id, interface, state)`).
2. Il comptabilise les transitions au cours des **60 dernières secondes**. Si $\ge 4$ transitions se produisent, l'alerte de battement de lien est levée.
3. De plus, sur le plan télémétrique, si la perte de paquets dépasse $10\%$ combinée à une latence RTT supérieure à $200\text{ ms}$, une alerte de dégradation de liaison est émise.
