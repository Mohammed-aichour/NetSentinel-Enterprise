# NetSentinel Enterprise — Journal de Progression du Développement & Audit Technique

> **Projet :** NetSentinel Enterprise (NMS / SIEM Platform)  
> **Auteur :** Mohammed AICHOUR  
> **Encadrement & Mentorat :** Antigravity Senior Engineering Assistant  
> **Date de démarrage de l'audit :** 16 Octobre 2026  
> **Statut global :** Phase 1 terminée — Audit complet établi, passage à la Phase 2.

---

## 📋 1. Rapport d'Audit Initial (Phase 1)

Une inspection minutieuse ligne par ligne de la totalité du code source a été réalisée (Backend Python, Base de données SQLite, Moteur SIEM, Frontend Canvas/JS, Tests automatisés, Docker).

### Catégorie 1 : Fonctionnalités Réellement Opérationnelles & Vérifiées
* **Télémétrie Système Réelle de l'Hôte :** `TelemetryCollector.get_local_system_telemetry()` collecte les véritables métriques CPU%, RAM%, Disque% et compteurs d'E/S réseau via `psutil`.
* **Sonde ICMP Ping Réelle :** `NetworkProbe.ping_host()` exécute une vraie commande système `ping` sous Windows (`-n 1`) et Linux (`-c 1`) avec mesure RTT et calcul de perte.
* **Sonde de Ports TCP Réelle :** `NetworkProbe.check_tcp_port()` réalise un véritable *3-way handshake* TCP avec gestion du timeout via `socket.connect_ex`.
* **Persistance Relationnelle SQLite WAL :** Gestionnaire de contexte sécurisé `get_connection()` garantissant la fermeture explicite des connexions (`conn.close()`) et l'activation du mode WAL (*Write-Ahead Logging*).
* **Endpoints REST API (`backend/routes/api.py`) :**
  - `GET /api/v1/health` : santé globale et compteurs.
  - `GET /api/v1/topology` : extraction des nœuds et des liaisons réseau.
  - `GET /api/v1/devices` : catalogue filtrable par niveau (*tier*), statut et recherche textuelle.
  - `GET /api/v1/devices/<id>` : détails d'un équipement et historique télémétrique.
  - `POST /api/v1/devices/<id>/probe` : exécute une vraie sonde ICMP et de vrais tests TCP sur les ports configurés.
  - `POST /api/v1/devices/<id>/quarantine` : mise à jour de l'état d'isolation logiciel.
  - `GET /api/v1/telemetry/live` : agrégation des flux du cluster.
  - `GET /api/v1/alerts` : liste des alertes actives.
  - `POST /api/v1/alerts/<id>/acknowledge` : accusé de réception SOC.
* **Moteur SIEM (3 règles validées) :**
  - `check_brute_force()` : fenêtre glissante sur échecs d'authentification (Règle `SEC-R001`, MITRE T1110.001).
  - `check_port_scan()` : fenêtre glissante sur ports scannés uniques (Règle `SEC-R002`, MITRE T1046).
  - `check_volumetric_ddos()` : comparaison au débit de base / seuil PPS (Règle `SEC-R003`, MITRE T1498.001).
  - `check_telemetry_thresholds()` : alertes de seuil CPU, latence et perte.
* **Moteur Visuel Canvas (`frontend/js/topology.js`) :** Cartographie dynamique par couches (*Tiers*), particules animées sur les câbles actifs, infobulles au survol et glisser-déposer des nœuds.
* **Graphiques Télémétriques Canvas (`frontend/js/charts.js`) :** Rendu streaming de courbes avec gradient sans aucune dépendance CDN externe.

---

### Catégorie 2 : Fonctionnalités Partiellement Implémentées
* **Rétablissement de l'état de santé lors de la résolution d'une alerte :**
  Quand `AlertManager.resolve_alert()` résout une alerte, le statut de l'alerte passe bien à `RESOLVED`, mais le statut de l'équipement (`CRITICAL` ou `DEGRADED`) reste bloqué et n'est jamais réévalué pour redevenir `ONLINE`.
* **Déduplication des Alertes :**
  Le filtre empêche la création de doublons identiques, mais ne comptabilise pas le nombre d'occurrences répétées (*hit count*) ni la dernière heure d'observation.
* **Distinction Visuelle Réel vs Simulé dans l'interface :**
  Le badge global `API LIVE` vs `STATIC DEMO` existe, mais dans les fiches d'équipements et les graphiques, il n'y a pas d'indication claire précisant si une donnée provient d'une sonde réelle ou de l'émulateur synthétique.
* **Mécanisme d'Isolation / Quarantaine :**
  Actuellement, la mise en quarantaine modifie un booléen en base de données et dégrade le statut, mais ne génère aucune règle de filtrage pare-feu logiciel réelle (ni simulation honnête d'ACL Cisco/iptables), et ne fournit pas d'audit détaillé de l'action.

---

### Catégorie 3 : Fonctionnalités Simulées (Synthétiques)
* **Équipements du Réseau d'Entreprise :** Les 14 équipements (Palo Alto, Cisco ASR, Nexus, Windows Server DC, PostgreSQL HA) représentent une topologie modèle de centre de données.
* **Télémétrie SNMP MIB-II :** Les valeurs de bande passante, CPU et paquets/seconde sont générées avec un modèle stochastique mathématique réaliste par rôle d'équipement, et non par interrogation UDP port 161 de routeurs physiques inexistants dans l'environnement local.
* **Simulateur d'Attaques :** Les scénarios (DDoS, Brute Force, Scan, Flap) injectent des événements de test dans la mémoire du corrélateur pour valider les règles en circuit fermé, sans attaquer de réseau externe.

---

### Catégorie 4 : Fonctionnalités Manquantes ou Défaillantes (Bugs Identifiés)
* **Bouton Factice (*Mocked Alert*) dans l'Interface :**
  Dans `frontend/index.html` (ligne 318), le bouton `Execute Live ICMP Probe` contient un code JavaScript codé en dur : `onclick="alert('ICMP Probe Executed: Round-trip RTT: 1.2ms...')"` au lieu d'appeler l'endpoint réel `POST /api/v1/devices/<id>/probe`.
* **Règle SIEM SEC-R004 (Rogue MAC) non implémentée :**
  Définie dans `backend/config.py` et documentée dans le README, mais la fonction `check_rogue_mac()` n'existe nulle part dans `backend/engine/correlator.py`.
* **Règle SIEM SEC-R005 (Flapping d'Interface) incomplète :**
  La règle de flapping multi-transitions dans le temps n'est pas implémentée ; seule une détection de perte de paquet ponctuelle était présente.
* **Absence d'Ingestion Directe d'Événements SIEM :**
  Aucun endpoint `POST /api/v1/events/ingest` ne permettait à des scripts externes ou à des agents d'envoyer des journaux bruts de sécurité au corrélateur.
* **Accumulation Infinie des Métriques Télémétriques (Fuite de Stockage) :**
  À chaque appel de `/telemetry/live` (toutes les 4 secondes), 14 échantillons sont insérés dans la table `telemetry_samples` sans routine de purge des données expirées (> 120 points).
* **Absence de Documentation Pédagogique Dédiée en Français :**
  Les guides `docs/PROJECT_GUIDE.md`, `docs/INSTALLATION.md`, `docs/TESTING.md`, `docs/API.md`, et `docs/DETECTION_RULES.md` doivent être créés.

---

## 🛠️ 2. Matrice des 8 Phases de Développement

| Phase | Description | Statut |
| :--- | :--- | :--- |
| **Phase 1** | Audit exhaustif du dépôt, vérification du socle de tests baseline. | **TERMINÉE** ✅ |
| **Phase 2** | Correction des bugs critiques, assainissement de l'architecture, rétablissement de santé en boucle fermée (`recompute_status`). | **TERMINÉE** ✅ |
| **Phase 3** | Fiabilisation du collecteur réseau, diagnostic réel ICMP & TCP, étiquetage honnête et purge automatique de stockage (`prune_old_samples`). | **TERMINÉE** ✅ |
| **Phase 4** | Implémentation et tests complets des 5 règles SIEM (SEC-R001 à SEC-R005, MITRE ATT&CK). | **TERMINÉE** ✅ |
| **Phase 5** | Intégration frontend/backend rigoureuse, suppression du bouton factice, panneau de diagnostic réel dans la console SOC. | **TERMINÉE** ✅ |
| **Phase 6** | Validation du flux Simulateur ➔ Ingestion ➔ Corrélation ➔ Alerte et Quarantaine honnête avec audit de conformité. | **TERMINÉE** ✅ |
| **Phase 7** | Sécurité, robustesse des entrées, 5 guides pédagogiques complets en français (`PROJECT_GUIDE`, `INSTALLATION`, `TESTING`, `API`, `DETECTION_RULES`). | **TERMINÉE** ✅ |
| **Phase 8** | Tests de régression finaux 100% (26/26 passés), synchronisation des miroirs et rapport de synthèse. | **TERMINÉE** ✅ |

---

## 🧪 3. Résultats des Tests de Validation Finaux

* **Date d'exécution :** 16 Octobre 2026
* **Commande :** `pytest -v`
* **Résultat :** **26 tests passés avec succès / 0 échec (100% de réussite en 7.12s)**.

### Détail des composants validés :
1. `tests/test_alert_manager.py` : Déduplication des alertes, cycle de vie complet (`NEW` → `ACK` → `RESOLVE`), et auto-rétablissement dynamique de l'état nominal (`ONLINE`).
2. `tests/test_collector.py` : Diagnostic réel ICMP ping avec calcul RTT et perte, détection de ports TCP fermés/ouverts, télémétrie locale réelle via `psutil`, et étiquetage honnête des données synthétiques.
3. `tests/test_correlator.py` : Validation unitaire des règles MITRE SEC-R001 (SSH Brute Force), SEC-R002 (Port Sweep), SEC-R003 (Volumetric DDoS), SEC-R004 (Rogue MAC sur VLAN sensible), et SEC-R005 (Flapping de liaison fibre).
4. `tests/test_api.py` : 12 tests d'intégration couvrant la santé, la topologie, le catalogue d'équipements, la sonde réelle `/probe`, le basculement d'isolation `/quarantine`, l'ingestion unitaire et par lot `/events/ingest`, les pistes d'audit `/audit`, les 5 scénarios d'attaque et le cycle complet en boucle fermée.

