# Guide de Validation et Tests Automatisés — NetSentinel Enterprise

> Ce document explique l'organisation de la suite de tests automatisés de NetSentinel Enterprise, comment exécuter les tests et comment interpréter les résultats.

---

## 1. Vue d'Ensemble de la Suite de Tests

La plateforme intègre **26 tests automatisés** couvrant l'ensemble des composants critiques :
1. **Gestionnaire d'Alertes (`test_alert_manager.py`) :** Déduplication, cycle de vie, calcul de santé en boucle fermée.
2. **Collecteur Réseau (`test_collector.py`) :** Sondes ICMP réelles, sondes TCP par socket, gestion de la perte de paquets et étiquetage honnête des données simulées.
3. **Moteur SIEM de Corrélation (`test_correlator.py`) :** Règles de détection MITRE ATT&CK SEC-R001 à SEC-R005, fenêtres temporelles glissantes.
4. **API REST et Cycle Intégral (`test_api.py`) :** Tous les points de terminaison HTTP, l'ingestion d'événements, le journal d'audit et le scénario complet d'attaque-remédiation.

---

## 2. Exécution des Tests

Assurez-vous que votre environnement virtuel est activé, puis lancez `pytest` :

### Exécution standard :
```bash
pytest
```

### Exécution détaillée avec noms des tests :
```bash
pytest -v
```

### Exécution d'un module spécifique :
```bash
# Tester uniquement le moteur de corrélation SIEM
pytest -v tests/test_correlator.py

# Tester uniquement l'API REST
pytest -v tests/test_api.py
```

---

## 3. Détail des Tests par Module

### `tests/test_alert_manager.py` (2 tests)
- `test_alert_processing_and_deduplication` : Vérifie que le gestionnaire évite de créer des doublons lorsqu'une même menace persiste sur le même équipement.
- `test_alert_acknowledgment_and_resolution` : Valide la transition d'état d'alerte (`NEW` → `ACKNOWLEDGED` → `RESOLVED`) et la restauration automatique de la santé du nœud à `ONLINE`.

### `tests/test_collector.py` (6 tests)
- `test_localhost_ping` : Valide la sonde ICMP sur l'interface de bouclage locale (127.0.0.1) et vérifie la présence du statut `REACHABLE` et de la latence RTT.
- `test_unreachable_ping` : Vérifie le comportement nominal face à une adresse IP inexistante (timeout, calcul de 100% de perte de paquets).
- `test_tcp_port_probe_refused` : Sonde un port TCP fermé (ex. 65432) et vérifie la détection du statut `REFUSED` avec code diagnostic.
- `test_local_telemetry_metrics` : Valide l'extraction de métriques réelles du système hôte via `psutil`.
- `test_synthetic_device_telemetry_firewall` : Vérifie que les métriques synthétiques du pare-feu sont étiquetées honnêtement `is_simulated: True`.
- `test_quarantined_device_telemetry` : Vérifie que les équipements placés en quarantaine ont un trafic nul (0 Mbps / 0 PPS).

### `tests/test_correlator.py` (6 tests)
- `test_ssh_brute_force_detection` : Vérifie la détection de la règle SEC-R001 (MITRE T1110.001) lors de 5 échecs consécutifs d'authentification SSH.
- `test_port_scan_detection` : Valide la détection de balayage de ports SEC-R002 (MITRE T1046) lors de la tentative sur 10 ports distincts.
- `test_volumetric_ddos_detection` : Teste le seuil d'anomalie de trafic SEC-R003 (MITRE T1498.001) lors d'un pic supérieur à 800 Mbps.
- `test_rogue_mac_detection` : Teste la règle SEC-R004 (MITRE T1200) interceptant une adresse MAC inconnue sur le réseau cœur.
- `test_interface_flapping_detection` : Valide la règle SEC-R005 (NMS-NET-01) lors de 4 battements d'état de lien d'interface.
- `test_telemetry_threshold_alerts` : Vérifie la génération d'alertes NMS lors de dépassement de seuil de perte de paquets (> 10%).

### `tests/test_api.py` (12 tests)
- `test_health_endpoint` : Vérifie la disponibilité du service (`GET /api/v1/health`).
- `test_topology_endpoint` : Valide le graphe complet des nœuds et liens de l'entreprise.
- `test_devices_listing_and_filtering` : Teste les filtres par tier (`EDGE`, `CORE`, `DMZ`, etc.) et par statut.
- `test_device_detail_endpoint` : Récupère les métadonnées d'un équipement spécifique.
- `test_device_probe_endpoint` : Exécute une véritable sonde ICMP et TCP via l'API REST.
- `test_device_quarantine_toggle` : Active et désactive l'isolation logicielle d'une machine.
- `test_telemetry_live_endpoint` : Récupère le flux agrégé en temps réel du cluster.
- `test_simulation_attack_endpoint` : Déclenche une attaque de démonstration via l'API.
- `test_all_simulation_scenarios` : Valide les 5 scénarios d'attaque (`ddos`, `brute_force`, `port_scan`, `link_flap`, `rogue_mac`).
- `test_events_ingest_and_retrieval` : Valide l'ingestion d'événements unitaires et par lot (batch) dans le pipeline SIEM.
- `test_audit_logs_endpoint` : Vérifie la consultation des pistes d'audit de conformité.
- `test_closed_loop_lifecycle` : Scénario complet de bout en bout (Attaque → Dégradation de santé → Détection SIEM → Résolution de l'incident → Restauration automatique de l'état nominal).

---

## 4. Exemple de Rapport de Test Réussi

```text
============================= test session starts =============================
platform win32 -- Python 3.13.15, pytest-9.1.1, pluggy-1.7.0
rootdir: NetSentinel-Enterprise
collected 26 items

tests/test_alert_manager.py::TestAlertManager::test_alert_acknowledgment_and_resolution PASSED [  3%]
tests/test_alert_manager.py::TestAlertManager::test_alert_processing_and_deduplication PASSED [  7%]
tests/test_api.py::TestRestAPI::test_all_simulation_scenarios PASSED     [ 11%]
tests/test_api.py::TestRestAPI::test_audit_logs_endpoint PASSED          [ 15%]
tests/test_api.py::TestRestAPI::test_closed_loop_lifecycle PASSED        [ 19%]
tests/test_api.py::TestRestAPI::test_device_detail_endpoint PASSED       [ 23%]
tests/test_api.py::TestRestAPI::test_device_probe_endpoint PASSED        [ 26%]
tests/test_api.py::TestRestAPI::test_device_quarantine_toggle PASSED     [ 30%]
tests/test_api.py::TestRestAPI::test_devices_listing_and_filtering PASSED [ 34%]
tests/test_api.py::TestRestAPI::test_events_ingest_and_retrieval PASSED  [ 38%]
tests/test_api.py::TestRestAPI::test_health_endpoint PASSED              [ 42%]
tests/test_api.py::TestRestAPI::test_simulation_attack_endpoint PASSED   [ 46%]
tests/test_api.py::TestRestAPI::test_telemetry_live_endpoint PASSED      [ 50%]
tests/test_api.py::TestRestAPI::test_topology_endpoint PASSED            [ 53%]
tests/test_collector.py::TestNetworkCollector::test_local_telemetry_metrics PASSED [ 57%]
tests/test_collector.py::TestNetworkCollector::test_localhost_ping PASSED [ 61%]
tests/test_collector.py::TestNetworkCollector::test_quarantined_device_telemetry PASSED [ 65%]
tests/test_collector.py::TestNetworkCollector::test_synthetic_device_telemetry_firewall PASSED [ 69%]
tests/test_collector.py::TestNetworkCollector::test_tcp_port_probe_refused PASSED [ 73%]
tests/test_collector.py::TestNetworkCollector::test_unreachable_ping PASSED [ 76%]
tests/test_correlator.py::TestEventCorrelator::test_interface_flapping_detection PASSED [ 80%]
tests/test_correlator.py::TestEventCorrelator::test_port_scan_detection PASSED [ 84%]
tests/test_correlator.py::TestEventCorrelator::test_rogue_mac_detection PASSED [ 88%]
tests/test_correlator.py::TestEventCorrelator::test_ssh_brute_force_detection PASSED [ 92%]
tests/test_correlator.py::TestEventCorrelator::test_telemetry_threshold_alerts PASSED [ 96%]
tests/test_correlator.py::TestEventCorrelator::test_volumetric_ddos_detection PASSED [100%]

============================= 26 passed in 7.12s ==============================
```
