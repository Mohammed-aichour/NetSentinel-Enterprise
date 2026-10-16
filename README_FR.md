# NetSentinel Enterprise — Plateforme de Sécurité Réseau & Supervision Télémétrique d'Entreprise (NMS / SIEM)

[![CI/CD Tests](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/Mohammed-aichour/NetSentinel-Enterprise/actions)
[![Version Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Licence: MIT](https://img.shields.io/badge/Licence-MIT-yellow.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/S%C3%A9curit%C3%A9-MITRE%20ATT%26CK-crimson.svg)](https://attack.mitre.org/)
[![Démo SOC en Direct](https://img.shields.io/badge/D%C3%A9mo%20Live-GitHub%20Pages-success.svg)](https://mohammed-aichour.github.io/NetSentinel-Enterprise/)

> **NetSentinel Enterprise** est une plateforme de supervision de réseaux et de gestion des événements de sécurité (NMS / SIEM) conçue pour les infrastructures d'entreprise et les centres de données d'envergure. Inspirée des standards de l'industrie (Zabbix, Wazuh, Prometheus, Nagios), elle combine cartographie dynamique de topologie, collecte télémétrique multi-protocoles, corrélation d'attaques cyber alignée sur MITRE ATT&CK, et orchestration d'incidents SOC au sein d'une console opérationnelle unifiée.

---

## 🌐 Démonstration Interactive SOC en Ligne

Testez la console Cyber SOC en temps réel directement dans votre navigateur :  
👉 **[Accéder à la Démo Live NetSentinel SOC](https://mohammed-aichour.github.io/NetSentinel-Enterprise/)**

---

## 🏛️ Architecture Réseau Multi-Niveaux

NetSentinel surveille une topologie d'entreprise structurée en six niveaux de sécurité :

* **Niveau 0 (Périmètre / Bordure) :** Pare-feu de nouvelle génération Palo Alto PA-5450, Fortinet FortiGate-3700F et routeur de bordure Cisco ASR 9904 BGP.
* **Niveau 1 (Dorsale de Cœur) :** Commutateurs de distribution Cisco Nexus 9300 interconnectés en 100GbE / 40GbE.
* **Niveau 2 (Zone DMZ) :** Reverse proxy / WAF Nginx Enterprise et passerelle WireGuard / OpenVPN.
* **Niveau 3 (Services Communs) :** Contrôleur de domaine Active Directory Windows Server 2022 et serveur maître NetSentinel SIEM.
* **Niveau 4 (Bases de Données Critiques) :** Cluster haute disponibilité PostgreSQL 16 (Maître et Réplica en réplication synchrone).
* **Niveau 5 (Accès & Terminaux) :** Commutateurs Cisco Catalyst 9200, postes de travail ingénieurs et caméras de sécurité Axis 4K.

---

## ⚡ Fonctionnalités Clés

1. **Collecteur Télémétrique Haute Fidélité :**
   * Sondes ICMP ping mesurant en temps réel la latence RTT et la gigue.
   * Sondes de ports TCP (vérification du 3-way handshake sur les ports 80, 443, 22, 53, 5432).
   * Émulation SNMP MIB-II synthétique avec variabilité stochastique selon le rôle opérationnel de chaque équipement.
   * Base de données relationnelle SQLite optimisée en mode WAL (Write-Ahead Logging).

2. **Moteur de Corrélation SIEM (MITRE ATT&CK) :**
   * **`SEC-R001` (T1110.001) :** Détection de force brute SSH / RDP (> 5 échecs en 60s).
   * **`SEC-R002` (T1046) :** Détection de balayage de ports horizontal / vertical (> 12 ports en 30s).
   * **`SEC-R003` (T1498.001) :** Détection d'anomalie volumétrique DDoS (> 3x le débit de base ou > 30k PPS).
   * **`SEC-R004` (T1200) :** Détection d'adresses MAC non autorisées sur VLAN sensible.
   * **`SEC-R005` :** Détection d'instabilité de liaison (flapping d'interface).

3. **Console SOC & Simulateur d'Attaques :**
   * Cartographie Canvas interactive avec impulsions de trafic animées et infobulles détaillées.
   * Graphiques télémétriques en continu (débit global, latence moyenne du cluster, taux de perte de paquets).
   * Simulateur d'attaques intégré pour tester instantanément la levée d'alertes et la mise en quarantaine d'hôtes.
   * Procédure d'isolation réseau en 1 clic (Quarantine Host).

---

## 🚀 Démarrage Rapide

```bash
# 1. Cloner le dépôt
git clone https://github.com/Mohammed-aichour/NetSentinel-Enterprise.git
cd NetSentinel-Enterprise

# 2. Créer l'environnement virtuel et installer les dépendances
python -m venv .venv
.\.venv\Scripts\Activate.ps1    # Sur Windows PowerShell
# source .venv/bin/activate     # Sur Linux / macOS
pip install -r requirements.txt

# 3. Lancer le serveur NetSentinel
python app.py
```
Accédez à la console SOC à l'adresse : **`http://localhost:8080/`**.

---

## 🧪 Tests Automatisés

```bash
pytest -v
```
**18 tests unitaires et d'intégration réussis à 100% :**
* Sondes réseau ICMP et TCP.
* Moteur télémétrique et SNMP.
* Règles de détection SIEM et corrélation MITRE ATT&CK.
* Machine d'état des alertes et déduplication.
* Endpoints de l'API REST.

---

## 👤 Auteur

**Mohammed Aichour**  
*Étudiant Ingénieur en Génie Informatique & Réseaux — Universiapolis (Agadir, Maroc)*  
*Spécialisation : Cybersécurité, Architectures Réseaux & Développement Full-Stack*  

* **GitHub :** [@Mohammed-aichour](https://github.com/Mohammed-aichour)
* **Portfolio :** [mohammed-aichour.github.io](https://mohammed-aichour.github.io/)

---

## 📄 Licence

Ce projet est sous licence [MIT](LICENSE) — libre pour usage académique, d'entreprise et de recherche.
