# Spécification et Catalogue de l'API REST v1 — NetSentinel Enterprise

> L'API REST de NetSentinel Enterprise expose des points de terminaison pour la télémétrie, la gestion de topologie, l'investigation d'incidents SIEM et le contrôle d'équipements.

- **Format d'échange :** `JSON` (`Content-Type: application/json`)
- **Préfixe global :** `/api/v1`
- **Authentification :** Ouverte en environnement de laboratoire SOC (extensible via JWT / API Keys).

---

## 1. Endpoints de Santé et Topologie

### `GET /api/v1/health`
Retourne l'état opérationnel du serveur et les statistiques globales du parc.
- **Réponse 200 OK :**
```json
{
  "status": "HEALTHY",
  "version": "2.4.0",
  "enterprise": "UniversiaCorp Global",
  "soc_center": "UniversiaCorp Global Cyber Defense Operations Center (CDOC)",
  "timestamp": "2026-10-16T11:42:00+00:00",
  "stats": {
    "total_devices": 11,
    "online_devices": 11,
    "degraded_devices": 0,
    "critical_devices": 0,
    "active_threats": 0
  }
}
```

---

### `GET /api/v1/topology`
Fournit le graphe complet de la topologie multi-tiers (nœuds et liens physiques/logiques) pour le rendu interactif D3.js.
- **Réponse 200 OK :**
```json
{
  "nodes": [
    {
      "id": "fw-edge-01",
      "hostname": "FW-EDGE-P1.corp.internal",
      "ip": "10.0.1.1",
      "tier": "EDGE",
      "role": "Next-Gen Firewall",
      "vendor": "Palo Alto PAN-OS 11.1",
      "status": "ONLINE",
      "is_quarantined": false
    }
  ],
  "links": [
    {
      "source": "fw-edge-01",
      "target": "sw-core-a",
      "type": "FIBER_100G",
      "status": "UP"
    }
  ],
  "timestamp": "2026-10-16T11:42:00+00:00"
}
```

---

## 2. Endpoints Équipements & Diagnostics Réseau

### `GET /api/v1/devices`
Liste l'ensemble des équipements enregistrés avec filtrage optionnel.
- **Paramètres de requête (Query params) :**
  - `tier` : Filtrer par niveau réseau (`EDGE`, `CORE`, `DMZ`, `SERVICES`, `DATABASE`).
  - `status` : Filtrer par état de santé (`ONLINE`, `DEGRADED`, `CRITICAL`).
  - `q` : Recherche textuelle sur le hostname, l'IP ou le rôle.
- **Réponse 200 OK :**
```json
{
  "count": 11,
  "devices": [...]
}
```

---

### `GET /api/v1/devices/<device_id>`
Récupère les détails d'un équipement et son historique télémétrique récent.
- **Réponse 200 OK :**
```json
{
  "device": {
    "id": "db-prod-pri",
    "hostname": "PG-CLUSTER-MASTER.corp.internal",
    "ip_address": "10.0.5.10",
    "status": "ONLINE",
    "tier": "DATABASE"
  },
  "telemetry_history": [...]
}
```

---

### `POST /api/v1/devices/<device_id>/probe`
Exécute une **véritable sonde de diagnostic** (ICMP Echo request et poignée de main TCP sur les ports applicatifs configurés) depuis le serveur.
- **Réponse 200 OK :**
```json
{
  "device_id": "fw-edge-01",
  "hostname": "FW-EDGE-P1.corp.internal",
  "ip_address": "10.0.1.1",
  "icmp": {
    "reachable": true,
    "status": "REACHABLE",
    "rtt_ms": 1.45,
    "packet_loss_percent": 0.0,
    "diagnosis": "Host responded to echo probe within nominal round-trip time."
  },
  "services": [
    {
      "port": 443,
      "name": "PAN-OS WebUI",
      "status": "OPEN",
      "is_open": true,
      "rtt_ms": 2.1,
      "diagnosis": "TCP connection established successfully."
    },
    {
      "port": 22,
      "name": "SSH",
      "status": "OPEN",
      "is_open": true,
      "rtt_ms": 1.8,
      "diagnosis": "TCP connection established successfully."
    }
  ],
  "timestamp": "2026-10-16T11:42:00+00:00"
}
```

---

### `POST /api/v1/devices/<device_id>/quarantine`
Applique ou lève une isolation réseau logicielle sur la machine cible et consigne l'action dans le journal d'audit de conformité.
- **Corps de la requête (Request Body) :**
```json
{
  "quarantine": true,
  "operator": "SOC-Analyst-01",
  "reason": "Host suspected of credential stuffing involvement"
}
```
- **Réponse 200 OK :**
```json
{
  "status": "SUCCESS",
  "device_id": "db-prod-pri",
  "is_quarantined": true,
  "action_enforced": "SOFTWARE_NMS_ROUTING_FILTER",
  "timestamp": "2026-10-16T11:42:00+00:00"
}
```

---

## 3. Endpoints Télémétrie en Direct

### `GET /api/v1/telemetry/live`
Fournit l'instantané agrégé du cluster et les derniers échantillons horodatés de chaque machine. Déclenche automatiquement l'élagage des données anciennes (`prune_old_samples`).
- **Réponse 200 OK :**
```json
{
  "cluster_summary": {
    "aggregate_bandwidth_in_mbps": 438.2,
    "aggregate_bandwidth_out_mbps": 395.1,
    "cluster_avg_latency_ms": 2.15,
    "devices_reporting": 11
  },
  "samples": [
    {
      "device_id": "fw-edge-01",
      "cpu_percent": 28.5,
      "memory_percent": 42.1,
      "latency_ms": 1.2,
      "packet_loss_percent": 0.0,
      "bandwidth_in_mbps": 145.8,
      "bandwidth_out_mbps": 132.4,
      "packets_per_sec": 14200,
      "is_simulated": true,
      "collector_method": "SYNTHETIC_ENTERPRISE_TELEMETRY"
    }
  ]
}
```

---

## 4. Endpoints SIEM & Gestion des Alertes

### `GET /api/v1/alerts`
Liste les alertes de sécurité avec filtres optionnels (`status`, `severity`, `device_id`).
- **Réponse 200 OK :**
```json
{
  "count": 1,
  "alerts": [
    {
      "id": "ALT-BF-50EF4E91",
      "device_id": "db-prod-pri",
      "severity": "CRITICAL",
      "rule_id": "SEC-R001",
      "mitre_id": "T1110.001",
      "title": "SSH Credential Brute-Force Detected",
      "message": "Detected 8 failed SSH login attempts from unauthorized IP 185.220.101.42 within 60s.",
      "status": "NEW",
      "created_at": "2026-10-16T11:42:00+00:00"
    }
  ]
}
```

---

### `POST /api/v1/alerts/<alert_id>/acknowledge`
Prend en charge une alerte par l'opérateur SOC (`status: ACKNOWLEDGED`).

---

### `POST /api/v1/alerts/<alert_id>/resolve`
Clôture une alerte avec note d'incident. Déclenche le recalcul dynamique de santé (`recompute_status`) pour rétablir automatiquement le nœud à `ONLINE` si aucune autre alerte active ne subsiste.
- **Corps de la requête :**
```json
{
  "resolution_note": "Attacker IP blocked on perimeter firewall, credentials rotated."
}
```

---

### `POST /api/v1/events/ingest`
Point d'entrée du pipeline de collecte de journaux SIEM. Accepte un objet unique ou un tableau d'événements.
- **Corps de la requête (Exemple unitaire) :**
```json
{
  "source_ip": "185.220.101.42",
  "target_device_id": "db-prod-pri",
  "event_type": "AUTH_FAILURE",
  "protocol": "SSH",
  "raw_message": "Failed password for root from 185.220.101.42 port 48291 ssh2"
}
```
- **Réponse 201 Created :**
```json
{
  "status": "INGESTED",
  "ingested_count": 1,
  "alerts_triggered_count": 1,
  "alerts": [...]
}
```

---

### `GET /api/v1/events`
Consulte les derniers événements de sécurité bruts ingérés.

---

### `GET /api/v1/audit`
Consulte la piste d'audit de conformité (actions d'isolement, résolutions d'incidents, interventions des opérateurs).
- **Réponse 200 OK :**
```json
{
  "count": 2,
  "logs": [
    {
      "id": 1,
      "timestamp": "2026-10-16T11:42:00+00:00",
      "operator": "SOC-Operator",
      "action": "QUARANTINE_ENFORCE",
      "target_id": "db-prod-pri",
      "details": "Administrative software isolation via NetSentinel Console"
    }
  ]
}
```

---

## 5. Endpoints de Simulation Cyber

### `POST /api/v1/simulation/attack`
Injecte un scénario cyberréaliste prédéfini pour tester la détection et les alertes.
- **Scénarios disponibles (`attack_type`) :**
  - `ddos` : Attaque SYN Flood volumétrique sur le pare-feu de bordure (Règle SEC-R003).
  - `brute_force` : Attaque SSH par force brute contre le cluster PostgreSQL (Règle SEC-R001).
  - `port_scan` : Balayage horizontal de ports contre le proxy DMZ (Règle SEC-R002).
  - `link_flap` : Battement de liaison fibre et rafale de perte de paquets sur le cœur Spine (Règle SEC-R005).
  - `rogue_mac` : Injection d'une adresse MAC non approuvée sur le VLAN sensible (Règle SEC-R004).
