/**
 * NetSentinel Enterprise - SOC Dashboard Application Controller
 * Real-time API synchronization, alert operations, device CRUD, attack simulation, and offline demo fallback.
 * Author: Mohammed Aichour
 */

const FALLBACK_ENTERPRISE_TOPOLOGY = {
  nodes: [
    { id: "fw-edge-01", hostname: "FW-EDGE-P1.corp.internal", ip: "10.0.1.1", tier: "EDGE", role: "Next-Gen Firewall", vendor: "Palo Alto PAN-OS 11.1", status: "ONLINE", is_quarantined: false, services_count: 2 },
    { id: "fw-edge-02", hostname: "FW-EDGE-P2-HA.corp.internal", ip: "10.0.1.2", tier: "EDGE", role: "Next-Gen Firewall HA", vendor: "Fortinet FortiGate-3700F", status: "ONLINE", is_quarantined: false, services_count: 1 },
    { id: "rtr-border-01", hostname: "RTR-BGP-CORE.corp.internal", ip: "10.0.1.254", tier: "EDGE", role: "Border BGP Router", vendor: "Cisco ASR 9904", status: "ONLINE", is_quarantined: false, services_count: 2 },
    { id: "sw-core-a", hostname: "SW-CORE-SPINE-01.corp.internal", ip: "10.0.2.1", tier: "CORE", role: "Spine Switch 01", vendor: "Cisco Nexus 9300", status: "ONLINE", is_quarantined: false, services_count: 2 },
    { id: "sw-core-b", hostname: "SW-CORE-SPINE-02.corp.internal", ip: "10.0.2.2", tier: "CORE", role: "Spine Switch 02", vendor: "Cisco Nexus 9300", status: "ONLINE", is_quarantined: false, services_count: 2 },
    { id: "srv-proxy-01", hostname: "DMZ-WAF-PROXY01.corp.internal", ip: "10.0.3.10", tier: "DMZ", role: "Reverse Proxy & WAF", vendor: "Nginx Enterprise", status: "ONLINE", is_quarantined: false, services_count: 2 },
    { id: "srv-vpn-gw", hostname: "DMZ-VPN-GATEWAY.corp.internal", ip: "10.0.3.20", tier: "DMZ", role: "VPN Gateway", vendor: "WireGuard Enterprise", status: "ONLINE", is_quarantined: false, services_count: 2 },
    { id: "srv-ad-dc01", hostname: "DC01-PRIMARY.corp.internal", ip: "10.0.4.10", tier: "SERVICES", role: "Active Directory DC", vendor: "Windows Server 2022", status: "ONLINE", is_quarantined: false, services_count: 4 },
    { id: "srv-siem-01", hostname: "NETSENTINEL-SOC01.corp.internal", ip: "10.0.4.50", tier: "SERVICES", role: "SIEM & Collector", vendor: "NetSentinel Engine", status: "ONLINE", is_quarantined: false, services_count: 2 },
    { id: "db-prod-pri", hostname: "PG-CLUSTER-MASTER.corp.internal", ip: "10.0.5.10", tier: "DATABASE", role: "Primary Database", vendor: "PostgreSQL 16", status: "ONLINE", is_quarantined: false, services_count: 2 },
    { id: "db-prod-rep", hostname: "PG-CLUSTER-REPLICA.corp.internal", ip: "10.0.5.11", tier: "DATABASE", role: "Standby Replica", vendor: "PostgreSQL 16", status: "ONLINE", is_quarantined: false, services_count: 2 },
    { id: "sw-access-fl1", hostname: "SW-LEAF-FLOOR1.corp.internal", ip: "10.0.10.1", tier: "ACCESS", role: "Floor 1 Switch", vendor: "Cisco Catalyst 9200", status: "ONLINE", is_quarantined: false, services_count: 1 },
    { id: "ws-eng-dev01", hostname: "WS-DEV-MOHAMMED.corp.internal", ip: "10.0.10.105", tier: "ACCESS", role: "Engineer Workstation", vendor: "Ubuntu Linux 24.04", status: "ONLINE", is_quarantined: false, services_count: 1 },
    { id: "iot-cam-gate", hostname: "CAM-MAIN-ENTRANCE.iot.internal", ip: "10.0.20.15", tier: "ACCESS", role: "IP Camera", vendor: "Axis 4K H.265", status: "ONLINE", is_quarantined: false, services_count: 2 }
  ],
  links: [
    { source_id: "rtr-border-01", target_id: "fw-edge-01", link_type: "100GbE", status: "UP" },
    { source_id: "rtr-border-01", target_id: "fw-edge-02", link_type: "100GbE", status: "UP" },
    { source_id: "fw-edge-01", target_id: "sw-core-a", link_type: "40GbE", status: "UP" },
    { source_id: "fw-edge-02", target_id: "sw-core-b", link_type: "40GbE", status: "UP" },
    { source_id: "sw-core-a", target_id: "sw-core-b", link_type: "100GbE", status: "UP" },
    { source_id: "sw-core-a", target_id: "srv-proxy-01", link_type: "10GbE", status: "UP" },
    { source_id: "sw-core-b", target_id: "srv-vpn-gw", link_type: "10GbE", status: "UP" },
    { source_id: "sw-core-a", target_id: "srv-ad-dc01", link_type: "10GbE", status: "UP" },
    { source_id: "sw-core-b", target_id: "srv-siem-01", link_type: "10GbE", status: "UP" },
    { source_id: "sw-core-a", target_id: "db-prod-pri", link_type: "25GbE", status: "UP" },
    { source_id: "sw-core-b", target_id: "db-prod-rep", link_type: "25GbE", status: "UP" },
    { source_id: "db-prod-pri", target_id: "db-prod-rep", link_type: "25GbE", status: "UP" },
    { source_id: "sw-core-a", target_id: "sw-access-fl1", link_type: "10GbE", status: "UP" },
    { source_id: "sw-access-fl1", target_id: "ws-eng-dev01", link_type: "1GbE", status: "UP" },
    { source_id: "sw-access-fl1", target_id: "iot-cam-gate", link_type: "1GbE", status: "UP" }
  ]
};

class SocApplication {
  constructor() {
    this.isLiveBackend = false;
    this.databaseEngine = "SQLite";
    this.topology = null;
    this.alerts = [];
    this.devices = [];
    this.selectedDevice = null;
    this.deviceFormMode = "create";

    // Search and filters
    this.searchTerm = "";
    this.tierFilter = "";
    this.statusFilter = "";

    // Configurable API endpoint
    this.apiBase = typeof localStorage !== "undefined" ? (localStorage.getItem("netsentinel_api_base") || "") : "";
    this.apiKey = typeof localStorage !== "undefined" ? (localStorage.getItem("netsentinel_api_key") || "") : "";

    // Charts
    this.bwChart = null;
    this.latencyChart = null;
    this.lossChart = null;
    this.topoViz = null;

    this.init();
  }

  async init() {
    this._initClock();
    this._initVisualizers();
    this._bindUiEvents();

    await this.checkBackendAndLoad();
    setInterval(() => this.pollUpdates(), 4000);
  }

  _apiUrl(endpoint) {
    const base = this.apiBase ? this.apiBase.replace(/\/+$/, "") : "";
    return `${base}${endpoint}`;
  }

  _getHeaders(extra = {}) {
    const headers = { "Content-Type": "application/json", ...extra };
    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }
    return headers;
  }

  _initClock() {
    const el = document.getElementById("soc-clock");
    if (!el) return;
    const update = () => {
      const d = new Date();
      el.textContent = `${d.toISOString().slice(11, 19)} UTC`;
    };
    update();
    setInterval(update, 1000);
  }

  _initVisualizers() {
    this.topoViz = new NetworkTopologyVisualizer("topology-canvas", {
      onNodeSelect: (node) => this.openDeviceInspector(node.id)
    });

    this.bwChart = new RealtimeStreamChart("chart-bandwidth", {
      label: "Bandwidth In",
      unit: "Mbps",
      lineColor: "#38bdf8",
      fillColor: "rgba(56, 189, 248, 0.2)"
    });

    this.latencyChart = new RealtimeStreamChart("chart-latency", {
      label: "Avg Latency",
      unit: "ms",
      lineColor: "#10b981",
      fillColor: "rgba(16, 185, 129, 0.2)"
    });

    this.lossChart = new RealtimeStreamChart("chart-loss", {
      label: "Packet Loss",
      unit: "%",
      lineColor: "#ef4444",
      fillColor: "rgba(239, 68, 68, 0.2)"
    });
  }

  async checkBackendAndLoad() {
    try {
      const [healthRes, readyRes] = await Promise.all([
        fetch(this._apiUrl("/api/v1/health"), { headers: this._getHeaders() }),
        fetch(this._apiUrl("/api/v1/ready"), { headers: this._getHeaders() }).catch(() => null)
      ]);

      if (healthRes.ok) {
        this.isLiveBackend = true;
        if (readyRes && readyRes.ok) {
          const readyData = await readyRes.json();
          this.databaseEngine = readyData.database_engine || "Relational DB";
        }

        const badge = document.getElementById("mode-badge");
        if (badge) {
          badge.textContent = `API LIVE (${this.databaseEngine})`;
          badge.classList.remove("btn-secondary");
          badge.classList.add("btn-primary");
        }
        const streamBadge = document.getElementById("badge-telemetry-mode");
        if (streamBadge) streamBadge.textContent = "Live Python Engine Stream";
      } else {
        this._setOfflineMode();
      }
    } catch {
      this._setOfflineMode();
    }

    await this.refreshData();
  }

  _setOfflineMode() {
    this.isLiveBackend = false;
    const badge = document.getElementById("mode-badge");
    if (badge) {
      badge.textContent = "STATIC DEMO (SIMULATED)";
      badge.classList.remove("btn-primary");
      badge.classList.add("btn-secondary");
    }
    const streamBadge = document.getElementById("badge-telemetry-mode");
    if (streamBadge) streamBadge.textContent = "Simulated SNMP Stream";
  }

  async refreshData() {
    if (this.isLiveBackend) {
      await this._fetchLiveTopology();
      await this._fetchLiveAlerts();
      await this._fetchLiveDevices();
      await this._fetchLiveTelemetry();
    } else {
      this._loadFallbackData();
    }
  }

  async _fetchLiveTopology() {
    try {
      const res = await fetch(this._apiUrl("/api/v1/topology"), { headers: this._getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      this.topology = data;
      this.topoViz.setData(data.nodes, data.links);
    } catch (e) {
      console.error("Failed to fetch topology:", e);
    }
  }

  async _fetchLiveAlerts() {
    try {
      const res = await fetch(this._apiUrl("/api/v1/alerts"), { headers: this._getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      this.alerts = data.alerts;
      this.renderAlertsTable();
    } catch (e) {
      console.error("Failed to fetch alerts:", e);
    }
  }

  async _fetchLiveDevices() {
    try {
      const res = await fetch(this._apiUrl("/api/v1/devices"), { headers: this._getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      this.devices = data.devices;
      this.renderDevicesTable();
      this.updateKpiCounters();
    } catch (e) {
      console.error("Failed to fetch devices:", e);
    }
  }

  async _fetchLiveTelemetry() {
    try {
      const res = await fetch(this._apiUrl("/api/v1/telemetry/live"), { headers: this._getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const s = data.cluster_summary;
      if (s) {
        this.bwChart.pushValue(s.aggregate_bandwidth_in_mbps);
        this.latencyChart.pushValue(s.cluster_avg_latency_ms);
      }
      if (data.samples && data.samples.length > 0) {
        const avgLoss = (data.samples.reduce((acc, cur) => acc + cur.packet_loss_percent, 0) / data.samples.length).toFixed(2);
        this.lossChart.pushValue(parseFloat(avgLoss));
      }
    } catch (e) {
      console.error("Failed to fetch telemetry:", e);
    }
  }

  _loadFallbackData() {
    if (!this.topology || !this.devices || this.devices.length === 0) {
      this.topology = FALLBACK_ENTERPRISE_TOPOLOGY;
      this.devices = JSON.parse(JSON.stringify(FALLBACK_ENTERPRISE_TOPOLOGY.nodes));
      this.topoViz.setData(this.devices, this.topology.links);
    }

    if (this.alerts.length === 0) {
      this.alerts = [
        {
          id: "ALT-SEC-8142",
          device_id: "fw-edge-01",
          hostname: "FW-EDGE-P1.corp.internal",
          severity: "HIGH",
          rule_id: "SEC-R002",
          mitre_id: "T1046",
          title: "Horizontal Reconnaissance Port Sweep",
          message: "18 ports scanned by 194.26.29.112 across perimeter interface.",
          status: "NEW",
          created_at: new Date().toISOString()
        }
      ];
    }

    this.renderAlertsTable();
    this.renderDevicesTable();
    this.updateKpiCounters();
    this._pollFallbackMetrics();
  }

  _pollFallbackMetrics() {
    const simBw = Math.round(420 + Math.random() * 80);
    const simLat = parseFloat((1.8 + Math.random() * 0.8).toFixed(2));
    const simLoss = Math.random() > 0.85 ? 0.3 : 0.0;
    this.bwChart.pushValue(simBw);
    this.latencyChart.pushValue(simLat);
    this.lossChart.pushValue(simLoss);
  }

  async pollUpdates() {
    if (this.isLiveBackend) {
      await this.refreshData();
    } else {
      this._pollFallbackMetrics();
    }
  }

  updateKpiCounters() {
    const total = this.devices.length;
    const online = this.devices.filter(d => d.status === "ONLINE").length;
    const critical = this.devices.filter(d => d.status === "CRITICAL").length;
    const activeThreats = this.alerts.filter(a => a.status === "NEW").length;

    const elTotal = document.getElementById("kpi-total-nodes");
    const elOnline = document.getElementById("kpi-online-nodes");
    const elCrit = document.getElementById("kpi-critical-nodes");
    const elThreats = document.getElementById("kpi-active-threats");

    if (elTotal) elTotal.textContent = total;
    if (elOnline) elOnline.textContent = online;
    if (elCrit) elCrit.textContent = critical;
    if (elThreats) elThreats.textContent = activeThreats;
  }

  renderAlertsTable() {
    const tbody = document.getElementById("alerts-table-body");
    if (!tbody) return;

    if (this.alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 24px; color: #64748b;">No active threats detected. All perimeter and core clusters operating normally.</td></tr>`;
      return;
    }

    tbody.innerHTML = this.alerts.map(alt => `
      <tr>
        <td><span class="badge-${alt.severity.toLowerCase()}">${alt.severity}</span></td>
        <td>
          <div style="font-weight: 600; color: #f8fafc;">${alt.title}</div>
          <div style="font-size: 0.72rem; color: #94a3b8;">${alt.message}</div>
        </td>
        <td>
          <span class="badge-mitre">${alt.mitre_id || 'NMS'}</span>
        </td>
        <td>
          <span style="font-family: monospace;">${alt.device_id}</span>
        </td>
        <td>
          ${alt.status === 'NEW' ? `
            <button class="btn btn-primary" onclick="window.socApp.acknowledgeAlert('${alt.id}')" style="font-size:0.7rem; padding: 2px 8px;">Ack</button>
            <button class="btn btn-danger" onclick="window.socApp.quarantineDevice('${alt.device_id}')" style="font-size:0.7rem; padding: 2px 8px;">Isolate</button>
          ` : `
            <button class="btn btn-secondary" onclick="window.socApp.resolveAlert('${alt.id}')" style="font-size:0.7rem; padding: 2px 8px;">Resolve</button>
          `}
        </td>
      </tr>
    `).join('');
  }

  renderDevicesTable() {
    const tbody = document.getElementById("devices-table-body");
    if (!tbody) return;

    let filtered = this.devices;

    if (this.searchTerm) {
      const q = this.searchTerm.toLowerCase();
      filtered = filtered.filter(d =>
        (d.hostname && d.hostname.toLowerCase().includes(q)) ||
        ((d.ip || d.ip_address) && (d.ip || d.ip_address).includes(q)) ||
        (d.role && d.role.toLowerCase().includes(q)) ||
        (d.vendor && d.vendor.toLowerCase().includes(q))
      );
    }

    if (this.tierFilter) {
      filtered = filtered.filter(d => (d.tier || "").toUpperCase() === this.tierFilter.toUpperCase());
    }

    if (this.statusFilter) {
      if (this.statusFilter === "QUARANTINED") {
        filtered = filtered.filter(d => d.is_quarantined);
      } else {
        filtered = filtered.filter(d => (d.status || "").toUpperCase() === this.statusFilter.toUpperCase());
      }
    }

    const countBadge = document.getElementById("devices-count-badge");
    if (countBadge) {
      countBadge.textContent = `Showing ${filtered.length} of ${this.devices.length} Devices`;
    }

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 20px; color: #64748b;">No devices match the filter criteria.</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(d => `
      <tr>
        <td>
          <div style="font-weight: 600; color: #f8fafc;">${d.hostname}</div>
          <div style="font-size: 0.72rem; font-family: monospace; color: #94a3b8;">${d.ip || d.ip_address}</div>
        </td>
        <td><span class="badge-tag">${d.tier}</span></td>
        <td>${d.role}</td>
        <td>
          <span class="status-pill status-${d.is_quarantined ? 'quarantined' : d.status.toLowerCase()}">
            <span class="pulse-dot" style="${d.is_quarantined ? 'background:#64748b; box-shadow:none;' : ''}"></span>
            ${d.is_quarantined ? 'QUARANTINED' : d.status}
          </span>
        </td>
        <td>
          <button class="btn btn-secondary" onclick="window.socApp.openDeviceInspector('${d.id}')" style="font-size:0.7rem; padding: 2px 8px;">Inspect</button>
        </td>
      </tr>
    `).join('');
  }

  async acknowledgeAlert(alertId) {
    if (this.isLiveBackend) {
      await fetch(this._apiUrl(`/api/v1/alerts/${alertId}/acknowledge`), {
        method: "POST",
        headers: this._getHeaders()
      });
      await this.refreshData();
    } else {
      const a = this.alerts.find(x => x.id === alertId);
      if (a) a.status = "ACKNOWLEDGED";
      this.renderAlertsTable();
    }
  }

  async resolveAlert(alertId) {
    if (this.isLiveBackend) {
      await fetch(this._apiUrl(`/api/v1/alerts/${alertId}/resolve`), {
        method: "POST",
        headers: this._getHeaders()
      });
      await this.refreshData();
    } else {
      this.alerts = this.alerts.filter(x => x.id !== alertId);
      this.renderAlertsTable();
      this.updateKpiCounters();
    }
  }

  async quarantineDevice(deviceId, shouldQuarantine = true) {
    if (this.isLiveBackend) {
      await fetch(this._apiUrl(`/api/v1/devices/${deviceId}/quarantine`), {
        method: "POST",
        headers: this._getHeaders(),
        body: JSON.stringify({ quarantine: shouldQuarantine })
      });
      await this.refreshData();
    } else {
      const dev = this.devices.find(d => d.id === deviceId);
      if (dev) {
        dev.is_quarantined = shouldQuarantine;
        dev.status = shouldQuarantine ? "CRITICAL" : "ONLINE";
      }
      this.topoViz.setData(this.devices, this.topology.links);
      this.renderDevicesTable();
      this.updateKpiCounters();
    }
  }

  async toggleSelectedDeviceQuarantine() {
    if (!this.selectedDevice) return;
    const nextState = !this.selectedDevice.is_quarantined;
    await this.quarantineDevice(this.selectedDevice.id, nextState);
    this.selectedDevice.is_quarantined = nextState;
    this.selectedDevice.status = nextState ? "CRITICAL" : "ONLINE";
    this.updateDeviceModalState();
  }

  updateDeviceModalState() {
    if (!this.selectedDevice) return;
    const dev = this.selectedDevice;
    const qStatus = document.getElementById("modal-dev-quarantine-status");
    const qBtn = document.getElementById("btn-toggle-quarantine");
    const statusEl = document.getElementById("modal-dev-status");

    if (statusEl) {
      statusEl.textContent = dev.is_quarantined ? "CRITICAL (QUARANTINED)" : dev.status;
      statusEl.style.color = dev.is_quarantined ? "#ef4444" : (dev.status === "ONLINE" ? "#10b981" : "#f59e0b");
    }

    if (qStatus) {
      qStatus.innerHTML = dev.is_quarantined
        ? `<span style="color:#ef4444; font-weight:700;">● ISOLATED (Host Traffic Dropped)</span>`
        : `<span style="color:#10b981;">● PERMITTED (Routing Active)</span>`;
    }

    if (qBtn) {
      qBtn.textContent = dev.is_quarantined ? "Release Host Quarantine" : "Isolate / Quarantine Host";
      qBtn.className = dev.is_quarantined ? "btn btn-secondary" : "btn btn-danger";
    }
  }

  async openDeviceInspector(deviceId) {
    const dev = this.devices.find(d => d.id === deviceId);
    if (!dev) return;

    this.selectedDevice = dev;
    document.getElementById("modal-dev-hostname").textContent = dev.hostname;
    document.getElementById("modal-dev-ip").textContent = dev.ip || dev.ip_address;
    document.getElementById("modal-dev-tier").textContent = dev.tier;
    document.getElementById("modal-dev-role").textContent = dev.role;
    document.getElementById("modal-dev-vendor").textContent = dev.vendor;

    const probeBox = document.getElementById("modal-probe-results");
    if (probeBox) {
      probeBox.style.display = "none";
      probeBox.innerHTML = "";
    }

    const badge = document.getElementById("modal-telemetry-badge");
    if (badge) {
      badge.textContent = this.isLiveBackend
        ? `⚡ Live Python Socket Probe (Real ICMP / TCP) • ${this.databaseEngine}`
        : "🌐 Static GitHub Pages Mode (Simulated)";
    }

    this.updateDeviceModalState();
    document.getElementById("device-modal").classList.add("active");
  }

  closeDeviceModal() {
    document.getElementById("device-modal").classList.remove("active");
  }

  async probeSelectedDevice() {
    if (!this.selectedDevice) return;
    const probeBtn = document.getElementById("btn-execute-probe");
    const probeBox = document.getElementById("modal-probe-results");
    if (probeBtn) {
      probeBtn.disabled = true;
      probeBtn.innerHTML = `<span>Probing ${this.selectedDevice.hostname}...</span>`;
    }

    if (probeBox) {
      probeBox.style.display = "block";
      probeBox.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px; color: #38bdf8;">
          <span class="pulse-dot"></span>
          <span>Sending ICMP ping probe & testing configured TCP service ports...</span>
        </div>
      `;
    }

    try {
      if (this.isLiveBackend) {
        const res = await fetch(this._apiUrl(`/api/v1/devices/${this.selectedDevice.id}/probe`), {
          method: "POST",
          headers: this._getHeaders()
        });
        const data = await res.json();
        this.renderProbeResults(data);
        await this.refreshData();
      } else {
        setTimeout(() => {
          this.renderProbeResults({
            device_id: this.selectedDevice.id,
            hostname: this.selectedDevice.hostname,
            ip_address: this.selectedDevice.ip || this.selectedDevice.ip_address,
            icmp: {
              reachable: true,
              status: "REACHABLE",
              rtt_ms: parseFloat((1.1 + Math.random() * 0.9).toFixed(2)),
              packet_loss_percent: 0.0,
              diagnosis: "Static Client Demo: Echo request resolved with nominal latency."
            },
            services: (this.selectedDevice.services || []).map(s => ({
              port: s.port,
              name: s.name,
              status: "OPEN",
              is_open: true,
              rtt_ms: parseFloat((1.8 + Math.random() * 1.2).toFixed(2)),
              diagnosis: "SYN-ACK 3-way handshake established successfully."
            }))
          });
        }, 350);
      }
    } catch (err) {
      if (probeBox) {
        probeBox.innerHTML = `<div style="color: #ef4444;">Diagnostic probe failed: ${err.message}</div>`;
      }
    } finally {
      if (probeBtn) {
        probeBtn.disabled = false;
        probeBtn.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px; vertical-align: middle;">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
          Execute Live ICMP & TCP Probe
        `;
      }
    }
  }

  renderProbeResults(data) {
    const probeBox = document.getElementById("modal-probe-results");
    if (!probeBox) return;

    const icmp = data.icmp || {};
    const services = data.services || [];
    const isReachable = icmp.reachable;
    const statusColor = isReachable ? "#10b981" : "#ef4444";

    let servicesHtml = "";
    if (services.length > 0) {
      servicesHtml = `
        <div style="margin-top: 10px;">
          <strong style="color: #94a3b8; font-size: 0.72rem; text-transform: uppercase;">TCP Service Probes (Socket Connect):</strong>
          <table style="width: 100%; margin-top: 4px; border-collapse: collapse; font-size: 0.72rem;">
            <thead>
              <tr style="color: #64748b; border-bottom: 1px solid #1e293b; text-align: left;">
                <th style="padding: 3px 6px;">Port</th>
                <th style="padding: 3px 6px;">Service</th>
                <th style="padding: 3px 6px;">State</th>
                <th style="padding: 3px 6px;">RTT</th>
                <th style="padding: 3px 6px;">Diagnosis</th>
              </tr>
            </thead>
            <tbody>
              ${services.map(s => `
                <tr style="border-bottom: 1px solid rgba(30, 41, 59, 0.4);">
                  <td style="padding: 3px 6px; font-family: monospace; color: #f8fafc;">${s.port}</td>
                  <td style="padding: 3px 6px; color: #94a3b8;">${s.name}</td>
                  <td style="padding: 3px 6px; color: ${s.is_open ? '#10b981' : '#ef4444'}; font-weight: 600;">${s.status}</td>
                  <td style="padding: 3px 6px; font-family: monospace;">${s.rtt_ms > 0 ? s.rtt_ms + ' ms' : '--'}</td>
                  <td style="padding: 3px 6px; color: #64748b;">${s.diagnosis || ''}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    }

    probeBox.innerHTML = `
      <div style="border-left: 3px solid ${statusColor}; padding-left: 8px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div style="font-weight: 700; color: #f8fafc;">
            Host ICMP Ping Result:
          </div>
          <span style="font-size: 0.7rem; font-weight: 700; padding: 2px 6px; border-radius: 4px; background: ${isReachable ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)'}; color: ${statusColor};">
            ${icmp.status || (isReachable ? 'REACHABLE' : 'UNREACHABLE')}
          </span>
        </div>
        <div style="display: flex; gap: 16px; margin-top: 6px; font-size: 0.72rem; color: #94a3b8;">
          <div>Latency RTT: <strong style="color: #f8fafc; font-family: monospace;">${icmp.rtt_ms !== undefined ? icmp.rtt_ms + ' ms' : '--'}</strong></div>
          <div>Packet Loss: <strong style="color: ${icmp.packet_loss_percent > 0 ? '#ef4444' : '#10b981'}; font-family: monospace;">${icmp.packet_loss_percent !== undefined ? icmp.packet_loss_percent + '%' : '0.0%'}</strong></div>
        </div>
        <div style="margin-top: 4px; font-size: 0.7rem; color: #64748b;">
          ${icmp.diagnosis || ''}
        </div>
      </div>
      ${servicesHtml}
      <div style="margin-top: 8px; font-size: 0.65rem; color: #475569; text-align: right;">
        Sample recorded to telemetry database • Timestamp: ${new Date().toLocaleTimeString()}
      </div>
    `;
  }

  // Device CRUD Operations
  openAddDeviceModal() {
    this.deviceFormMode = "create";
    document.getElementById("device-form-title").textContent = "Add Infrastructure Device";
    document.getElementById("form-dev-id").disabled = false;
    document.getElementById("form-dev-id").value = "";
    document.getElementById("form-dev-hostname").value = "";
    document.getElementById("form-dev-ip").value = "";
    document.getElementById("form-dev-mac").value = "";
    document.getElementById("form-dev-tier").value = "ACCESS";
    document.getElementById("form-dev-role").value = "Host Workstation";
    document.getElementById("form-dev-vendor").value = "Ubuntu Linux 24.04";
    document.getElementById("form-dev-services").value = "22:SSH";
    const errBox = document.getElementById("device-form-error");
    if (errBox) errBox.style.display = "none";
    document.getElementById("device-form-modal").classList.add("active");
  }

  openEditSelectedDevice() {
    if (!this.selectedDevice) return;
    this.closeDeviceModal();
    this.deviceFormMode = "edit";
    document.getElementById("device-form-title").textContent = `Edit Device: ${this.selectedDevice.id}`;
    const idInput = document.getElementById("form-dev-id");
    idInput.value = this.selectedDevice.id;
    idInput.disabled = true;

    document.getElementById("form-dev-hostname").value = this.selectedDevice.hostname || "";
    document.getElementById("form-dev-ip").value = this.selectedDevice.ip || this.selectedDevice.ip_address || "";
    document.getElementById("form-dev-mac").value = this.selectedDevice.mac_address || "";
    document.getElementById("form-dev-tier").value = this.selectedDevice.tier || "ACCESS";
    document.getElementById("form-dev-role").value = this.selectedDevice.role || "";
    document.getElementById("form-dev-vendor").value = this.selectedDevice.vendor || "";

    const services = (this.selectedDevice.services || []).map(s => `${s.port}:${s.name}`).join(", ");
    document.getElementById("form-dev-services").value = services;

    const errBox = document.getElementById("device-form-error");
    if (errBox) errBox.style.display = "none";
    document.getElementById("device-form-modal").classList.add("active");
  }

  closeDeviceFormModal() {
    document.getElementById("device-form-modal").classList.remove("active");
  }

  async handleDeviceFormSubmit(event) {
    event.preventDefault();
    const devId = document.getElementById("form-dev-id").value.trim();
    const hostname = document.getElementById("form-dev-hostname").value.trim();
    const ip = document.getElementById("form-dev-ip").value.trim();
    const mac = document.getElementById("form-dev-mac").value.trim();
    const tier = document.getElementById("form-dev-tier").value;
    const role = document.getElementById("form-dev-role").value.trim();
    const vendor = document.getElementById("form-dev-vendor").value.trim();
    const rawServices = document.getElementById("form-dev-services").value.trim();

    // Parse services
    const services = [];
    if (rawServices) {
      rawServices.split(",").forEach(item => {
        const parts = item.trim().split(":");
        if (parts.length >= 2) {
          const port = parseInt(parts[0], 10);
          if (port > 0) services.push({ port, name: parts[1].trim() });
        }
      });
    }

    const payload = {
      id: devId,
      hostname,
      ip_address: ip,
      mac_address: mac || "00:00:00:00:00:00",
      tier,
      role: role || "Host",
      vendor: vendor || "Generic",
      services
    };

    const errBox = document.getElementById("device-form-error");

    if (this.isLiveBackend) {
      try {
        const endpoint = this.deviceFormMode === "create" ? "/api/v1/devices" : `/api/v1/devices/${devId}`;
        const method = this.deviceFormMode === "create" ? "POST" : "PUT";
        const res = await fetch(this._apiUrl(endpoint), {
          method,
          headers: this._getHeaders(),
          body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (!res.ok) {
          if (errBox) {
            errBox.textContent = data.error || "Failed to save device.";
            errBox.style.display = "block";
          }
          return;
        }

        this.closeDeviceFormModal();
        await this.refreshData();
      } catch (err) {
        if (errBox) {
          errBox.textContent = `Network error: ${err.message}`;
          errBox.style.display = "block";
        }
      }
    } else {
      // Local fallback simulation
      if (this.deviceFormMode === "create") {
        payload.ip = ip;
        payload.status = "ONLINE";
        payload.is_quarantined = false;
        payload.services_count = services.length;
        this.devices.push(payload);
      } else {
        const dev = this.devices.find(d => d.id === devId);
        if (dev) {
          Object.assign(dev, payload);
          dev.ip = ip;
          dev.services_count = services.length;
        }
      }
      this.closeDeviceFormModal();
      this.renderDevicesTable();
      this.updateKpiCounters();
      this.topoViz.setData(this.devices, this.topology.links);
    }
  }

  async deleteSelectedDevice() {
    if (!this.selectedDevice) return;
    const devId = this.selectedDevice.id;
    const confirmed = confirm(`Are you sure you want to delete '${devId}' (${this.selectedDevice.hostname})? This will cascade across links and telemetry.`);
    if (!confirmed) return;

    if (this.isLiveBackend) {
      try {
        const res = await fetch(this._apiUrl(`/api/v1/devices/${devId}`), {
          method: "DELETE",
          headers: this._getHeaders()
        });
        if (res.ok) {
          this.closeDeviceModal();
          await this.refreshData();
        } else {
          const data = await res.json();
          alert(`Error deleting device: ${data.error}`);
        }
      } catch (err) {
        alert(`Network error: ${err.message}`);
      }
    } else {
      this.devices = this.devices.filter(d => d.id !== devId);
      this.closeDeviceModal();
      this.renderDevicesTable();
      this.updateKpiCounters();
      this.topoViz.setData(this.devices, this.topology.links);
    }
  }

  // Audit Logs Modal
  async openAuditModal() {
    const tbody = document.getElementById("audit-table-body");
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 16px; color:#64748b;">Loading compliance audit logs...</td></tr>`;
    document.getElementById("audit-modal").classList.add("active");

    try {
      let logs = [];
      if (this.isLiveBackend) {
        const res = await fetch(this._apiUrl("/api/v1/audit?limit=30"), { headers: this._getHeaders() });
        const data = await res.json();
        logs = data.logs || [];
      } else {
        logs = [
          { timestamp: new Date().toISOString(), operator: "SOC-Analyst", action: "QUARANTINE_ENFORCE", target_id: "fw-edge-01", details: "Administrative isolation simulation" },
          { timestamp: new Date(Date.now() - 60000).toISOString(), operator: "SOC-Operator", action: "ALERT_ACKNOWLEDGE", target_id: "ALT-SEC-8142", details: "Reviewed by operator" }
        ];
      }

      if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 20px; color:#64748b;">No audit records found.</td></tr>`;
        return;
      }

      tbody.innerHTML = logs.map(l => `
        <tr>
          <td style="font-family: monospace; font-size: 0.72rem; color: #94a3b8;">${l.timestamp.slice(0, 19).replace('T', ' ')}</td>
          <td><span style="font-weight: 600; color: #f8fafc;">${l.operator}</span></td>
          <td><span class="badge-tag">${l.action}</span></td>
          <td style="font-family: monospace; color: #38bdf8;">${l.target_id}</td>
          <td style="font-size: 0.72rem; color: #94a3b8;">${l.details || ''}</td>
        </tr>
      `).join('');
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:#ef4444;">Error fetching audit logs: ${err.message}</td></tr>`;
    }
  }

  closeAuditModal() {
    document.getElementById("audit-modal").classList.remove("active");
  }

  // Settings Modal
  openSettingsModal() {
    document.getElementById("settings-api-url").value = this.apiBase;
    document.getElementById("settings-api-key").value = this.apiKey;
    const statusEl = document.getElementById("settings-db-status");
    if (statusEl) {
      statusEl.textContent = this.isLiveBackend ? `CONNECTED (${this.databaseEngine})` : "OFFLINE / DEMO";
      statusEl.className = this.isLiveBackend ? "badge-tag" : "badge-tag";
      statusEl.style.color = this.isLiveBackend ? "#10b981" : "#f59e0b";
    }
    document.getElementById("settings-modal").classList.add("active");
  }

  closeSettingsModal() {
    document.getElementById("settings-modal").classList.remove("active");
  }

  async testApiConnection() {
    const testUrl = document.getElementById("settings-api-url").value.trim().replace(/\/+$/, "");
    const testKey = document.getElementById("settings-api-key").value.trim();
    const feedback = document.getElementById("settings-probe-feedback");
    const statusEl = document.getElementById("settings-db-status");

    if (feedback) feedback.innerHTML = `<span style="color:#38bdf8;">Testing connection to ${testUrl || 'relative host'}...</span>`;

    try {
      const headers = { "Content-Type": "application/json" };
      if (testKey) headers["X-API-Key"] = testKey;

      const res = await fetch(`${testUrl}/api/v1/ready`, { headers });
      const data = await res.json();

      if (res.ok && data.status === "READY") {
        if (statusEl) {
          statusEl.textContent = `READY (${data.database_engine})`;
          statusEl.style.color = "#10b981";
        }
        if (feedback) {
          feedback.innerHTML = `<span style="color:#10b981;">✓ Connected! Database: <strong>${data.database_engine}</strong>, Registered Devices: <strong>${data.devices_registered}</strong>.</span>`;
        }
      } else {
        if (statusEl) {
          statusEl.textContent = "DEGRADED / NOT READY";
          statusEl.style.color = "#ef4444";
        }
        if (feedback) {
          feedback.innerHTML = `<span style="color:#ef4444;">Error: ${data.error || 'Server returned non-ready status.'}</span>`;
        }
      }
    } catch (err) {
      if (statusEl) {
        statusEl.textContent = "FAILED";
        statusEl.style.color = "#ef4444";
      }
      if (feedback) {
        feedback.innerHTML = `<span style="color:#ef4444;">Connection failed: ${err.message}. Ensure CORS is enabled and URL is accessible.</span>`;
      }
    }
  }

  async saveApiSettings() {
    const newUrl = document.getElementById("settings-api-url").value.trim().replace(/\/+$/, "");
    const newKey = document.getElementById("settings-api-key").value.trim();

    this.apiBase = newUrl;
    this.apiKey = newKey;

    if (typeof localStorage !== "undefined") {
      if (newUrl) {
        localStorage.setItem("netsentinel_api_base", newUrl);
      } else {
        localStorage.removeItem("netsentinel_api_base");
      }

      if (newKey) {
        localStorage.setItem("netsentinel_api_key", newKey);
      } else {
        localStorage.removeItem("netsentinel_api_key");
      }
    }

    this.closeSettingsModal();
    await this.checkBackendAndLoad();
  }

  openAttackModal() {
    document.getElementById("attack-modal").classList.add("active");
  }

  closeAttackModal() {
    document.getElementById("attack-modal").classList.remove("active");
  }

  async triggerAttackScenario(scenario) {
    this.closeAttackModal();
    
    if (this.isLiveBackend) {
      await fetch(this._apiUrl("/api/v1/simulation/attack"), {
        method: "POST",
        headers: this._getHeaders(),
        body: JSON.stringify({ attack_type: scenario })
      });
      await this.refreshData();
    } else {
      if (scenario === 'ddos') {
        const target = this.devices.find(d => d.id === 'fw-edge-01');
        if (target) target.status = 'CRITICAL';
        this.alerts.unshift({
          id: `ALT-DDOS-${Math.floor(Math.random() * 9000 + 1000)}`,
          device_id: 'fw-edge-01',
          severity: 'CRITICAL',
          rule_id: 'SEC-R003',
          mitre_id: 'T1498.001',
          title: 'Volumetric SYN Flood DDoS Assault',
          message: 'Inbound traffic spiked to 894 Mbps / 48,250 PPS on PA-5450 perimeter interface.',
          status: 'NEW',
          created_at: new Date().toISOString()
        });
        this.bwChart.pushValue(894);
        this.lossChart.pushValue(7.8);
      } else if (scenario === 'brute_force') {
        const target = this.devices.find(d => d.id === 'db-prod-pri');
        if (target) target.status = 'CRITICAL';
        this.alerts.unshift({
          id: `ALT-BF-${Math.floor(Math.random() * 9000 + 1000)}`,
          device_id: 'db-prod-pri',
          severity: 'CRITICAL',
          rule_id: 'SEC-R001',
          mitre_id: 'T1110.001',
          title: 'SSH Credential Brute-Force Attack',
          message: '8 consecutive failed SSH authentication attempts from 185.220.101.42.',
          status: 'NEW',
          created_at: new Date().toISOString()
        });
      } else if (scenario === 'port_scan') {
        const target = this.devices.find(d => d.id === 'srv-proxy-01');
        if (target) target.status = 'DEGRADED';
        this.alerts.unshift({
          id: `ALT-SCAN-${Math.floor(Math.random() * 9000 + 1000)}`,
          device_id: 'srv-proxy-01',
          severity: 'HIGH',
          rule_id: 'SEC-R002',
          mitre_id: 'T1046',
          title: 'Horizontal Port Sweep In Progress',
          message: '18 distinct ports probed in 4 seconds from external IP 194.26.29.112.',
          status: 'NEW',
          created_at: new Date().toISOString()
        });
      } else if (scenario === 'link_flap') {
        const target = this.devices.find(d => d.id === 'sw-core-a');
        if (target) target.status = 'DEGRADED';
        this.alerts.unshift({
          id: `ALT-NET-${Math.floor(Math.random() * 9000 + 1000)}`,
          device_id: 'sw-core-a',
          severity: 'MEDIUM',
          rule_id: 'NMS-NET-01',
          mitre_id: 'NMS-STAB',
          title: 'Core Backbone Fiber Link Flapping',
          message: 'Packet drop burst of 12.5% and RTT latency spiked to 215ms.',
          status: 'NEW',
          created_at: new Date().toISOString()
        });
        this.lossChart.pushValue(12.5);
      } else if (scenario === 'rogue_mac') {
        const target = this.devices.find(d => d.id === 'sw-core-a');
        if (target) target.status = 'CRITICAL';
        this.alerts.unshift({
          id: `ALT-MAC-${Math.floor(Math.random() * 9000 + 1000)}`,
          device_id: 'sw-core-a',
          severity: 'CRITICAL',
          rule_id: 'SEC-R004',
          mitre_id: 'T1200',
          title: 'Unauthorized Rogue MAC Detected on Core VLAN',
          message: 'MAC 00:0C:29:DE:AD:01 is not registered in enterprise whitelist. Switchport auto-quarantined.',
          status: 'NEW',
          created_at: new Date().toISOString()
        });
      }

      this.topoViz.setData(this.devices, this.topology.links);
      this.renderAlertsTable();
      this.renderDevicesTable();
      this.updateKpiCounters();
    }
  }

  _bindUiEvents() {
    document.getElementById("btn-open-attack-modal")?.addEventListener("click", () => this.openAttackModal());
    document.getElementById("btn-close-attack-modal")?.addEventListener("click", () => this.closeAttackModal());
    document.getElementById("btn-close-device-modal")?.addEventListener("click", () => this.closeDeviceModal());

    // Device Form Modal
    document.getElementById("btn-open-add-device")?.addEventListener("click", () => this.openAddDeviceModal());
    document.getElementById("btn-close-device-form-modal")?.addEventListener("click", () => this.closeDeviceFormModal());

    // Audit Logs Modal
    document.getElementById("btn-open-audit-modal")?.addEventListener("click", () => this.openAuditModal());
    document.getElementById("btn-close-audit-modal")?.addEventListener("click", () => this.closeAuditModal());

    // Settings Modal
    document.getElementById("btn-open-settings-modal")?.addEventListener("click", () => this.openSettingsModal());
    document.getElementById("btn-close-settings-modal")?.addEventListener("click", () => this.closeSettingsModal());

    // Search and Filters
    document.getElementById("device-search-input")?.addEventListener("input", (e) => {
      this.searchTerm = e.target.value.trim();
      this.renderDevicesTable();
    });

    document.getElementById("device-tier-filter")?.addEventListener("change", (e) => {
      this.tierFilter = e.target.value;
      this.renderDevicesTable();
    });

    document.getElementById("device-status-filter")?.addEventListener("change", (e) => {
      this.statusFilter = e.target.value;
      this.renderDevicesTable();
    });

    document.getElementById("btn-reset-filters")?.addEventListener("click", () => {
      this.searchTerm = "";
      this.tierFilter = "";
      this.statusFilter = "";
      const sInput = document.getElementById("device-search-input");
      const tSelect = document.getElementById("device-tier-filter");
      const stSelect = document.getElementById("device-status-filter");
      if (sInput) sInput.value = "";
      if (tSelect) tSelect.value = "";
      if (stSelect) stSelect.value = "";
      this.renderDevicesTable();
    });
  }
}

// Global bootstrap
window.addEventListener("DOMContentLoaded", () => {
  window.socApp = new SocApplication();
});
