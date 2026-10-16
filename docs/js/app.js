/**
 * NetSentinel Enterprise - SOC Dashboard Application Controller
 * Real-time API synchronization, alert operations, attack simulation, and offline demo fallback.
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
    this.topology = null;
    this.alerts = [];
    this.devices = [];
    this.selectedDevice = null;

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

  _initClock() {
    const el = document.getElementById("soc-clock");
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
      const res = await fetch("/api/v1/health");
      if (res.ok) {
        this.isLiveBackend = true;
        document.getElementById("mode-badge").textContent = "API LIVE";
        document.getElementById("mode-badge").classList.add("btn-primary");
      }
    } catch {
      this.isLiveBackend = false;
      document.getElementById("mode-badge").textContent = "STATIC DEMO";
      document.getElementById("mode-badge").classList.add("btn-secondary");
    }

    await this.refreshData();
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
      const res = await fetch("/api/v1/topology");
      const data = await res.json();
      this.topology = data;
      this.topoViz.setData(data.nodes, data.links);
    } catch (e) {
      console.error("Failed to fetch topology:", e);
    }
  }

  async _fetchLiveAlerts() {
    try {
      const res = await fetch("/api/v1/alerts");
      const data = await res.json();
      this.alerts = data.alerts;
      this.renderAlertsTable();
    } catch (e) {
      console.error("Failed to fetch alerts:", e);
    }
  }

  async _fetchLiveDevices() {
    try {
      const res = await fetch("/api/v1/devices");
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
      const res = await fetch("/api/v1/telemetry/live");
      const data = await res.json();
      const s = data.cluster_summary;
      this.bwChart.pushValue(s.aggregate_bandwidth_in_mbps);
      this.latencyChart.pushValue(s.cluster_avg_latency_ms);
      
      const avgLoss = (data.samples.reduce((acc, cur) => acc + cur.packet_loss_percent, 0) / (data.samples.length || 1)).toFixed(2);
      this.lossChart.pushValue(parseFloat(avgLoss));
    } catch (e) {
      console.error("Failed to fetch telemetry:", e);
    }
  }

  _loadFallbackData() {
    this.topology = FALLBACK_ENTERPRISE_TOPOLOGY;
    this.devices = FALLBACK_ENTERPRISE_TOPOLOGY.nodes;
    this.topoViz.setData(this.topology.nodes, this.topology.links);
    
    // Seed initial alerts
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

    // Stream synthetic chart metrics
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
      this._loadFallbackData();
    }
  }

  updateKpiCounters() {
    const total = this.devices.length;
    const online = this.devices.filter(d => d.status === "ONLINE").length;
    const critical = this.devices.filter(d => d.status === "CRITICAL").length;
    const activeThreats = this.alerts.filter(a => a.status === "NEW").length;

    document.getElementById("kpi-total-nodes").textContent = total;
    document.getElementById("kpi-online-nodes").textContent = online;
    document.getElementById("kpi-critical-nodes").textContent = critical;
    document.getElementById("kpi-active-threats").textContent = activeThreats;
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

    tbody.innerHTML = this.devices.map(d => `
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
      await fetch(`/api/v1/alerts/${alertId}/acknowledge`, { method: "POST" });
      await this.refreshData();
    } else {
      const a = this.alerts.find(x => x.id === alertId);
      if (a) a.status = "ACKNOWLEDGED";
      this.renderAlertsTable();
    }
  }

  async resolveAlert(alertId) {
    if (this.isLiveBackend) {
      await fetch(`/api/v1/alerts/${alertId}/resolve`, { method: "POST" });
      await this.refreshData();
    } else {
      this.alerts = this.alerts.filter(x => x.id !== alertId);
      this.renderAlertsTable();
      this.updateKpiCounters();
    }
  }

  async quarantineDevice(deviceId) {
    if (this.isLiveBackend) {
      await fetch(`/api/v1/devices/${deviceId}/quarantine`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ quarantine: true })
      });
      await this.refreshData();
    } else {
      const dev = this.devices.find(d => d.id === deviceId);
      if (dev) {
        dev.is_quarantined = true;
        dev.status = "CRITICAL";
      }
      this.topoViz.setData(this.devices, this.topology.links);
      this.renderDevicesTable();
      this.updateKpiCounters();
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
    document.getElementById("modal-dev-status").textContent = dev.status;

    document.getElementById("device-modal").classList.add("active");
  }

  closeDeviceModal() {
    document.getElementById("device-modal").classList.remove("active");
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
      await fetch("/api/v1/simulation/attack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack_type: scenario })
      });
      await this.refreshData();
    } else {
      // Offline fallback simulation
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
  }
}

// Global bootstrap
window.addEventListener("DOMContentLoaded", () => {
  window.socApp = new SocApplication();
});
