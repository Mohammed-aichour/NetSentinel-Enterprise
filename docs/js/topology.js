/**
 * NetSentinel Enterprise - Interactive Canvas Network Topology Engine
 * High-performance SOC visualizer with animated traffic particles and tier layouts.
 */

class NetworkTopologyVisualizer {
  constructor(canvasId, options = {}) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    
    this.nodes = [];
    this.links = [];
    this.particles = [];
    this.selectedNode = null;
    this.hoveredNode = null;
    this.onNodeSelect = options.onNodeSelect || (() => {});
    
    this.isDragging = false;
    this.draggedNode = null;
    this.dragOffset = { x: 0, y: 0 };

    this._initCanvasSize();
    this._bindEvents();
    this._startAnimationLoop();
  }

  _initCanvasSize() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.canvas.width = rect.width * window.devicePixelRatio || 900;
    this.canvas.height = rect.height * window.devicePixelRatio || 480;
    this.width = rect.width;
    this.height = rect.height;
    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }

  setData(nodes, links) {
    this.nodes = this._computeTierCoordinates(nodes);
    this.links = links;
    this._initParticles();
  }

  _computeTierCoordinates(rawNodes) {
    const tierRanks = {
      'EDGE': 0,
      'CORE': 1,
      'DMZ': 2,
      'SERVICES': 3,
      'DATABASE': 4,
      'ACCESS': 5
    };

    const tiers = { 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] };
    rawNodes.forEach(node => {
      const rank = tierRanks[node.tier] ?? 3;
      tiers[rank].push(node);
    });

    const tierCount = 6;
    const paddingX = 80;
    const paddingY = 60;
    const colWidth = (this.width - paddingX * 2) / (tierCount - 1);

    const computed = [];
    Object.keys(tiers).forEach(tierKey => {
      const rank = parseInt(tierKey, 10);
      const group = tiers[rank];
      const count = group.length;
      const x = paddingX + rank * colWidth;

      group.forEach((node, idx) => {
        const spacingY = (this.height - paddingY * 2) / (count + 1);
        const y = paddingY + (idx + 1) * spacingY;
        computed.push({
          ...node,
          x,
          y,
          radius: node.tier === 'CORE' ? 18 : 14
        });
      });
    });

    return computed;
  }

  _initParticles() {
    this.particles = [];
    for (let i = 0; i < 24; i++) {
      if (this.links.length === 0) break;
      const link = this.links[Math.floor(Math.random() * this.links.length)];
      this.particles.push({
        sourceId: link.source_id,
        targetId: link.target_id,
        progress: Math.random(),
        speed: 0.004 + Math.random() * 0.006,
        color: link.status === 'DEGRADED' ? '#f59e0b' : '#38bdf8'
      });
    }
  }

  _bindEvents() {
    window.addEventListener('resize', () => {
      this._initCanvasSize();
      if (this.nodes.length) {
        this.nodes = this._computeTierCoordinates(this.nodes);
      }
    });

    this.canvas.addEventListener('mousemove', (e) => this._onMouseMove(e));
    this.canvas.addEventListener('mousedown', (e) => this._onMouseDown(e));
    window.addEventListener('mouseup', () => this._onMouseUp());
  }

  _getMousePos(e) {
    const rect = this.canvas.getBoundingClientRect();
    return {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    };
  }

  _onMouseMove(e) {
    const pos = this._getMousePos(e);
    if (this.isDragging && this.draggedNode) {
      this.draggedNode.x = pos.x - this.dragOffset.x;
      this.draggedNode.y = pos.y - this.dragOffset.y;
      return;
    }

    const hit = this.nodes.find(n => {
      const dx = n.x - pos.x;
      const dy = n.y - pos.y;
      return Math.sqrt(dx * dx + dy * dy) <= n.radius + 4;
    });

    this.hoveredNode = hit || null;
    this.canvas.style.cursor = hit ? 'pointer' : 'default';
  }

  _onMouseDown(e) {
    const pos = this._getMousePos(e);
    const hit = this.nodes.find(n => {
      const dx = n.x - pos.x;
      const dy = n.y - pos.y;
      return Math.sqrt(dx * dx + dy * dy) <= n.radius + 4;
    });

    if (hit) {
      this.isDragging = true;
      this.draggedNode = hit;
      this.selectedNode = hit;
      this.dragOffset = { x: pos.x - hit.x, y: pos.y - hit.y };
      this.onNodeSelect(hit);
    } else {
      this.selectedNode = null;
    }
  }

  _onMouseUp() {
    this.isDragging = false;
    this.draggedNode = null;
  }

  _startAnimationLoop() {
    const render = () => {
      this._draw();
      requestAnimationFrame(render);
    };
    requestAnimationFrame(render);
  }

  _draw() {
    this.ctx.clearRect(0, 0, this.width, this.height);

    // Draw background subtle grid
    this.ctx.strokeStyle = 'rgba(30, 41, 59, 0.25)';
    this.ctx.lineWidth = 1;
    for (let x = 0; x < this.width; x += 40) {
      this.ctx.beginPath();
      this.ctx.moveTo(x, 0);
      this.ctx.lineTo(x, this.height);
      this.ctx.stroke();
    }
    for (let y = 0; y < this.height; y += 40) {
      this.ctx.beginPath();
      this.ctx.moveTo(0, y);
      this.ctx.lineTo(this.width, y);
      this.ctx.stroke();
    }

    // Draw Tier Labels
    const tierLabels = ['EDGE', 'CORE', 'DMZ', 'SERVICES', 'DATABASE', 'ACCESS'];
    const paddingX = 80;
    const colWidth = (this.width - paddingX * 2) / 5;
    this.ctx.font = '10px -apple-system, sans-serif';
    this.ctx.fillStyle = '#64748b';
    this.ctx.textAlign = 'center';
    tierLabels.forEach((label, i) => {
      this.ctx.fillText(label, paddingX + i * colWidth, 25);
    });

    const nodeMap = new Map(this.nodes.map(n => [n.id, n]));

    // Draw Links
    this.links.forEach(link => {
      const src = nodeMap.get(link.source_id);
      const tgt = nodeMap.get(link.target_id);
      if (!src || !tgt) return;

      this.ctx.beginPath();
      this.ctx.moveTo(src.x, src.y);
      this.ctx.lineTo(tgt.x, tgt.y);

      if (link.status === 'DEGRADED') {
        this.ctx.strokeStyle = 'rgba(245, 158, 11, 0.4)';
        this.ctx.lineWidth = 2;
      } else if (src.status === 'CRITICAL' || tgt.status === 'CRITICAL') {
        this.ctx.strokeStyle = 'rgba(239, 68, 68, 0.5)';
        this.ctx.lineWidth = 2.5;
      } else {
        this.ctx.strokeStyle = 'rgba(56, 189, 248, 0.18)';
        this.ctx.lineWidth = 1.5;
      }
      this.ctx.stroke();
    });

    // Draw Traffic Particles
    this.particles.forEach(p => {
      const src = nodeMap.get(p.sourceId);
      const tgt = nodeMap.get(p.targetId);
      if (!src || !tgt) return;

      p.progress += p.speed;
      if (p.progress >= 1.0) p.progress = 0;

      const px = src.x + (tgt.x - src.x) * p.progress;
      const py = src.y + (tgt.y - src.y) * p.progress;

      this.ctx.beginPath();
      this.ctx.arc(px, py, 2.5, 0, Math.PI * 2);
      this.ctx.fillStyle = p.color;
      this.ctx.fill();
    });

    // Draw Nodes
    const nowTime = Date.now() / 1000;
    this.nodes.forEach(node => {
      const isSelected = this.selectedNode && this.selectedNode.id === node.id;
      const isHovered = this.hoveredNode && this.hoveredNode.id === node.id;

      let fillColor = '#10b981'; // Green (Online)
      let glowColor = 'rgba(16, 185, 129, 0.4)';

      if (node.is_quarantined) {
        fillColor = '#64748b'; // Gray
        glowColor = 'rgba(100, 116, 139, 0.2)';
      } else if (node.status === 'CRITICAL') {
        fillColor = '#ef4444'; // Red
        glowColor = 'rgba(239, 68, 68, 0.7)';
      } else if (node.status === 'DEGRADED') {
        fillColor = '#f59e0b'; // Amber
        glowColor = 'rgba(245, 158, 11, 0.5)';
      }

      // Outer Glow Pulse for Critical or Selected Nodes
      if (node.status === 'CRITICAL' || isSelected) {
        const pulse = (Math.sin(nowTime * 5) + 1) / 2;
        this.ctx.beginPath();
        this.ctx.arc(node.x, node.y, node.radius + 6 + pulse * 4, 0, Math.PI * 2);
        this.ctx.fillStyle = glowColor;
        this.ctx.fill();
      }

      // Node Body
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = '#111726';
      this.ctx.fill();
      this.ctx.lineWidth = isSelected ? 3 : 2;
      this.ctx.strokeStyle = fillColor;
      this.ctx.stroke();

      // Inner Core Dot
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, 4, 0, Math.PI * 2);
      this.ctx.fillStyle = fillColor;
      this.ctx.fill();

      // Hostname Label
      this.ctx.font = '10px -apple-system, sans-serif';
      this.ctx.fillStyle = isSelected ? '#38bdf8' : '#e2e8f0';
      this.ctx.textAlign = 'center';
      this.ctx.fillText(node.hostname.split('.')[0], node.x, node.y + node.radius + 14);

      // Tooltip on Hover
      if (isHovered && !this.isDragging) {
        this._drawTooltip(node);
      }
    });
  }

  _drawTooltip(node) {
    const text = `${node.hostname} (${node.ip})`;
    const sub = `${node.role} • ${node.status}`;
    this.ctx.font = '11px monospace';
    const width = Math.max(this.ctx.measureText(text).width, this.ctx.measureText(sub).width) + 20;
    const height = 42;
    const tx = Math.min(Math.max(node.x - width / 2, 10), this.width - width - 10);
    const ty = Math.max(node.y - height - 15, 10);

    this.ctx.fillStyle = 'rgba(17, 23, 38, 0.95)';
    this.ctx.strokeStyle = '#38bdf8';
    this.ctx.lineWidth = 1;
    this.ctx.fillRect(tx, ty, width, height);
    this.ctx.strokeRect(tx, ty, width, height);

    this.ctx.textAlign = 'left';
    this.ctx.fillStyle = '#f8fafc';
    this.ctx.fillText(text, tx + 10, ty + 16);
    this.ctx.fillStyle = '#94a3b8';
    this.ctx.font = '10px sans-serif';
    this.ctx.fillText(sub, tx + 10, ty + 32);
  }
}
