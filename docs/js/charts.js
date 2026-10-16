/**
 * NetSentinel Enterprise - High-Performance Real-Time Canvas Charts
 * Lightweight, zero-dependency streaming area charts with glow shaders.
 */

class RealtimeStreamChart {
  constructor(canvasId, options = {}) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    
    this.label = options.label || 'Metric';
    this.unit = options.unit || '';
    this.lineColor = options.lineColor || '#38bdf8';
    this.fillColor = options.fillColor || 'rgba(56, 189, 248, 0.15)';
    this.maxPoints = options.maxPoints || 30;
    this.fixedMax = options.fixedMax || null;

    this.data = [];
    this._initCanvasSize();
  }

  _initCanvasSize() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.canvas.width = rect.width * window.devicePixelRatio || 400;
    this.canvas.height = rect.height * window.devicePixelRatio || 140;
    this.width = rect.width;
    this.height = rect.height;
    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }

  pushValue(val) {
    this.data.push(val);
    if (this.data.length > this.maxPoints) {
      this.data.shift();
    }
    this.render();
  }

  render() {
    if (!this.ctx || this.data.length < 2) return;
    this.ctx.clearRect(0, 0, this.width, this.height);

    const paddingX = 10;
    const paddingY = 16;
    const drawW = this.width - paddingX * 2;
    const drawH = this.height - paddingY * 2;

    const maxVal = this.fixedMax || Math.max(...this.data, 10) * 1.15;
    const minVal = 0;

    const stepX = drawW / (this.maxPoints - 1);
    const startOffset = (this.maxPoints - this.data.length) * stepX;

    // Draw subtle grid lines
    this.ctx.strokeStyle = 'rgba(30, 41, 59, 0.4)';
    this.ctx.lineWidth = 1;
    this.ctx.beginPath();
    this.ctx.moveTo(paddingX, paddingY);
    this.ctx.lineTo(this.width - paddingX, paddingY);
    this.ctx.moveTo(paddingX, this.height - paddingY);
    this.ctx.lineTo(this.width - paddingX, this.height - paddingY);
    this.ctx.stroke();

    // Build Path
    this.ctx.beginPath();
    const points = [];
    this.data.forEach((val, i) => {
      const x = paddingX + startOffset + i * stepX;
      const normalized = (val - minVal) / (maxVal - minVal);
      const y = (this.height - paddingY) - normalized * drawH;
      points.push({ x, y });
      if (i === 0) {
        this.ctx.moveTo(x, y);
      } else {
        this.ctx.lineTo(x, y);
      }
    });

    // Draw Line
    this.ctx.strokeStyle = this.lineColor;
    this.ctx.lineWidth = 2;
    this.ctx.stroke();

    // Area Fill
    if (points.length > 0) {
      this.ctx.lineTo(points[points.length - 1].x, this.height - paddingY);
      this.ctx.lineTo(points[0].x, this.height - paddingY);
      this.ctx.closePath();
      
      const grad = this.ctx.createLinearGradient(0, paddingY, 0, this.height - paddingY);
      grad.addColorStop(0, this.fillColor);
      grad.addColorStop(1, 'rgba(10, 13, 20, 0)');
      this.ctx.fillStyle = grad;
      this.ctx.fill();
    }

    // Latest value indicator badge
    const lastVal = this.data[this.data.length - 1];
    this.ctx.fillStyle = '#f8fafc';
    this.ctx.font = 'bold 11px monospace';
    this.ctx.textAlign = 'right';
    this.ctx.fillText(`${lastVal} ${this.unit}`, this.width - paddingX - 4, paddingY - 4);
  }
}
