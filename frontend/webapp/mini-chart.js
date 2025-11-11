// Minimal offline Chart fallback
// Provides a tiny subset of Chart.js API used in this app.
// Only supports: types 'line' and 'bar' with a single dataset.
// If a real Chart.js is present, do nothing.
(function(){
  if (window.Chart) return; // use CDN if available

  function toColor(v, fallback) {
    if (typeof v === 'string' && v.trim()) return v;
    return fallback || '#4e9eff';
  }

  function setupCanvas(canvas) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const cssW = canvas.clientWidth || 400;
    const cssH = canvas.clientHeight || 200;
    canvas.width = Math.round(cssW * dpr);
    canvas.height = Math.round(cssH * dpr);
    ctx.scale(dpr, dpr);
    return ctx;
  }

  function scaleFn(values, height, padding) {
    const max = Math.max(1, Math.max.apply(null, values.map(v => Number(v)||0)));
    const min = Math.min(0, Math.min.apply(null, values.map(v => Number(v)||0)));
    const span = max - min || 1;
    const usable = Math.max(1, height - padding*2);
    return {
      y(v){ return height - padding - ((v - min) / span) * usable; },
      min, max
    };
  }

  function drawAxes(ctx, w, h, padding) {
    ctx.strokeStyle = 'rgba(159,176,210,0.25)';
    ctx.lineWidth = 1;
    // x axis
    ctx.beginPath();
    ctx.moveTo(padding, h - padding);
    ctx.lineTo(w - padding, h - padding);
    ctx.stroke();
    // y axis
    ctx.beginPath();
    ctx.moveTo(padding, h - padding);
    ctx.lineTo(padding, padding);
    ctx.stroke();
  }

  function drawLine(ctx, labels, data, color, w, h, padding) {
    const n = Math.max(1, data.length);
    const step = (w - padding*2) / (n - 1 || 1);
    const scale = scaleFn(data, h, padding);
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    data.forEach((v, i) => {
      const x = padding + step * i;
      const y = scale.y(Number(v)||0);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();
  }

  function drawBars(ctx, labels, data, color, w, h, padding) {
    const n = Math.max(1, data.length);
    const totalW = (w - padding*2);
    const barW = Math.max(2, totalW / n * 0.6);
    const gap = (totalW / n) - barW;
    const scale = scaleFn(data, h, padding);
    ctx.fillStyle = color;
    data.forEach((v, i) => {
      const x = padding + i * (barW + gap) + gap/2;
      const y = scale.y(Number(v)||0);
      const y0 = scale.y(0);
      const top = Math.min(y, y0);
      const height = Math.abs(y0 - y);
      ctx.fillRect(x, top, barW, Math.max(1, height));
    });
  }

  function TinyChart(canvas, config) {
    const ctx = setupCanvas(canvas);
    const w = canvas.clientWidth || 400;
    const h = canvas.clientHeight || 200;
    const padding = 28;
    const labels = (config.data && config.data.labels) || [];
    const ds = (config.data && config.data.datasets && config.data.datasets[0]) || { data: [] };
    const data = ds.data || [];
    drawAxes(ctx, w, h, padding);
    if ((config.type||'').toLowerCase() === 'bar') {
      drawBars(ctx, labels, data, toColor(ds.backgroundColor, '#4e9eff'), w, h, padding);
    } else {
      drawLine(ctx, labels, data, toColor(ds.borderColor, '#4e9eff'), w, h, padding);
    }
  }

  // expose compatible API surface
  window.Chart = TinyChart;
})();

