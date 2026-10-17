/* CyberGuard charts — hand-rolled SVG. No CDN, no dependencies, fully offline.
   Every chart animates with transform/opacity only (compositor thread). */
window.CG = window.CG || {};

(function () {
  const NS = "http://www.w3.org/2000/svg";
  const PALETTE = ["#5E9FE8", "#EAC26B", "#72BC8F", "#BF8EDA", "#DE9255", "#DF84A8", "#4FB9C9", "#E97366"];

  function el(tag, attrs = {}, parent) {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (parent) parent.appendChild(n);
    return n;
  }

  function mount(container, svg, legendItems) {
    container.innerHTML = "";
    container.appendChild(svg);
    svg.style.opacity = "0";
    svg.style.transform = "translateY(8px)";
    requestAnimationFrame(() => {
      svg.style.transition = "opacity .6s cubic-bezier(.16,1,.3,1), transform .6s cubic-bezier(.16,1,.3,1)";
      svg.style.opacity = "1";
      svg.style.transform = "none";
    });
    if (legendItems && legendItems.length) {
      const lg = document.createElement("div");
      lg.className = "chart-legend";
      lg.innerHTML = legendItems.map(([label, color]) =>
        `<span class="lg"><span class="lg-swatch" style="background:${color}"></span>${label}</span>`).join("");
      container.appendChild(lg);
    }
  }

  /* Donut — attack type distribution */
  function donut(container, data) {
    const rawTotal = (data || []).reduce((s, d) => s + (d.value || 0), 0);
    const svg = el("svg", { viewBox: "0 0 220 160", role: "img", "aria-label": "Attack type distribution" });
    const cx = 72, cy = 80, r = 52, ir = 32;

    if (rawTotal <= 0) {
      el("circle", { cx, cy, r: (r + ir) / 2, fill: "none", stroke: "rgba(255,255,255,0.08)", "stroke-width": r - ir }, svg);
      const t1 = el("text", { x: cx, y: cy - 4, "text-anchor": "middle", fill: "#EDF1F6", "font-size": "20", "font-weight": "650", "font-family": "ui-monospace, Menlo, Consolas, monospace" }, svg);
      t1.textContent = "0";
      const t2 = el("text", { x: cx, y: cy + 14, "text-anchor": "middle", fill: "rgba(237,241,246,.45)", "font-size": "9" }, svg);
      t2.textContent = "alerts";
      mount(container, svg, [["No active threats", "#64748b"]]);
      return;
    }

    // Sort descending
    const sorted = [...data].sort((a, b) => b.value - a.value);

    // If more than 5 distinct types, group smaller ones into "Other"
    let chartData = sorted;
    if (sorted.length > 5) {
      const topItems = sorted.slice(0, 4);
      const otherItems = sorted.slice(4);
      const otherVal = otherItems.reduce((acc, x) => acc + x.value, 0);
      if (otherVal > 0) {
        chartData = [
          ...topItems,
          { label: `Other Threats (${otherItems.length} types)`, value: otherVal, color: "#64748b" }
        ];
      }
    }

    const total = chartData.reduce((s, d) => s + d.value, 0) || 1;
    let angle = -Math.PI / 2;
    const legend = [];

    chartData.forEach((d, i) => {
      const frac = d.value / total;
      if (frac <= 0) return;
      const a0 = angle, a1 = angle + frac * Math.PI * 2;
      angle = a1;
      const large = a1 - a0 > Math.PI ? 1 : 0;
      const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0);
      const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
      const xi1 = cx + ir * Math.cos(a1), yi1 = cy + ir * Math.sin(a1);
      const xi0 = cx + ir * Math.cos(a0), yi0 = cy + ir * Math.sin(a0);
      const color = d.color || PALETTE[i % PALETTE.length];
      el("path", {
        d: `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1} L ${xi1} ${yi1} A ${ir} ${ir} 0 ${large} 0 ${xi0} ${yi0} Z`,
        fill: color, opacity: "0.92",
      }, svg).appendChild(Object.assign(document.createElementNS(NS, "title"), { textContent: `${d.label}: ${d.value}` }));
      legend.push([`${d.label} (${d.value})`, color]);
    });

    const t1 = el("text", { x: cx, y: cy - 4, "text-anchor": "middle", fill: "#EDF1F6", "font-size": "20", "font-weight": "650", "font-family": "ui-monospace, Menlo, Consolas, monospace" }, svg);
    t1.textContent = rawTotal;
    const t2 = el("text", { x: cx, y: cy + 14, "text-anchor": "middle", fill: "rgba(237,241,246,.45)", "font-size": "9" }, svg);
    t2.textContent = "alerts";
    mount(container, svg, legend);
  }

  /* Area — alert timeline (per-minute counts) */
  function area(container, points) {
    const W = 400, H = 170, padX = 8, padB = 20, padT = 12;
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": "Alert timeline" });
    const max = Math.max(...points.map((p) => p.value), 1);
    const iw = W - padX * 2, ih = H - padT - padB;
    const px = (i) => padX + (i / Math.max(points.length - 1, 1)) * iw;
    const py = (v) => padT + ih - (v / max) * ih;
    for (let g = 0; g <= 3; g++) {
      const y = padT + (g / 3) * ih;
      el("line", { x1: padX, y1: y, x2: W - padX, y2: y, class: "axis-line" }, svg);
    }
    const linePts = points.map((p, i) => `${px(i)},${py(p.value)}`).join(" ");
    el("polygon", {
      points: `${padX},${padT + ih} ${linePts} ${px(points.length - 1)},${padT + ih}`,
      fill: "url(#cgGrad)", opacity: "0.5",
    }, svg);
    const defs = el("defs", {}, svg);
    const grad = el("linearGradient", { id: "cgGrad", x1: "0", y1: "0", x2: "0", y2: "1" }, defs);
    el("stop", { offset: "0%", "stop-color": "#E97366", "stop-opacity": "0.45" }, grad);
    el("stop", { offset: "100%", "stop-color": "#E97366", "stop-opacity": "0" }, grad);
    el("polyline", { points: linePts, fill: "none", stroke: "#E97366", "stroke-width": "2", "stroke-linejoin": "round", "stroke-linecap": "round" }, svg);
    const last = points[points.length - 1];
    el("circle", { cx: px(points.length - 1), cy: py(last.value), r: "3.5", fill: "#E97366" }, svg);
    const lbl = el("text", { x: W - padX, y: py(last.value) - 8, "text-anchor": "end", class: "bar-value", "font-size": "10" }, svg);
    lbl.textContent = `${last.value} now`;
    mount(container, svg);
  }

  /* Histogram — autoencoder anomaly scores vs threshold */
  function histogram(container, values, threshold) {
    const W = 400, H = 170, padX = 8, padB = 20, padT = 12;
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": "Anomaly score distribution" });
    const bins = new Array(18).fill(0);
    const maxV = Math.max(...values, threshold * 1.15, 0.001);
    values.forEach((v) => { bins[Math.min(bins.length - 1, Math.floor((v / maxV) * bins.length))]++; });
    const maxB = Math.max(...bins, 1);
    const iw = W - padX * 2, ih = H - padT - padB;
    const bw = iw / bins.length;
    bins.forEach((b, i) => {
      const h = (b / maxB) * ih;
      const over = ((i + 0.5) / bins.length) * maxV > threshold;
      el("rect", {
        x: padX + i * bw + 1, y: padT + ih - h, width: Math.max(bw - 2, 1), height: Math.max(h, 1),
        rx: "2", fill: over ? "#E97366" : "#4FB9C9", opacity: over ? "0.9" : "0.65",
      }, svg);
    });
    const tx = padX + (threshold / maxV) * iw;
    el("line", { x1: tx, y1: padT, x2: tx, y2: padT + ih, stroke: "#EAC26B", "stroke-width": "1.5", "stroke-dasharray": "4 3" }, svg);
    const lbl = el("text", { x: tx + 4, y: padT + 10, class: "bar-label", "font-size": "9" }, svg);
    lbl.textContent = `threshold (k·σ) = ${threshold}`;
    mount(container, svg, [["benign error", "#4FB9C9"], ["unknown anomaly", "#E97366"], ["threshold", "#EAC26B"]]);
  }

  /* Horizontal bars — XGBoost feature importance */
  function hbars(container, rows) {
    const svg = el("svg", { viewBox: "0 0 400 190", role: "img", "aria-label": "Feature importance" });
    const max = Math.max(...rows.map((r) => r[1]), 0.001);
    const rowH = 22, labelW = 150, barMax = 190;
    rows.slice(0, 8).forEach((r, i) => {
      const y = 8 + i * rowH;
      const w = Math.max((r[1] / max) * barMax, 2);
      const label = el("text", { x: 0, y: y + 12, class: "bar-label", "font-size": "10.5" }, svg);
      label.textContent = r[0].length > 21 ? r[0].slice(0, 20) + "…" : r[0];
      el("rect", { x: labelW, y: y + 3, width: barMax, height: "10", rx: "5", fill: "rgba(255,255,255,.05)" }, svg);
      el("rect", { x: labelW, y: y + 3, width: w, height: "10", rx: "5", fill: "#5E9FE8", opacity: String(0.55 + 0.45 * (1 - i / 8)) }, svg);
      const val = el("text", { x: labelW + w + 8, y: y + 12, class: "bar-value", "font-size": "10" }, svg);
      val.textContent = r[1].toFixed(2);
    });
    mount(container, svg);
  }

  CG.charts = { donut, area, histogram, hbars };
})();
