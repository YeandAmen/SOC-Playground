const TraceModel = (() => {
  const techniques = ['Attk101', 'Attk102', 'Attk103', 'Attk104'];
  function buildProfiles(observations, end, seconds, samples = 480) {
    const profiles = Object.fromEntries(techniques.map(key => [key, Array(samples).fill(0)]));
    const spacing = seconds / (samples - 1), sigma = Math.max(1.5, spacing * 0.65), start = end - seconds;
    for (const event of observations) {
      if (!profiles[event.technique] || !Number.isFinite(event.time)) continue;
      const position = (event.time - start) / spacing, radius = sigma * 3 / spacing;
      for (let index = Math.max(0, Math.ceil(position - radius)); index <= Math.min(samples - 1, Math.floor(position + radius)); index += 1) {
        const distance = (index - position) * spacing / sigma;
        profiles[event.technique][index] += (event.count || 1) * Math.exp(-0.5 * distance * distance);
      }
    }
    return {profiles, maximum: Math.max(4, ...Object.values(profiles).flat()), end, seconds, sigma};
  }
  function sampleX(index, samples, end, now, seconds, width) {
    return index / (samples - 1) * width - (now - end) / seconds * width;
  }
  return {techniques, buildProfiles, sampleX};
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = TraceModel;
} else {
const $ = id => document.getElementById(id);
const colors = {Attk101: '#65e7d1', Attk102: '#eab45e', Attk103: '#94a8ff', Attk104: '#ff777c'};
let current = null;
let selectedHours = 1;
let captureSeconds = 900;
let capture = null;
let hoverFraction = null;
let connected = false;
let frozenTime = Date.now() / 1000;
let requestId = 0;
let requestController = null;
let lastFrame = 0;

function node(tag, text, cls) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (cls) element.className = cls;
  return element;
}

function displayTime() { return connected ? Date.now() / 1000 : frozenTime; }

function rebuildCapture() {
  if (!current) return;
  const seconds = captureSeconds || current.hours * 3600;
  const end = Date.now() / 1000;
  let observations = current.trace_events || current.events;
  // Historical overview uses every returned bin, including events beyond the table limit.
  if (!captureSeconds) {
    observations = current.trace.flatMap((bin, index) => Object.entries(bin).map(([technique, count]) => ({
      technique, count, time: current.updated_at - current.hours * 3600 + (index + 0.5) * current.hours * 3600 / current.trace.length,
    })));
  }
  capture = TraceModel.buildProfiles(observations, end, seconds);
  $('axis-start').textContent = `-${seconds / 60}m`;
  $('axis-middle').textContent = `-${seconds / 120}m`;
  $('trace-caption').textContent = `${captureSeconds ? 'LIVE CAPTURE' : 'WINDOW OVERVIEW'} / ${seconds / 60} MIN`;
}

function drawTrace() {
  if ($('statistics').hidden === false) return;
  const canvas = $('trace');
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const ratio = window.devicePixelRatio || 1;
  const pixelWidth = Math.round(rect.width * ratio), pixelHeight = Math.round(rect.height * ratio);
  if (canvas.width !== pixelWidth || canvas.height !== pixelHeight) {
    canvas.width = pixelWidth; canvas.height = pixelHeight;
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  const width = rect.width, height = rect.height, center = height / 2;
  const now = displayTime(), seconds = capture?.seconds || captureSeconds;
  ctx.clearRect(0, 0, width, height);
  ctx.lineWidth = 1;
  ctx.strokeStyle = '#2c353b';
  const gridSeconds = seconds / 8;
  const shift = (now % gridSeconds) / gridSeconds * width / 8;
  for (let index = 0; index <= 9; index += 1) {
    const x = index * width / 8 - shift;
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
  }
  for (const offset of [-0.7, -0.35, 0.35, 0.7]) {
    const y = center + offset * (center - 14);
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
  }

  if (capture) {
    ctx.save();
    ctx.globalCompositeOperation = 'screen';
    for (const [technique, values] of Object.entries(capture.profiles)) {
      const color = colors[technique];
      const points = values.map((value, index) => ({
        x: TraceModel.sampleX(index, values.length, capture.end, now, capture.seconds, width),
        amplitude: Math.sqrt(value / capture.maximum) * (center - 14), value,
      }));
      const fill = ctx.createLinearGradient(0, 10, 0, height - 10);
      fill.addColorStop(0, `${color}08`); fill.addColorStop(0.5, `${color}60`); fill.addColorStop(1, `${color}08`);
      ctx.beginPath();
      points.forEach((point, index) => index ? ctx.lineTo(point.x, center - point.amplitude) : ctx.moveTo(point.x, center - point.amplitude));
      for (let index = points.length - 1; index >= 0; index -= 1) ctx.lineTo(points[index].x, center + points[index].amplitude);
      ctx.closePath(); ctx.fillStyle = fill; ctx.fill();
      ctx.strokeStyle = `${color}90`; ctx.lineWidth = 0.7;
      for (const point of points) {
        if (point.value < 0.01) continue;
        ctx.beginPath(); ctx.moveTo(point.x, center - point.amplitude); ctx.lineTo(point.x, center + point.amplitude); ctx.stroke();
      }
      ctx.strokeStyle = color; ctx.lineWidth = 1.2; ctx.shadowColor = color; ctx.shadowBlur = 5;
      for (const direction of [-1, 1]) {
        ctx.beginPath();
        let drawing = false;
        for (const point of points) {
          if (point.value < 0.005) { drawing = false; continue; }
          if (drawing) ctx.lineTo(point.x, center + direction * point.amplitude);
          else ctx.moveTo(point.x, center + direction * point.amplitude);
          drawing = true;
        }
        ctx.stroke();
      }
      ctx.shadowBlur = 0;
    }
    ctx.restore();
  }
  ctx.strokeStyle = connected ? '#c4e9e4' : '#718089';
  ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(0, center); ctx.lineTo(width, center); ctx.stroke();
  if (hoverFraction !== null) {
    const x = hoverFraction * width;
    ctx.strokeStyle = '#dce9ed'; ctx.setLineDash([3, 4]);
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke(); ctx.setLineDash([]);
  }
}

function animate(timestamp) {
  if (timestamp - lastFrame >= 33 && !document.hidden) {
    drawTrace(); lastFrame = timestamp;
  }
  requestAnimationFrame(animate);
}

function updateTraceTooltip(event) {
  if (!capture || !current) return;
  const rect = $('trace').getBoundingClientRect();
  hoverFraction = Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width));
  const time = displayTime() - (1 - hoverFraction) * capture.seconds;
  const halfInterval = Math.max(2.5, capture.sigma);
  const matches = (current.trace_events || current.events).filter(item => Math.abs(item.time - time) <= halfInterval);
  const entries = Object.keys(colors).map(key => [key, matches.filter(item => item.technique === key).length]).filter(([, count]) => count);
  const tooltip = $('trace-tooltip');
  tooltip.textContent = `${new Date(time * 1000).toLocaleTimeString()} / ${Math.round(halfInterval * 2)}s / ${entries.map(([key, count]) => `${key} ${count}`).join(' / ') || 'no events'}`;
  tooltip.hidden = false;
  tooltip.style.left = `${Math.max(8, Math.min(rect.width - tooltip.offsetWidth - 8, event.clientX - rect.left + 12))}px`;
  tooltip.style.top = `${Math.max(8, event.clientY - rect.top - 34)}px`;
}

function render(data) {
  current = data;
  $('total-count').textContent = data.total.toLocaleString();
  $('metric-events').textContent = data.total.toLocaleString();
  $('metric-detections').textContent = data.detections.length;
  $('metric-hosts').textContent = data.hosts.length;
  $('last-update').textContent = `LAST SEARCH ${new Date(data.updated_at * 1000).toLocaleString()} / POLL 5s`;
  $('event-count').textContent = `${data.events.length} SHOWN`;
  const sampled = !data.trace_events && data.total > data.events.length;
  $('limit-note').textContent = sampled ? `Live capture is limited to the newest ${data.events.length} of ${data.total} matching events.` : data.limited ? 'Result limit reached. Narrow the search window to inspect more events.' : '';
  const stats = $('technique-stats'); stats.replaceChildren();
  const maximum = Math.max(1, ...Object.values(data.counts));
  for (const [technique, color] of Object.entries(colors)) {
    const row = node('div', undefined, 'technique-row');
    const track = node('div', undefined, 'stat-track'), fill = node('div', undefined, 'stat-fill');
    fill.style.background = color; fill.style.width = `${(data.counts[technique] || 0) / maximum * 100}%`;
    track.append(fill); row.append(node('span', technique), track, node('strong', String(data.counts[technique] || 0))); stats.append(row);
  }
  const detections = $('detections'); detections.replaceChildren();
  if (!data.detections.length) detections.append(node('p', 'No detection rules matched in this window.', 'empty'));
  for (const item of data.detections) {
    const card = node('div', undefined, `detection ${item.severity}`);
    card.append(node('code', item.technique), node('strong', item.title), node('small', item.reason)); detections.append(card);
  }
  const tbody = $('events'); tbody.replaceChildren();
  if (!data.events.length) {
    const row = node('tr'), cell = node('td', 'No matching events in this window.', 'empty');
    cell.colSpan = 5; row.append(cell); tbody.append(row);
  }
  for (const event of data.events) {
    const row = node('tr');
    for (const value of [new Date(event.time * 1000).toLocaleString(), event.technique, event.label, event.host, event.actor]) row.append(node('td', value));
    row.title = event.detail; tbody.append(row);
  }
  rebuildCapture();
}

async function refresh(replace = false) {
  if (requestController && !replace) return;
  if (requestController) requestController.abort();
  const id = ++requestId;
  const controller = new AbortController(); requestController = controller;
  try {
    const response = await fetch(`/api/events?hours=${selectedHours}`, {cache: 'no-store', signal: controller.signal});
    const data = await response.json();
    if (id !== requestId) return;
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    connected = true; render(data); $('connect-form').hidden = true;
    $('status').className = 'status live'; $('status').innerHTML = '<i></i> LIVE';
  } catch (error) {
    if (id !== requestId || error.name === 'AbortError') return;
    frozenTime = displayTime(); connected = false;
    $('status').className = 'status error'; $('status').innerHTML = '<i></i> DISCONNECTED';
    $('last-update').textContent = error.message;
    if (error.message.includes('Connect to Splunk') || error.message.includes('401')) $('connect-form').hidden = false;
  } finally { if (id === requestId) requestController = null; }
}

$('connect-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget, user = form.elements.user.value.trim(), password = form.elements.password.value;
  form.elements.password.value = ''; $('connect-error').textContent = '';
  try {
    const response = await fetch('/api/connect', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({user, password})});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
    await refresh(true);
  } catch (error) { $('connect-error').textContent = error.message; }
});
$('hours').addEventListener('change', event => { selectedHours = Number(event.target.value); refresh(true); });
$('capture-range').addEventListener('change', event => { captureSeconds = Number(event.target.value); rebuildCapture(); });
$('refresh').addEventListener('click', () => refresh(true));
function setView(view) {
  const stats = view === 'stats';
  $('statistics').hidden = !stats; document.querySelector('.trace-section').hidden = stats; document.querySelector('.events-section').hidden = stats;
  $('stats-tab').classList.toggle('active', stats); $('traces-tab').classList.toggle('active', !stats);
  $('stats-tab').setAttribute('aria-selected', String(stats)); $('traces-tab').setAttribute('aria-selected', String(!stats));
}
$('stats-tab').addEventListener('click', () => setView('stats'));
$('traces-tab').addEventListener('click', () => setView('traces'));
$('trace').addEventListener('pointermove', updateTraceTooltip);
$('trace').addEventListener('pointerleave', () => { hoverFraction = null; $('trace-tooltip').hidden = true; });
refresh(); setInterval(refresh, 5000); requestAnimationFrame(animate);
}

async function loadTags() {
  try {
    const r = await fetch('/api/status', {cache:'no-store'});
    const data = await r.json();
    if (data.error) throw new Error(data.error);
    const c = data.tags || [];
    const html = c.map(t => {
      const dot = t.tag === 'red' ? '&#9679;' : '&#9675;';
      const clr = t.tag === 'red' ? '#ff777c' : '#65e7d1';
      return `<span style="color:${clr}">${dot}</span> <strong>${t.check}</strong> <span>${t.count} events</span>`;
    }).join('<br>');
    document.getElementById('status-tags').innerHTML = html || '<p class="empty">No data</p>';
  } catch (_) {
    document.getElementById('status-tags').innerHTML = '<p class="empty">offline</p>';
  }
}
setInterval(loadTags, 30000);
loadTags();
