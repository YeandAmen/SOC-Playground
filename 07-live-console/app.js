const $ = id => document.getElementById(id);
const colors = { 'Attk101': '#65e7d1', 'Attk102': '#eab45e', 'Attk103': '#94a8ff', 'Attk104': '#ff777c' };
let current = null;
let selectedHours = 24;
let hoverBin = null;

function node(tag, text, cls) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (cls) element.className = cls;
  return element;
}

function smooth(values, passes = 3) {
  let output = values.slice();
  for (let pass = 0; pass < passes; pass += 1) {
    output = output.map((value, index) => {
      const previous = output[Math.max(0, index - 1)];
      const next = output[Math.min(output.length - 1, index + 1)];
      return previous * 0.24 + value * 0.52 + next * 0.24;
    });
  }
  return output;
}

function interpolate(values, position) {
  const left = Math.floor(position);
  const right = Math.min(values.length - 1, left + 1);
  const amount = position - left;
  return values[left] * (1 - amount) + values[right] * amount;
}

function traceSeries(bins) {
  return Object.keys(colors).reduce((series, technique) => {
    series[technique] = smooth(bins.map(bin => bin[technique] || 0));
    return series;
  }, {});
}

function drawTrace() {
  const canvas = $('trace');
  const rect = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.round(rect.width * ratio));
  canvas.height = Math.max(1, Math.round(rect.height * ratio));
  const ctx = canvas.getContext('2d');
  ctx.scale(ratio, ratio);
  const width = rect.width, height = rect.height;
  const center = Math.round(height / 2);
  ctx.clearRect(0, 0, width, height);
  ctx.strokeStyle = '#2c353b';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 8; i += 1) {
    const x = Math.round(width * i / 8) + 0.5;
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
  }
  for (const offset of [-0.72, -0.36, 0, 0.36, 0.72]) {
    const y = Math.round(center + offset * (center - 14)) + 0.5;
    ctx.strokeStyle = offset === 0 ? '#718089' : '#2c353b';
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
  }

  const bins = current?.trace || Array.from({length: 60}, () => ({}));
  if (!current?.total) {
    ctx.beginPath(); ctx.moveTo(0, center); ctx.lineTo(width, center);
    ctx.strokeStyle = '#718089'; ctx.lineWidth = 1; ctx.stroke();
    return;
  }

  const series = traceSeries(bins);
  const totals = bins.map((_, index) => Object.values(series).reduce((sum, values) => sum + values[index], 0));
  const max = Math.max(1, ...totals);
  const samples = [];
  const step = Math.max(2, Math.round(width / 360));
  for (let x = 0; x <= width; x += step) {
    const position = x / width * (bins.length - 1);
    const values = Object.entries(series).map(([technique, points]) => [technique, interpolate(points, position)]);
    const total = values.reduce((sum, item) => sum + item[1], 0);
    const dominant = values.reduce((best, item) => item[1] > best[1] ? item : best, values[0]);
    const amplitude = total ? 3 + Math.pow(total / max, 0.62) * (center - 17) : 1;
    samples.push({x, amplitude, color: colors[dominant[0]], total});
  }

  ctx.save();
  ctx.globalCompositeOperation = 'screen';
  for (const sample of samples) {
    if (!sample.total) continue;
    const gradient = ctx.createLinearGradient(0, center - sample.amplitude, 0, center + sample.amplitude);
    gradient.addColorStop(0, `${sample.color}18`);
    gradient.addColorStop(0.5, `${sample.color}d8`);
    gradient.addColorStop(1, `${sample.color}18`);
    ctx.strokeStyle = gradient;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(sample.x, center - sample.amplitude);
    ctx.lineTo(sample.x, center + sample.amplitude);
    ctx.stroke();
  }
  ctx.restore();

  for (let index = 1; index < samples.length; index += 1) {
    const previous = samples[index - 1];
    const sample = samples[index];
    if (!previous.total && !sample.total) continue;
    ctx.strokeStyle = sample.color;
    ctx.lineWidth = 1.25;
    ctx.shadowColor = sample.color;
    ctx.shadowBlur = 7;
    ctx.beginPath();
    ctx.moveTo(previous.x, center - previous.amplitude);
    ctx.lineTo(sample.x, center - sample.amplitude);
    ctx.moveTo(previous.x, center + previous.amplitude);
    ctx.lineTo(sample.x, center + sample.amplitude);
    ctx.stroke();
  }
  ctx.shadowBlur = 0;
  ctx.strokeStyle = '#e4ffff';
  ctx.globalAlpha = 0.74;
  ctx.beginPath(); ctx.moveTo(0, center); ctx.lineTo(width, center); ctx.stroke();
  ctx.globalAlpha = 1;

  if (hoverBin !== null) {
    const x = hoverBin / (bins.length - 1) * width;
    ctx.strokeStyle = '#dce9ed';
    ctx.setLineDash([3, 4]);
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
    ctx.setLineDash([]);
  }
}

function updateTraceTooltip(event) {
  if (!current?.trace?.length) return;
  const canvas = $('trace');
  const rect = canvas.getBoundingClientRect();
  hoverBin = Math.max(0, Math.min(59, Math.round((event.clientX - rect.left) / rect.width * 59)));
  const bin = current.trace[hoverBin] || {};
  const minutesAgo = Math.round((59 - hoverBin) / 59 * current.hours * 60);
  const tooltip = $('trace-tooltip');
  const entries = Object.entries(colors).filter(([technique]) => bin[technique]).map(([technique]) => `${technique} ${bin[technique]}`);
  tooltip.textContent = `${minutesAgo ? `${minutesAgo}m ago` : 'now'} / ${entries.join(' / ') || 'no events'}`;
  tooltip.hidden = false;
  const left = Math.max(8, Math.min(rect.width - tooltip.offsetWidth - 8, event.clientX - rect.left + 12));
  tooltip.style.left = `${left}px`;
  tooltip.style.top = `${Math.max(8, event.clientY - rect.top - 34)}px`;
  drawTrace();
}

function render(data) {
  current = data;
  $('total-count').textContent = data.total.toLocaleString();
  $('metric-events').textContent = data.total.toLocaleString();
  $('metric-detections').textContent = data.detections.length;
  $('metric-hosts').textContent = data.hosts.length;
  $('last-update').textContent = `LAST SEARCH ${new Date(data.updated_at * 1000).toLocaleString()} · AUTO REFRESH 15s`;
  $('axis-start').textContent = `−${data.hours}h`;
  $('trace-caption').textContent = `${data.total} matching events · ${data.hours}h window`;
  $('event-count').textContent = `${data.events.length} SHOWN`;
  $('limit-note').textContent = data.limited ? 'Result limit reached for at least one source. Narrow the time window to inspect more events.' : '';
  const stats = $('technique-stats'); stats.replaceChildren();
  const maximum = Math.max(1, ...Object.values(data.counts));
  for (const [technique, color] of Object.entries(colors)) {
    const row = node('div', undefined, 'technique-row');
    const track = node('div', undefined, 'stat-track');
    const fill = node('div', undefined, 'stat-fill');
    fill.style.background = color;
    fill.style.width = `${(data.counts[technique] || 0) / maximum * 100}%`;
    track.append(fill);
    row.append(node('span', technique), track, node('strong', String(data.counts[technique] || 0)));
    stats.append(row);
  }
  const detections = $('detections'); detections.replaceChildren();
  if (!data.detections.length) detections.append(node('p', 'No detection rules matched in this window.', 'empty'));
  for (const item of data.detections) {
    const card = node('div', undefined, `detection ${item.severity}`);
    card.append(node('code', item.technique), node('strong', item.title), node('small', item.reason));
    detections.append(card);
  }
  const tbody = $('events'); tbody.replaceChildren();
  if (!data.events.length) {
    const row = node('tr'); const cell = node('td', 'No matching events in this window.', 'empty'); cell.colSpan = 5; row.append(cell); tbody.append(row);
  }
  for (const event of data.events) {
    const row = node('tr');
    for (const value of [new Date(event.time * 1000).toLocaleString(), event.technique, event.label, event.host, event.actor]) row.append(node('td', value));
    row.title = event.detail;
    tbody.append(row);
  }
  drawTrace();
}

async function refresh() {
  try {
    const response = await fetch(`/api/events?hours=${selectedHours}`, {cache:'no-store'});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    render(data);
    $('connect-form').hidden = true;
    $('status').className = 'status live'; $('status').innerHTML = '<i></i> LIVE';
  } catch (error) {
    $('status').className = 'status error'; $('status').innerHTML = '<i></i> DISCONNECTED';
    $('last-update').textContent = error.message;
    if (error.message.includes('Connect to Splunk') || error.message.includes('401')) $('connect-form').hidden = false;
  }
}

$('connect-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const user = form.elements.user.value.trim();
  const password = form.elements.password.value;
  form.elements.password.value = '';
  $('connect-error').textContent = '';
  try {
    const response = await fetch('/api/connect', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({user,password})});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
    await refresh();
  } catch (error) {
    $('connect-error').textContent = error.message;
  }
});

$('hours').addEventListener('change', event => { selectedHours = Number(event.target.value); refresh(); });
$('refresh').addEventListener('click', refresh);
function setView(view) {
  const stats = view === 'stats';
  $('statistics').hidden = !stats;
  document.querySelector('.trace-section').hidden = stats;
  document.querySelector('.events-section').hidden = stats;
  $('stats-tab').classList.toggle('active', stats);
  $('traces-tab').classList.toggle('active', !stats);
  $('stats-tab').setAttribute('aria-selected', String(stats));
  $('traces-tab').setAttribute('aria-selected', String(!stats));
  if (!stats) drawTrace();
}
$('stats-tab').addEventListener('click', () => setView('stats'));
$('traces-tab').addEventListener('click', () => setView('traces'));
window.addEventListener('resize', drawTrace);
$('trace').addEventListener('pointermove', updateTraceTooltip);
$('trace').addEventListener('pointerleave', () => { hoverBin = null; $('trace-tooltip').hidden = true; drawTrace(); });
refresh();
setInterval(refresh, 15000);
