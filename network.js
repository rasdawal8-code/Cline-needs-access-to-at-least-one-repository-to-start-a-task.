'use strict';

// ============================================================
// SOC Triage Toolkit — Network Traffic Triage Tool
// All analysis is performed locally. No data is transmitted.
// ============================================================

let parsedPackets = [];
let isDemo = false;

// --- SECURITY: safe text escaping to prevent XSS ---
function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// --- CSV Parser ---
function parseCSV(text) {
  const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  if (lines.length < 2) return [];

  const headers = splitCSVLine(lines[0]).map(h => h.trim().replace(/^"|"$/g, ''));

  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const vals = splitCSVLine(line).map(v => v.trim().replace(/^"|"$/g, ''));
    const row = {};
    headers.forEach((h, idx) => { row[h] = vals[idx] || ''; });
    rows.push(row);
  }
  return rows;
}

function splitCSVLine(line) {
  const result = [];
  let cur = '', inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuote && line[i+1] === '"') { cur += '"'; i++; }
      else inQuote = !inQuote;
    } else if (ch === ',' && !inQuote) {
      result.push(cur); cur = '';
    } else {
      cur += ch;
    }
  }
  result.push(cur);
  return result;
}

// --- Column mapping: flexible header detection ---
function mapColumns(headers) {
  const map = {};
  const norm = h => h.toLowerCase().replace(/[^a-z0-9]/g, '');
  const candidates = {
    no:      ['no', 'num', 'number', 'packet'],
    time:    ['time', 'timestamp', 'datetime'],
    src:     ['source', 'src', 'ipsrc', 'sourceip', 'srcip', 'sourceaddress'],
    dst:     ['destination', 'dst', 'dest', 'ipdst', 'destip', 'dstip', 'destinationaddress'],
    proto:   ['protocol', 'proto', 'type'],
    length:  ['length', 'len', 'size', 'bytes'],
    info:    ['info', 'description', 'detail', 'details', 'summary']
  };
  headers.forEach(h => {
    const n = norm(h);
    Object.keys(candidates).forEach(key => {
      if (!map[key] && candidates[key].includes(n)) map[key] = h;
    });
  });
  return map;
}

// --- Normalise a packet row ---
function normalisePacket(row, colMap) {
  return {
    no:     row[colMap.no]   || '',
    time:   row[colMap.time] || '',
    src:    (row[colMap.src]  || '').trim(),
    dst:    (row[colMap.dst]  || '').trim(),
    proto:  (row[colMap.proto]|| '').trim().toUpperCase(),
    length: parseInt(row[colMap.length] || '0', 10) || 0,
    info:   row[colMap.info]  || ''
  };
}

// --- Get thresholds ---
function getThresholds() {
  return {
    packets: parseInt(document.getElementById('thr-packets').value, 10) || 50,
    dests:   parseInt(document.getElementById('thr-dests').value,   10) || 10,
    ports:   parseInt(document.getElementById('thr-ports').value,   10) || 10,
    icmp:    parseInt(document.getElementById('thr-icmp').value,    10) || 30,
    dns:     parseInt(document.getElementById('thr-dns').value,     10) || 30,
    repeat:  parseInt(document.getElementById('thr-repeat').value,  10) || 40
  };
}

function resetNetworkThresholds() {
  document.getElementById('thr-packets').value = 50;
  document.getElementById('thr-dests').value   = 10;
  document.getElementById('thr-ports').value   = 10;
  document.getElementById('thr-icmp').value    = 30;
  document.getElementById('thr-dns').value     = 30;
  document.getElementById('thr-repeat').value  = 40;
}

// --- Tab switching ---
function showTab(name, btn) {
  document.querySelectorAll('.tool-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.section-tab').forEach(b => { b.classList.remove('active'); b.setAttribute('aria-selected','false'); });
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active'); btn.setAttribute('aria-selected','true');
}

// --- File upload handling ---
document.addEventListener('DOMContentLoaded', () => {
  const zone = document.getElementById('upload-zone');
  const input = document.getElementById('file-input');

  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault(); zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  });
  zone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') input.click(); });
  input.addEventListener('change', () => { if (input.files[0]) handleFile(input.files[0]); });

  // filter listeners
  ['filter-src','filter-dst','filter-proto','filter-sev'].forEach(id => {
    document.getElementById(id).addEventListener('input', renderAlerts);
    document.getElementById(id).addEventListener('change', renderAlerts);
  });
});

function handleFile(file) {
  if (!file.name.toLowerCase().endsWith('.csv')) {
    showNetError('Please upload a CSV file. This tool supports Wireshark CSV packet exports.');
    return;
  }
  if (file.size > 50 * 1024 * 1024) {
    showNetError('File is too large (max 50 MB). Consider filtering the capture in Wireshark before exporting.');
    return;
  }
  const reader = new FileReader();
  reader.onload = e => processCSV(e.target.result, file.name, false);
  reader.onerror = () => showNetError('Could not read the file. Please try again.');
  reader.readAsText(file);
}

function showNetError(msg) {
  const box = document.getElementById('parse-error');
  document.getElementById('parse-error-text').textContent = msg;
  box.classList.remove('hidden');
}

function processCSV(text, filename, demo) {
  document.getElementById('parse-error').classList.add('hidden');
  isDemo = demo;

  let rows;
  try { rows = parseCSV(text); } catch(err) {
    showNetError('Failed to parse CSV: ' + err.message);
    return;
  }

  if (rows.length === 0) { showNetError('The CSV file appears to be empty.'); return; }

  const headers = Object.keys(rows[0]);
  const colMap = mapColumns(headers);

  const missing = [];
  if (!colMap.src)   missing.push('Source IP (expected column: Source, src, ip.src)');
  if (!colMap.dst)   missing.push('Destination IP (expected column: Destination, dst, ip.dst)');
  if (!colMap.proto) missing.push('Protocol (expected column: Protocol, proto)');

  if (!colMap.src && !colMap.dst) {
    showNetError('This CSV does not appear to contain Source or Destination address columns. Please check that you exported the correct packet list columns from Wireshark.');
    return;
  }

  parsedPackets = rows.map(r => normalisePacket(r, colMap));

  const fileInfo = document.getElementById('file-info');
  fileInfo.innerHTML = '<span aria-hidden="true">&#10003;</span> ' +
    esc(filename) + ' &mdash; ' + esc(String(parsedPackets.length)) + ' packets loaded' +
    (missing.length ? ' &mdash; Note: missing columns: ' + missing.map(esc).join(', ') : '');
  fileInfo.classList.add('visible');

  const demoBanner = document.getElementById('demo-banner');
  isDemo ? demoBanner.classList.add('visible') : demoBanner.classList.remove('visible');

  document.getElementById('results').classList.remove('hidden');
  populateProtoFilter();
  runAnalysis();
}

function populateProtoFilter() {
  const protos = [...new Set(parsedPackets.map(p => p.proto).filter(Boolean))].sort();
  const sel = document.getElementById('filter-proto');
  sel.innerHTML = '<option value="">All Protocols</option>';
  protos.forEach(p => {
    const opt = document.createElement('option');
    opt.value = p; opt.textContent = p;
    sel.appendChild(opt);
  });
}

// --- Core analysis ---
function runAnalysis() {
  const thr = getThresholds();
  const packets = parsedPackets;

  // Aggregate by source
  const bySource = {};
  const byDest   = {};
  const protos   = {};
  const pairCount = {}; // src->dst
  const srcToDstPorts = {}; // src->dst->Set(ports)

  packets.forEach(p => {
    if (p.src) {
      if (!bySource[p.src]) bySource[p.src] = { count: 0, dests: new Set(), protos: new Set(), lengths: [], icmp: 0, dns: 0 };
      bySource[p.src].count++;
      if (p.dst) bySource[p.src].dests.add(p.dst);
      if (p.proto) bySource[p.src].protos.add(p.proto);
      bySource[p.src].lengths.push(p.length);
      if (p.proto === 'ICMP' || p.proto === 'ICMPv6') bySource[p.src].icmp++;
      if (p.proto === 'DNS') bySource[p.src].dns++;
    }
    if (p.dst) {
      if (!byDest[p.dst]) byDest[p.dst] = { count: 0, sources: new Set() };
      byDest[p.dst].count++;
      if (p.src) byDest[p.dst].sources.add(p.src);
    }
    if (p.proto) protos[p.proto] = (protos[p.proto] || 0) + 1;

    // pair
    if (p.src && p.dst) {
      const pairKey = p.src + '|||' + p.dst;
      if (!pairCount[pairKey]) pairCount[pairKey] = { count: 0, protos: {} };
      pairCount[pairKey].count++;
      pairCount[pairKey].protos[p.proto] = (pairCount[pairKey].protos[p.proto] || 0) + 1;

      // port extraction from info field
      const portMatch = p.info.match(/(?:port\s*|:\s*)(\d{1,5})(?:[^\d]|$)/i);
      if (portMatch) {
        const portNum = parseInt(portMatch[1], 10);
        if (portNum > 0 && portNum < 65536) {
          const sKey = p.src + '|||' + p.dst;
          if (!srcToDstPorts[sKey]) srcToDstPorts[sKey] = new Set();
          srcToDstPorts[sKey].add(portNum);
        }
      }
    }
  });

  // Build stats
  const totalPackets = packets.length;
  const uniqueSrcs   = Object.keys(bySource).length;
  const uniqueDsts   = Object.keys(byDest).length;
  const topSrc       = Object.entries(bySource).sort((a,b) => b[1].count - a[1].count)[0];
  const topDst       = Object.entries(byDest).sort((a,b) => b[1].count - a[1].count)[0];
  const protoEntries = Object.entries(protos).sort((a,b) => b[1] - a[1]);
  const topProto     = protoEntries[0];
  const avgLen       = totalPackets ? Math.round(packets.reduce((s,p) => s + p.length, 0) / totalPackets) : 0;

  // Render stats
  const sg = document.getElementById('stat-grid');
  sg.innerHTML = [
    stat(totalPackets, 'Total Packets'),
    stat(uniqueSrcs,   'Unique Sources'),
    stat(uniqueDsts,   'Unique Destinations'),
    stat(topSrc ? esc(topSrc[0]) : 'N/A', 'Most Active Source'),
    stat(topDst ? esc(topDst[0]) : 'N/A', 'Most Contacted Dest'),
    stat(topProto ? esc(topProto[0]) : 'N/A', 'Top Protocol'),
    stat(avgLen ? avgLen + ' B' : 'N/A', 'Avg Packet Length')
  ].join('');

  // Protocol bars
  renderBars('protocol-bars', protoEntries, protoEntries[0] ? protoEntries[0][1] : 1);

  // Source bars (top 10)
  const srcEntries = Object.entries(bySource).sort((a,b) => b[1].count - a[1].count).slice(0,10);
  renderBars('source-bars', srcEntries.map(([k,v]) => [k, v.count]), srcEntries[0] ? srcEntries[0][1].count : 1);

  // Dest bars (top 10)
  const dstEntries = Object.entries(byDest).sort((a,b) => b[1].count - a[1].count).slice(0,10);
  renderBars('dest-bars', dstEntries.map(([k,v]) => [k, v.count]), dstEntries[0] ? dstEntries[0][1].count : 1);

  // Host table
  const hostTbody = document.getElementById('host-tbody');
  hostTbody.innerHTML = '';
  srcEntries.forEach(([ip, data], i) => {
    const avgL = data.lengths.length ? Math.round(data.lengths.reduce((a,b) => a+b, 0) / data.lengths.length) : 0;
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>' + (i+1) + '</td><td>' + esc(ip) + '</td><td>' + esc(String(data.count)) + '</td><td>' + esc(String(data.dests.size)) + '</td><td>' + [...data.protos].map(esc).join(', ') + '</td><td>' + esc(String(avgL)) + ' B</td>';
    hostTbody.appendChild(tr);
  });

  // Dest table
  const destTbody = document.getElementById('dest-tbody');
  destTbody.innerHTML = '';
  dstEntries.forEach(([ip, data], i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>' + (i+1) + '</td><td>' + esc(ip) + '</td><td>' + esc(String(data.count)) + '</td><td>' + esc(String(data.sources.size)) + '</td>';
    destTbody.appendChild(tr);
  });

  // --- Run detection rules ---
  window._netAlerts = [];
  let scoreTotal = 0;
  const scoreLines = [];

  // Rule 1: High packet volume
  Object.entries(bySource).forEach(([src, data]) => {
    if (data.count > thr.packets) {
      const sev = data.count > thr.packets * 4 ? 'high' : data.count > thr.packets * 2 ? 'medium' : 'low';
      const pts = sev === 'high' ? 25 : sev === 'medium' ? 15 : 10;
      scoreTotal += pts; scoreLines.push(['+' + pts, 'High packet volume: ' + esc(src)]);
      window._netAlerts.push({
        title: 'High Packet Volume',
        sev, src, dst: 'Multiple',
        proto: [...data.protos].join(', ') || 'Various',
        observed: 'Source ' + esc(src) + ' sent ' + esc(String(data.count)) + ' packets. Configured threshold: ' + thr.packets + '.',
        threshold: 'More than ' + thr.packets + ' packets from a single source.',
        why: 'A host generating significantly more traffic than expected may warrant investigation. High packet counts can indicate file transfers, scans, automated tools, or other intensive activity.',
        benign: ['Large file transfer or backup', 'Software update downloads', 'Streaming or video conferencing', 'Network management or monitoring tool', 'Automated application or script'],
        steps: ['Identify what the host was doing at the time.', 'Check whether this is expected for this type of host.', 'Review destination addresses and protocols.', 'Correlate with endpoint logs if available.', 'Determine whether the traffic pattern is consistent over time.']
      });
    }
  });

  // Rule 2: Possible host scanning
  Object.entries(bySource).forEach(([src, data]) => {
    if (data.dests.size > thr.dests) {
      const sev = data.dests.size > thr.dests * 5 ? 'high' : data.dests.size > thr.dests * 2 ? 'medium' : 'low';
      const pts = sev === 'high' ? 20 : sev === 'medium' ? 12 : 8;
      scoreTotal += pts; scoreLines.push(['+' + pts, 'Wide destination spread: ' + esc(src)]);
      window._netAlerts.push({
        title: 'Possible Host Scanning',
        sev, src, dst: data.dests.size + ' unique destinations',
        proto: [...data.protos].join(', ') || 'Various',
        observed: 'Source ' + esc(src) + ' communicated with ' + esc(String(data.dests.size)) + ' unique destination addresses. Configured threshold: ' + thr.dests + ' unique destinations.',
        threshold: 'More than ' + thr.dests + ' unique destinations from one source.',
        why: 'Communicating with a large number of distinct hosts may be consistent with host discovery or network scanning. It can also occur with legitimate network management tools or distributed application behaviour.',
        benign: ['Network management or monitoring software', 'Software that connects to many CDN endpoints', 'Backup tools communicating with multiple targets', 'Legitimate peer-to-peer or distributed applications', 'A developer testing connectivity to multiple hosts'],
        steps: ['Review the list of destination addresses.', 'Determine whether the destinations are internal or external.', 'Identify whether any well-known scanning tools or scripts are installed on the source host.', 'Check whether the activity was expected given the host role.', 'Correlate with firewall logs if available.']
      });
    }
  });

  // Rule 3: Possible port scanning
  Object.entries(srcToDstPorts).forEach(([pairKey, portSet]) => {
    if (portSet.size > thr.ports) {
      const [src, dst] = pairKey.split('|||');
      const sev = portSet.size > thr.ports * 5 ? 'high' : portSet.size > thr.ports * 2 ? 'medium' : 'low';
      const pts = sev === 'high' ? 20 : sev === 'medium' ? 12 : 8;
      scoreTotal += pts; scoreLines.push(['+' + pts, 'Port spread: ' + esc(src) + ' → ' + esc(dst)]);
      window._netAlerts.push({
        title: 'Possible Port Scanning',
        sev, src, dst,
        proto: 'Various (detected from Info field)',
        observed: 'Source ' + esc(src) + ' contacted ' + esc(String(portSet.size)) + ' different ports on destination ' + esc(dst) + '. Configured threshold: ' + thr.ports + ' unique ports.',
        threshold: 'More than ' + thr.ports + ' unique destination ports to the same host.',
        why: 'Contacting a large number of ports on a single host can indicate port scanning, which is sometimes used to identify open services. It can also occur during legitimate service discovery or complex application behaviour.',
        benign: ['Application performing service discovery', 'Load balancer health checking', 'Legitimate vulnerability scanner in an authorised test', 'Development or testing tools', 'Misconfigured application connecting on random ports'],
        steps: ['Review which ports were contacted.', 'Determine whether any of those ports correspond to sensitive services.', 'Check whether a vulnerability scanner or network tool is running on the source host.', 'Verify whether this activity was authorised.', 'Review firewall logs for connection outcomes (accepted vs rejected).']
      });
    }
  });

  // Rule 4: High ICMP
  Object.entries(bySource).forEach(([src, data]) => {
    if (data.icmp > thr.icmp) {
      const sev = data.icmp > thr.icmp * 5 ? 'high' : data.icmp > thr.icmp * 2 ? 'medium' : 'low';
      const pts = sev === 'high' ? 18 : sev === 'medium' ? 10 : 6;
      scoreTotal += pts; scoreLines.push(['+' + pts, 'High ICMP: ' + esc(src)]);
      window._netAlerts.push({
        title: 'High ICMP Activity',
        sev, src, dst: 'Various',
        proto: 'ICMP',
        observed: 'Source ' + esc(src) + ' generated ' + esc(String(data.icmp)) + ' ICMP packets. Configured threshold: ' + thr.icmp + '.',
        threshold: 'More than ' + thr.icmp + ' ICMP packets from one source.',
        why: 'Elevated ICMP traffic may indicate network troubleshooting, monitoring activity, a ping sweep, or denial-of-service related activity. ICMP is frequently used in network discovery.',
        benign: ['Network diagnostic tools (ping, traceroute)', 'Monitoring software checking host availability', 'Routine infrastructure health checks', 'Application-level keep-alive mechanisms'],
        steps: ['Identify the ICMP type (echo request, echo reply, TTL exceeded, etc.) if available.', 'Review the destinations of the ICMP packets.', 'Determine whether monitoring or diagnostic tools are installed on the source host.', 'Check for an unusual number of destinations (possible sweep).', 'Assess volume over time — sustained high ICMP rates are more notable than brief bursts.']
      });
    }
  });

  // Rule 5: High DNS
  Object.entries(bySource).forEach(([src, data]) => {
    if (data.dns > thr.dns) {
      const sev = data.dns > thr.dns * 5 ? 'high' : data.dns > thr.dns * 2 ? 'medium' : 'low';
      const pts = sev === 'high' ? 18 : sev === 'medium' ? 10 : 6;
      scoreTotal += pts; scoreLines.push(['+' + pts, 'High DNS: ' + esc(src)]);
      window._netAlerts.push({
        title: 'High DNS Query Activity',
        sev, src, dst: 'DNS Server(s)',
        proto: 'DNS',
        observed: 'Source ' + esc(src) + ' generated ' + esc(String(data.dns)) + ' DNS packets. Configured threshold: ' + thr.dns + '.',
        threshold: 'More than ' + thr.dns + ' DNS packets from one source.',
        why: 'Elevated DNS query volume may indicate normal browsing or software updates, but can also be associated with automated beaconing, DNS tunnelling, or misconfigured systems generating excessive lookups.',
        benign: ['Normal web browsing generating many DNS lookups', 'Software update mechanisms', 'Applications with aggressive DNS caching behaviour', 'Monitoring or network management software'],
        steps: ['Review which domains are being queried, if visible in the Info column.', 'Look for unusually long or randomised domain names that may indicate DGA (Domain Generation Algorithm) activity.', 'Check whether queries are going to an expected DNS server.', 'Assess whether the volume is consistent with the host role.', 'Consider reviewing DNS server logs for query content.']
      });
    }
  });

  // Rule 6: Repeated src->dst
  Object.entries(pairCount).forEach(([pairKey, data]) => {
    if (data.count > thr.repeat) {
      const [src, dst] = pairKey.split('|||');
      const topProtoForPair = Object.entries(data.protos).sort((a,b) => b[1]-a[1])[0];
      const sev = data.count > thr.repeat * 5 ? 'high' : data.count > thr.repeat * 2 ? 'medium' : 'low';
      const pts = sev === 'high' ? 15 : sev === 'medium' ? 8 : 4;
      scoreTotal += pts; scoreLines.push(['+' + pts, 'Repeated comm: ' + esc(src) + ' → ' + esc(dst)]);
      window._netAlerts.push({
        title: 'Repeated Source-to-Destination Communication',
        sev, src, dst,
        proto: topProtoForPair ? esc(topProtoForPair[0]) : 'Various',
        observed: 'Source ' + esc(src) + ' sent ' + esc(String(data.count)) + ' packets to destination ' + esc(dst) + '. Most common protocol: ' + (topProtoForPair ? esc(topProtoForPair[0]) : 'unknown') + '. Configured threshold: ' + thr.repeat + '.',
        threshold: 'More than ' + thr.repeat + ' packets from the same source to the same destination.',
        why: 'Repeated communication between the same pair of hosts may reflect normal application traffic, persistent connections, or unusual automated activity such as beaconing or data exfiltration.',
        benign: ['Persistent application connection (e.g. database, file share)', 'Streaming media or video call', 'Backup or sync tool', 'Monitoring agent checking in regularly', 'Web browser maintaining a long connection'],
        steps: ['Identify the protocol and services involved.', 'Determine whether an ongoing connection or session is expected between these hosts.', 'Review the time distribution of packets — evenly spaced packets can indicate automated beaconing.', 'Check whether large volumes of data are being transferred.', 'Correlate with endpoint telemetry if available.']
      });
    }
  });

  // Score label
  const scoreLabel = scoreTotal >= 80 ? 'Elevated Activity — Review Recommended' :
                     scoreTotal >= 40 ? 'Moderate Activity — Some Patterns Worth Examining' :
                     scoreTotal >= 10 ? 'Low Activity — Few Notable Patterns' :
                     'Minimal Activity — No Significant Patterns Detected';

  document.getElementById('score-value').textContent = scoreTotal;
  document.getElementById('score-label').textContent  = scoreLabel;

  const scoreTbody = document.querySelector('#score-table tbody');
  scoreTbody.innerHTML = '';
  if (scoreLines.length === 0) {
    scoreTbody.innerHTML = '<tr><td colspan="2">No scoring factors triggered.</td></tr>';
  } else {
    scoreLines.forEach(([pts, desc]) => {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td>' + esc(pts) + '</td><td>' + esc(desc) + '</td>';
      scoreTbody.appendChild(tr);
    });
  }

  renderAlerts();
}

function reanalyse() {
  if (parsedPackets.length > 0) runAnalysis();
}

// --- Render alert cards ---
function renderAlerts() {
  const alerts = window._netAlerts || [];
  const srcFilter  = document.getElementById('filter-src').value.toLowerCase().trim();
  const dstFilter  = document.getElementById('filter-dst').value.toLowerCase().trim();
  const protoFilter= document.getElementById('filter-proto').value.toLowerCase().trim();
  const sevFilter  = document.getElementById('filter-sev').value.toLowerCase().trim();

  const filtered = alerts.filter(a => {
    if (srcFilter   && !a.src.toLowerCase().includes(srcFilter))    return false;
    if (dstFilter   && !a.dst.toLowerCase().includes(dstFilter))    return false;
    if (protoFilter && !a.proto.toLowerCase().includes(protoFilter)) return false;
    if (sevFilter   && a.sev !== sevFilter) return false;
    return true;
  });

  const container = document.getElementById('alert-list');
  const countEl   = document.getElementById('alert-count');
  const noFindings= document.getElementById('no-findings');
  container.innerHTML = '';

  countEl.textContent = filtered.length + ' finding' + (filtered.length !== 1 ? 's' : '') +
    (filtered.length < alerts.length ? ' (filtered from ' + alerts.length + ' total)' : '');

  if (filtered.length === 0) {
    noFindings.classList.remove('hidden');
    return;
  }
  noFindings.classList.add('hidden');

  // Sort: high > medium > low > informational
  const sevOrder = { high:0, medium:1, low:2, informational:3 };
  filtered.sort((a,b) => (sevOrder[a.sev]||3) - (sevOrder[b.sev]||3));

  filtered.forEach((a, idx) => {
    const card = document.createElement('article');
    card.className = 'alert-card sev-' + a.sev;
    card.setAttribute('aria-label', a.title + ' — ' + a.sev + ' severity');

    const bodyId = 'net-alert-body-' + idx;
    card.innerHTML =
      '<div class="alert-header" role="button" tabindex="0" aria-expanded="false" aria-controls="' + bodyId + '" onclick="toggleAlert(this)" onkeydown="if(event.key===\'Enter\'||event.key===\' \')toggleAlert(this)">' +
        '<span class="sev-badge sev-' + a.sev + '" aria-label="Severity: ' + a.sev + '">' + a.sev + '</span>' +
        '<h3>' + esc(a.title) + '</h3>' +
        '<span class="alert-toggle" aria-hidden="true">Click to expand ▼</span>' +
      '</div>' +
      '<div class="alert-body" id="' + bodyId + '">' +
        '<div class="alert-meta">' +
          metaItem('Source', a.src) +
          metaItem('Destination', a.dst) +
          metaItem('Protocol', a.proto) +
          metaItem('Severity', a.sev) +
        '</div>' +
        alertSection('Observed Activity', a.observed) +
        alertSection('Configured Threshold', a.threshold) +
        alertSection('Why This Could Matter', a.why) +
        alertSectionList('Possible Benign Explanations', a.benign) +
        alertSectionList('Suggested Investigation Steps', a.steps) +
      '</div>';

    container.appendChild(card);
  });
}

function toggleAlert(header) {
  const body = header.nextElementSibling;
  const isOpen = body.classList.contains('open');
  body.classList.toggle('open', !isOpen);
  header.setAttribute('aria-expanded', String(!isOpen));
  header.querySelector('.alert-toggle').textContent = isOpen ? 'Click to expand \u25bc' : 'Click to collapse \u25b2';
}

function clearNetworkFilters() {
  ['filter-src','filter-dst','filter-proto','filter-sev'].forEach(id => {
    const el = document.getElementById(id);
    el.value = '';
  });
  renderAlerts();
}

// --- Helpers ---
function stat(value, label) {
  return '<div class="stat-card"><div class="stat-value">' + esc(String(value)) + '</div><div class="stat-label">' + esc(label) + '</div></div>';
}

function renderBars(containerId, entries, maxVal) {
  const el = document.getElementById(containerId);
  el.innerHTML = '';
  if (!entries.length) { el.innerHTML = '<p class="text-muted">No data available.</p>'; return; }
  entries.forEach(([label, count]) => {
    const pct = maxVal > 0 ? Math.round((count / maxVal) * 100) : 0;
    const item = document.createElement('div');
    item.className = 'bar-item';
    item.innerHTML =
      '<span class="bar-label" title="' + esc(label) + '">' + esc(label) + '</span>' +
      '<div class="bar-track" role="presentation"><div class="bar-fill" style="width:' + pct + '%"></div></div>' +
      '<span class="bar-count">' + esc(String(count)) + '</span>';
    el.appendChild(item);
  });
}

function metaItem(label, value) {
  return '<div class="alert-meta-item"><span class="meta-label">' + esc(label) + '</span><span class="meta-value">' + esc(String(value)) + '</span></div>';
}

function alertSection(heading, text) {
  return '<div class="alert-section"><h4>' + esc(heading) + '</h4><p>' + esc(String(text)) + '</p></div>';
}

function alertSectionList(heading, items) {
  return '<div class="alert-section"><h4>' + esc(heading) + '</h4><ul>' +
    items.map(i => '<li>' + esc(i) + '</li>').join('') + '</ul></div>';
}

// --- Sample data loading ---
function loadSample(name) {
  fetch('samples/' + name + '.csv')
    .then(r => { if (!r.ok) throw new Error('File not found'); return r.text(); })
    .then(text => processCSV(text, name + '.csv (sample)', true))
    .catch(() => {
      // fallback: generate inline
      const text = generateSampleCSV(name);
      processCSV(text, name + '.csv (built-in sample)', true);
    });
}

function generateSampleCSV(name) {
  const header = 'No.,Time,Source,Destination,Protocol,Length,Info\n';
  const lines = [header];
  let no = 1;

  function addPacket(src, dst, proto, len, info) {
    lines.push(no++ + ',' + (no * 0.001).toFixed(6) + ',' + src + ',' + dst + ',' + proto + ',' + len + ',"' + info + '"\n');
  }

  if (name === 'normal-traffic') {
    // Ordinary traffic between private hosts
    for (let i = 0; i < 20; i++) addPacket('192.168.1.10','192.168.1.1','TCP',60,'80 → 54321 [ACK]');
    for (let i = 0; i < 15; i++) addPacket('192.168.1.10','8.8.8.8','DNS',70,'Standard query A example.com');
    for (let i = 0; i < 10; i++) addPacket('192.168.1.20','192.168.1.1','TCP',60,'443 → 12345 [ACK]');
    for (let i = 0; i < 8;  i++) addPacket('192.168.1.1','192.168.1.10','ICMP',74,'Echo (ping) request');
    for (let i = 0; i < 5;  i++) addPacket('10.0.0.5','10.0.0.1','ARP',42,'Who has 10.0.0.1?');
  } else if (name === 'high-volume-traffic') {
    // One host sending > 50 packets
    for (let i = 0; i < 120; i++) addPacket('192.168.1.55','192.168.1.1','TCP',60,'[SYN] Seq=0');
    for (let i = 0; i < 20;  i++) addPacket('192.168.1.10','8.8.8.8','DNS',70,'Standard query A updates.example.com');
    for (let i = 0; i < 10;  i++) addPacket('192.168.1.20','192.168.1.1','TCP',60,'443 → port [ACK]');
    for (let i = 0; i < 8;   i++) addPacket('10.0.0.5','10.0.0.1','ICMP',74,'Echo request');
  } else {
    // mixed-soc-lab: high volume + scanning + ICMP
    for (let i = 0; i < 180; i++) addPacket('192.168.1.99','10.0.0.' + (i % 30 + 1),'TCP',60,'[SYN] Seq=0 port ' + (1000 + i));
    for (let i = 0; i < 60;  i++) addPacket('192.168.1.77','192.168.1.1','ICMP',74,'Echo (ping) request');
    for (let i = 0; i < 55;  i++) addPacket('192.168.1.42','192.168.1.1','TCP',60,'80 → port [ACK]');
    for (let i = 0; i < 20;  i++) addPacket('192.168.1.10','8.8.8.8','DNS',70,'Standard query A site' + i + '.example.com');
    for (let i = 0; i < 10;  i++) addPacket('192.168.1.20','192.168.1.1','TCP',60,'443 → port [ACK]');
  }

  return lines.join('');
}
