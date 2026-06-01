/* ============================================================
   CloudChef parser.worker.js
   Off-main-thread: parse → sniff → normalize → sort → metrics.
   Keeps the UI fluid on 50–100 MB JSON dumps.
   ============================================================ */

'use strict';

/* ----- Provider profiles (must mirror app.js definitions) ----- */
const PROVIDERS = {
  aws_cloudtrail: {
    label: 'AWS CloudTrail',
    detect: (r) => ('eventSource' in r) || ('userIdentity' in r) || ('eventVersion' in r && 'eventName' in r),
    time:   (r) => r.eventTime,
    action: (r) => r.eventName,
    actor:  (r) => {
      const u = r.userIdentity || {};
      return u.userName || u.arn || u.principalId || u.type || '—';
    },
    ip: (r) => r.sourceIPAddress || '—',
  },
  okta: {
    label: 'Okta System Log',
    detect: (r) => ('published' in r && 'eventType' in r) || ('actor' in r && 'displayMessage' in r),
    time:   (r) => r.published,
    action: (r) => r.eventType || r.displayMessage,
    actor:  (r) => (r.actor && (r.actor.displayName || r.actor.alternateId)) || '—',
    ip:     (r) => (r.client && r.client.ipAddress) || '—',
  },
  azure_activity: {
    label: 'Azure Activity',
    detect: (r) => ('operationName' in r) || ('callerIpAddress' in r) || ('correlationId' in r && 'resourceId' in r),
    time:   (r) => r.time || r.eventTimestamp,
    action: (r) => (r.operationName && typeof r.operationName === 'object' ? r.operationName.value : r.operationName) || r.operationNameValue,
    actor:  (r) => {
      // Azure identity is often a nested claims object, not a flat string.
      // Returning the object directly would render as [object Object] in the
      // timeline. Unwrap the common nested shapes and fall back to a JSON
      // stringification if the structure is unknown.
      if (r.caller) return r.caller;
      if (!r.identity) return '—';
      if (typeof r.identity === 'object') {
        return r.identity.id
            || (r.identity.claims && r.identity.claims.name)
            || JSON.stringify(r.identity);
      }
      return r.identity;
    },
    ip:     (r) => r.callerIpAddress || '—',
  },
  generic: {
    label: 'Generic JSON',
    detect: () => true,
    time:   (r) => r.timestamp || r.time || r.date || r['@timestamp'] || '',
    action: (r) => r.action || r.event || r.message || r.type || JSON.stringify(r).slice(0, 60),
    actor:  (r) => r.user || r.actor || r.username || r.principal || '—',
    ip:     (r) => r.ip || r.sourceIp || r.source_ip || r.client_ip || '—',
  },
};

const HIGH_RISK = [
  'delete','remove','terminate','destroy','putbucketpolicy','putbucketacl','putuserpolicy',
  'attachrolepolicy','createaccesskey','deactivatemfa','updateassumerolepolicy','consolelogin',
  'stoplogging','disable','revoke','password','createuser','deleteuser',
];
function isHighRisk(a) {
  if (!a) return false;
  const s = String(a).toLowerCase();
  return HIGH_RISK.some(k => s.includes(k));
}

function detectProvider(records) {
  const sample = records[0] || {};
  for (const key of ['aws_cloudtrail','okta','azure_activity']) {
    if (PROVIDERS[key].detect(sample)) return { key, profile: PROVIDERS[key] };
  }
  return { key: 'generic', profile: PROVIDERS.generic };
}

function topN(map, n) {
  return [...map.entries()].sort((a,b) => b[1] - a[1]).slice(0, n);
}

self.onmessage = (e) => {
  const { text } = e.data || {};
  try {
    self.postMessage({ type: 'progress', stage: 'parsing' });

    /* ---- Parse JSON or NDJSON ---- */
    let rawData;
    try {
      rawData = JSON.parse(text);
    } catch (_) {
      // Stream NDJSON via cursor-based regex: avoids materializing a giant
      // segment array, keeping the worker's RAM peak roughly equal to the
      // input string size instead of 2x.
      rawData = [];
      const lineRe = /[^\r\n]+/g;
      let mLine;
      while ((mLine = lineRe.exec(text)) !== null) {
        const t = mLine[0].trim();
        if (!t) continue;
        try { rawData.push(JSON.parse(t)); } catch (_) { /* skip bad line */ }
      }
      if (!rawData.length) throw new Error('Not valid JSON or NDJSON.');
    }

    /* ---- Envelope unwrap ---- */
    const logs = Array.isArray(rawData)
      ? rawData
      : (rawData.Records || rawData.records || rawData.events || rawData.value || []);
    if (!Array.isArray(logs) || logs.length === 0) {
      throw new Error('No log records found in the file.');
    }

    /* ---- Provider detection ---- */
    self.postMessage({ type: 'progress', stage: 'detecting' });
    const { profile, key: providerKey } = detectProvider(logs);

    /* ---- Normalization pass ---- */
    self.postMessage({ type: 'progress', stage: 'normalizing' });
    for (let i = 0; i < logs.length; i++) {
      const r = logs[i];
      r.__time   = profile.time(r) || '';
      r.__action = profile.action(r) || '—';
      r.__actor  = profile.actor(r) || '—';
      r.__ip     = profile.ip(r) || '—';
      const ms = r.__time ? Date.parse(r.__time) : NaN;
      r.__ts = isNaN(ms) ? 0 : ms;
      // Pre-compute lowercase JSON footprint so the search loop on the main
      // thread is O(1) string access per record instead of an O(n) stringify
      // per keystroke.
      r.__searchSpace = JSON.stringify(r).toLowerCase();
    }

    /* ---- Enforced chronological sort (ascending) ---- */
    self.postMessage({ type: 'progress', stage: 'sorting' });
    logs.sort((a, b) => a.__ts - b.__ts);

    /* ---- Metrics ---- */
    self.postMessage({ type: 'progress', stage: 'metrics' });
    const ipCount = new Map();
    const actorCount = new Map();
    const riskCount = new Map();
    let riskTotal = 0;
    let minT = Infinity, maxT = -Infinity;

    for (const r of logs) {
      if (r.__ip    && r.__ip !== '—')    ipCount.set(r.__ip,       (ipCount.get(r.__ip) || 0) + 1);
      if (r.__actor && r.__actor !== '—') actorCount.set(r.__actor, (actorCount.get(r.__actor) || 0) + 1);
      if (isHighRisk(r.__action)) {
        riskTotal++;
        riskCount.set(String(r.__action), (riskCount.get(String(r.__action)) || 0) + 1);
      }
      if (r.__ts) {
        if (r.__ts < minT) minT = r.__ts;
        if (r.__ts > maxT) maxT = r.__ts;
      }
    }

    const metrics = {
      total:    logs.length,
      actors:   actorCount.size,
      ips:      ipCount.size,
      risk:     riskTotal,
      minT:     isFinite(minT) ? minT : null,
      maxT:     isFinite(maxT) ? maxT : null,
      topIps:    topN(ipCount, 5),
      topActors: topN(actorCount, 5),
      topRisk:   topN(riskCount, 5),
    };

    self.postMessage({
      type: 'done',
      providerKey,
      providerLabel: profile.label,
      logs,
      metrics,
    });
  } catch (err) {
    self.postMessage({ type: 'error', message: err.message || String(err) });
  }
};
