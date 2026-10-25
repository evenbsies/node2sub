'use strict';
function b64encode(str) {
  return btoa(unescape(encodeURIComponent(str)));
}
// ---------------- 节点解析 ----------------
function dec(str) {
  try { return decodeURIComponent(str); } catch (e) { return str; }
}
function b64decodeSafe(str) {
  try {
    let s = str.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return decodeURIComponent(escape(atob(s)));
  } catch (e) { return null; }
}
function parseParams(qs) {
  const o = {};
  if (!qs) return o;
  qs.split('&').forEach(p => {
    const i = p.indexOf('=');
    if (i >= 0) o[dec(p.slice(0, i))] = dec(p.slice(i + 1));
    else if (p) o[p] = '';
  });
  return o;
}
function parseUserinfo(auth) {
  const i = auth.indexOf(':');
  if (i >= 0) return { user: dec(auth.slice(0, i)), pass: dec(auth.slice(i + 1)) };
  return { user: dec(auth), pass: '' };
}
function parseSS(body, name) {
  let main = body, query = '';
  const q = body.indexOf('?');
  if (q >= 0) { main = body.slice(0, q); query = body.slice(q + 1); }
  const p = parseParams(query);
  let server = '', port = 0, method = '', password = '';
  if (!main.includes('@')) {
    const d = b64decodeSafe(main);
    if (d && d.includes('@')) {
      const mm = d.match(/^(.*):(.*)@(.*):(\d+)$/);
      if (mm) { method = mm[1]; password = mm[2]; server = mm[3]; port = parseInt(mm[4]) || 0; }
    }
    if (!method) return null;
  } else {
    const at = main.lastIndexOf('@');
    const auth = main.slice(0, at), hp = main.slice(at + 1);
    const c = hp.lastIndexOf(':');
    if (c < 0) return null;
    server = hp.slice(0, c); port = parseInt(hp.slice(c + 1)) || 0;
    if (server.startsWith('[') && server.endsWith(']')) server = server.slice(1, -1);
    if (auth.includes(':')) {
      const i = auth.indexOf(':');
      method = dec(auth.slice(0, i)); password = dec(auth.slice(i + 1));
    } else {
      const d = b64decodeSafe(auth);
      if (d && d.includes(':')) {
        const i = d.indexOf(':');
        method = d.slice(0, i); password = d.slice(i + 1);
      } else return null;
    }
  }
  return { type: 'ss', name, server, port, method, password, plugin: p.plugin || '',
    tls: false, insecure: false, sni: '', net: 'tcp', host: '', path: '', grpcService: '' };
}
function parseNodeLine(line) {
  const h = line.lastIndexOf('#');
  const body = h >= 0 ? line.slice(0, h) : line;
  const name = h >= 0 ? dec(line.slice(h + 1)) : '';
  const m = body.match(/^([a-z0-9+.-]+):\/\/(.*)$/i);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  const rest = m[2];
  if (scheme === 'vmess') {
    let j;
    try { j = JSON.parse(b64decodeSafe(rest)); } catch (e) { return null; }
    if (!j) return null;
    return { type: 'vmess', name: name || j.ps || '', server: j.add || '', port: parseInt(j.port) || 0,
      uuid: j.id || '', alterId: parseInt(j.aid) || 0, cipher: j.scy || 'auto',
      net: j.net || 'tcp', tls: j.tls === 'tls', sni: j.sni || j.host || '',
      host: j.host || '', path: j.path || '', grpcService: j.path || '',
      insecure: false };
  }
  if (scheme === 'ss' || scheme === 'shadowsocks') return parseSS(rest, name);
  let main = rest, query = '';
  const q = rest.indexOf('?');
  if (q >= 0) { main = rest.slice(0, q); query = rest.slice(q + 1); }
  const p = parseParams(query);
  const at = main.lastIndexOf('@');
  let auth = '', hp = main;
  if (at >= 0) { auth = main.slice(0, at); hp = main.slice(at + 1); }
  const c = hp.lastIndexOf(':');
  if (c < 0) return null;
  let server = hp.slice(0, c);
  const port = parseInt(hp.slice(c + 1)) || 0;
  if (server.startsWith('[') && server.endsWith(']')) server = server.slice(1, -1);
  const up = parseUserinfo(auth);
  const tls = p.security === 'tls' || p.tls === '1' || p.tls === 'true';
  const insecure = p.insecure === '1' || p.allowInsecure === '1' || p['skip-cert-verify'] === '1';
  const base = { name, server, port, tls, insecure,
    sni: p.sni || p.peer || '', net: p.type || 'tcp',
    host: p.host || '', path: p.path || '', grpcService: p.serviceName || '' };
  if (scheme === 'vless') return Object.assign({ type: 'vless', uuid: up.user, flow: p.flow || '' }, base);
  if (scheme === 'trojan') return Object.assign({ type: 'trojan', password: up.user }, base);
  if (scheme === 'socks5' || scheme === 'socks') return Object.assign({ type: 'socks5', username: up.user, password: up.pass }, base);
  if (scheme === 'http') return Object.assign({ type: 'http', username: up.user, password: up.pass }, base);
  if (scheme === 'hysteria2' || scheme === 'hy2') return Object.assign({ type: 'hysteria2', password: up.user,
    obfs: p.obfs || '', obfsPassword: p['obfs-password'] || '' }, base);
  if (scheme === 'tuic') return Object.assign({ type: 'tuic', uuid: up.user, password: up.pass,
    congestion: p.congestion_control || '', udpRelay: p.udp_relay_mode || '', alpn: p.alpn || '' }, base);
  return null;
}
function parseNodes(raw) {
  const nodes = [], skipped = [];
  raw.split('\n').forEach((lineRaw, idx) => {
    const line = lineRaw.trim();
    if (!line) return;
    const node = parseNodeLine(line);
    if (node) nodes.push(node);
    else skipped.push('第' + (idx + 1) + '行无法识别，已跳过');
  });
  return { nodes, skipped };
}
function dedupNames(nodes) {
  const seen = {};
  nodes.forEach(n => {
    let nm = n.name || (n.server + ':' + n.port);
    if (seen[nm]) { let k = 2; while (seen[nm + '-' + k]) k++; nm = nm + '-' + k; }
    seen[nm] = 1;
    n.name = nm;
  });
}
function emitFormat(fmt, nodes) {
  if (fmt === 'clash') return emitClash(nodes);
  if (fmt === 'singbox') return emitSingbox(nodes);
  if (fmt === 'surge') return emitSurge(nodes);
  if (fmt === 'qx') return emitQx(nodes);
  if (fmt === 'loon') return emitLoon(nodes);
  return { content: '', skipped: ['未知格式'] };
}
// ---------------- Clash ----------------
function clashWsGrpc(n, L) {
  if (n.net === 'ws') {
    L.push('    network: ws');
    L.push('    ws-opts:');
    L.push('      path: ' + JSON.stringify(n.path || '/'));
    if (n.host) L.push('      headers: {Host: ' + JSON.stringify(n.host) + '}');
  } else if (n.net === 'grpc') {
    L.push('    network: grpc');
    L.push('    grpc-opts:');
    L.push('      grpc-service-name: ' + JSON.stringify(n.grpcService));
  }
}
function clashTls(n, L) {
  if (n.tls) {
    L.push('    tls: true');
    if (n.sni) L.push('    servername: ' + JSON.stringify(n.sni));
    if (n.insecure) L.push('    skip-cert-verify: true');
  }
}
function clashProxy(n) {
  const q = v => JSON.stringify(String(v));
  const L = [];
  L.push('  - name: ' + q(n.name));
  L.push('    type: ' + n.type);
  L.push('    server: ' + q(n.server));
  L.push('    port: ' + n.port);
  if (n.type === 'vless') {
    L.push('    uuid: ' + q(n.uuid));
    if (n.flow) L.push('    flow: ' + q(n.flow));
    clashTls(n, L); clashWsGrpc(n, L);
  } else if (n.type === 'vmess') {
    L.push('    uuid: ' + q(n.uuid));
    L.push('    alterId: ' + n.alterId);
    L.push('    cipher: ' + q(n.cipher));
    clashTls(n, L); clashWsGrpc(n, L);
  } else if (n.type === 'trojan') {
    L.push('    password: ' + q(n.password));
    if (n.sni) L.push('    sni: ' + q(n.sni));
    if (n.insecure) L.push('    skip-cert-verify: true');
    clashWsGrpc(n, L);
  } else if (n.type === 'ss') {
    L.push('    cipher: ' + q(n.method));
    L.push('    password: ' + q(n.password));
    if (n.plugin) {
      const parts = n.plugin.split(';');
      L.push('    plugin: ' + q(parts[0]));
      if (parts.length > 1) {
        L.push('    plugin-opts:');
        parts.slice(1).forEach(kv => {
          const i = kv.indexOf('=');
          if (i >= 0) L.push('      ' + kv.slice(0, i) + ': ' + q(kv.slice(i + 1)));
        });
      }
    }
  } else if (n.type === 'socks5') {
    if (n.username) L.push('    username: ' + q(n.username));
    if (n.password) L.push('    password: ' + q(n.password));
    clashTls(n, L);
  } else if (n.type === 'http') {
    if (n.username) L.push('    username: ' + q(n.username));
    if (n.password) L.push('    password: ' + q(n.password));
    if (n.tls) L.push('    tls: true');
  } else if (n.type === 'hysteria2') {
    L.push('    password: ' + q(n.password));
    if (n.sni) L.push('    sni: ' + q(n.sni));
    if (n.insecure) L.push('    skip-cert-verify: true');
    if (n.obfs) {
      L.push('    obfs: ' + q(n.obfs));
      if (n.obfsPassword) L.push('    obfs-password: ' + q(n.obfsPassword));
    }
  } else if (n.type === 'tuic') {
    L.push('    uuid: ' + q(n.uuid));
    L.push('    password: ' + q(n.password));
    if (n.sni) L.push('    sni: ' + q(n.sni));
    if (n.alpn) L.push('    alpn: [' + n.alpn.split(',').map(x => q(x.trim())).join(', ') + ']');
    if (n.congestion) L.push('    congestion-controller: ' + q(n.congestion));
    if (n.udpRelay) L.push('    udp-relay-mode: ' + q(n.udpRelay));
    if (n.insecure) L.push('    skip-cert-verify: true');
  }
  return L.join('\n');
}
function emitClash(nodes) {
  const ok = [], skipped = [];
  const TYPES = ['vless', 'vmess', 'trojan', 'ss', 'socks5', 'http', 'hysteria2', 'tuic'];
  nodes.forEach(n => {
    if (TYPES.includes(n.type)) ok.push(n);
    else skipped.push('Clash 不支持：' + (n.name || n.server));
  });
  if (!ok.length) return { content: '', skipped };
  dedupNames(ok);
  let y = 'port: 7890\nsocks-port: 7891\nallow-lan: false\nmode: rule\nlog-level: info\nproxies:\n';
  y += ok.map(clashProxy).join('\n') + '\n';
  y += 'proxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n';
  y += ok.map(n => '      - ' + JSON.stringify(n.name)).join('\n') + '\n';
  y += 'rules:\n  - MATCH,PROXY\n';
  return { content: y, skipped };
}
// ---------------- sing-box ----------------
function sbTls(n) {
  if (!n.tls && n.type !== 'hysteria2' && n.type !== 'tuic') return undefined;
  const t = { enabled: true };
  if (n.sni) t.server_name = n.sni;
  if (n.insecure) t.insecure = true;
  return t;
}
function sbTransport(n) {
  if (n.net === 'ws') {
    const t = { type: 'ws', path: n.path || '/' };
    if (n.host) t.headers = { Host: n.host };
    return t;
  }
  if (n.net === 'grpc') return { type: 'grpc', service_name: n.grpcService };
  return undefined;
}
function sbOutbound(n) {
  const o = { tag: n.name, server: n.server, server_port: n.port };
  if (n.type === 'vless') { o.type = 'vless'; o.uuid = n.uuid; if (n.flow) o.flow = n.flow; }
  else if (n.type === 'vmess') { o.type = 'vmess'; o.uuid = n.uuid; o.security = n.cipher; o.alter_id = n.alterId; }
  else if (n.type === 'trojan') { o.type = 'trojan'; o.password = n.password; }
  else if (n.type === 'ss') { o.type = 'shadowsocks'; o.method = n.method; o.password = n.password; }
  else if (n.type === 'socks5') { o.type = 'socks'; o.version = '5'; if (n.username) o.username = n.username; if (n.password) o.password = n.password; }
  else if (n.type === 'http') { o.type = 'http'; if (n.username) o.username = n.username; if (n.password) o.password = n.password; }
  else if (n.type === 'hysteria2') { o.type = 'hysteria2'; o.password = n.password; if (n.obfs) o.obfs = { type: n.obfs, password: n.obfsPassword || '' }; }
  else if (n.type === 'tuic') { o.type = 'tuic'; o.uuid = n.uuid; o.password = n.password; if (n.congestion) o.congestion_control = n.congestion; if (n.udpRelay) o.udp_relay_mode = n.udpRelay; }
  else return null;
  const tls = sbTls(n);
  if (tls) o.tls = tls;
  const tr = sbTransport(n);
  if (tr) o.transport = tr;
  return o;
}
function emitSingbox(nodes) {
  const outs = [], skipped = [], names = [];
  nodes.forEach(n => {
    const o = sbOutbound(n);
    if (!o) { skipped.push('sing-box 不支持：' + (n.name || n.server)); return; }
    let tag = o.tag, k = 2;
    while (names.includes(tag)) tag = o.tag + '-' + (k++);
    o.tag = tag; names.push(tag);
    outs.push(o);
  });
  if (!outs.length) return { content: '', skipped };
  const cfg = {
    log: { level: 'info' },
    inbounds: [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }],
    outbounds: [{ type: 'selector', tag: 'proxy', outbounds: names.concat(['direct']) }].concat(outs).concat([{ type: 'direct', tag: 'direct' }]),
    route: { final: 'proxy' }
  };
  return { content: JSON.stringify(cfg, null, 2) + '\n', skipped };
}
// ---------------- Surge / Quantumult X / Loon ----------------
function cleanName(n) {
  return (n.name || (n.server + ':' + n.port)).replace(/[,\n=\r]/g, '-').trim();
}
function surgeLine(n) {
  const nm = cleanName(n);
  const kv = [];
  if (n.username) kv.push('username=' + n.username);
  if (n.password) kv.push('password=' + n.password);
  if (n.type === 'vmess') {
    let s = nm + ' = vmess, ' + n.server + ', ' + n.port + ', username=' + n.uuid;
    if (n.net === 'ws') { s += ', ws=true, ws-path=' + (n.path || '/'); if (n.host) s += ', ws-headers=Host:' + n.host; }
    if (n.tls) { s += ', tls=true'; if (n.sni) s += ', sni=' + n.sni; if (n.insecure) s += ', skip-cert-verify=true'; }
    return s;
  }
  if (n.type === 'trojan') {
    let s = nm + ' = trojan, ' + n.server + ', ' + n.port + ', password=' + n.password;
    if (n.net === 'ws') { s += ', ws=true, ws-path=' + (n.path || '/'); if (n.host) s += ', ws-headers=Host:' + n.host; }
    s += ', tls=true';
    if (n.sni) s += ', sni=' + n.sni;
    if (n.insecure) s += ', skip-cert-verify=true';
    return s;
  }
  if (n.type === 'ss') return nm + ' = ss, ' + n.server + ', ' + n.port + ', encrypt-method=' + n.method + ', password=' + n.password;
  if (n.type === 'socks5') return nm + ' = socks5, ' + n.server + ', ' + n.port + (kv.length ? ', ' + kv.join(', ') : '');
  if (n.type === 'http') return nm + ' = http, ' + n.server + ', ' + n.port + (kv.length ? ', ' + kv.join(', ') : '');
  return null;
}
function emitSurge(nodes) {
  const lines = [], skipped = [], names = [];
  nodes.forEach(n => {
    const l = surgeLine(n);
    if (!l) { skipped.push('Surge 不支持：' + (n.name || n.server)); return; }
    let nm = cleanName(n), k = 2;
    while (names.includes(nm)) nm = cleanName(n) + '-' + (k++);
    names.push(nm);
    lines.push(l.replace(/^[^=]+(?= = )/, nm));
  });
  if (!lines.length) return { content: '', skipped };
  return { content: '[General]\nloglevel = notify\n[Proxy]\n' + lines.join('\n') +
    '\n[Proxy Group]\nPROXY = select, ' + names.join(', ') + '\n[Rule]\nFINAL,PROXY\n', skipped };
}
function qxLine(n) {
  const nm = cleanName(n);
  if (n.type === 'vmess') {
    let s = 'vmess=' + n.server + ':' + n.port + ', method=' + (n.cipher === 'auto' ? 'none' : n.cipher) + ', password=' + n.uuid;
    if (n.net === 'ws') { s += ', obfs=' + (n.tls ? 'wss' : 'ws'); if (n.host) s += ', obfs-host=' + n.host; if (n.path) s += ', obfs-uri=' + n.path; }
    if (n.tls && !n.insecure) s += ', tls-verification=true';
    if (n.tls && n.insecure) s += ', tls-verification=false';
    return s + ', tag=' + nm;
  }
  if (n.type === 'trojan') {
    let s = 'trojan=' + n.server + ':' + n.port + ', password=' + n.password + ', over-tls=true';
    if (n.sni) s += ', tls-host=' + n.sni;
    s += n.insecure ? ', tls-verification=false' : ', tls-verification=true';
    return s + ', tag=' + nm;
  }
  if (n.type === 'ss') {
    let s = 'shadowsocks=' + n.server + ':' + n.port + ', method=' + n.method + ', password=' + n.password;
    if (n.plugin) {
      const parts = n.plugin.split(';');
      parts.slice(1).forEach(kv => {
        const i = kv.indexOf('=');
        if (i >= 0) {
          const k = kv.slice(0, i), v = kv.slice(i + 1);
          if (k === 'obfs') s += ', obfs=' + v;
          if (k === 'obfs-host') s += ', obfs-host=' + v;
        }
      });
    }
    return s + ', udp-relay=true, tag=' + nm;
  }
  if (n.type === 'socks5') {
    let s = 'socks5=' + n.server + ':' + n.port;
    if (n.username) s += ', username=' + n.username;
    if (n.password) s += ', password=' + n.password;
    return s + ', tag=' + nm;
  }
  if (n.type === 'http') {
    let s = 'http=' + n.server + ':' + n.port;
    if (n.username) s += ', username=' + n.username;
    if (n.password) s += ', password=' + n.password;
    return s + ', tag=' + nm;
  }
  return null;
}
function emitQx(nodes) {
  const lines = [], skipped = [];
  nodes.forEach(n => {
    const l = qxLine(n);
    if (!l) { skipped.push('Quantumult X 不支持：' + (n.name || n.server)); return; }
    lines.push(l);
  });
  if (!lines.length) return { content: '', skipped };
  const tags = lines.map(l => { const m = l.match(/tag=(.*)$/); return m ? m[1] : ''; }).filter(Boolean);
  return { content: '[server_local]\n' + lines.join('\n') +
    '\n[policy]\nPROXY = select, ' + tags.join(', ') + '\n', skipped };
}
function loonLine(n) {
  const nm = cleanName(n);
  if (n.type === 'vless') {
    let s = nm + ' = vless, ' + n.server + ', ' + n.port + ', username=' + n.uuid;
    if (n.flow) s += ', flow=' + n.flow;
    if (n.net === 'ws') { s += ', ws=true, ws-path=' + (n.path || '/'); if (n.host) s += ', ws-headers=Host:' + n.host; }
    if (n.tls) { s += ', tls=true'; if (n.sni) s += ', sni=' + n.sni; if (n.insecure) s += ', skip-cert-verify=true'; }
    return s;
  }
  if (n.type === 'vmess') {
    let s = nm + ' = vmess, ' + n.server + ', ' + n.port + ', username=' + n.uuid;
    if (n.net === 'ws') { s += ', ws=true, ws-path=' + (n.path || '/'); if (n.host) s += ', ws-headers=Host:' + n.host; }
    if (n.tls) { s += ', tls=true'; if (n.sni) s += ', sni=' + n.sni; if (n.insecure) s += ', skip-cert-verify=true'; }
    return s;
  }
  if (n.type === 'trojan') {
    let s = nm + ' = trojan, ' + n.server + ', ' + n.port + ', password=' + n.password;
    if (n.net === 'ws') { s += ', ws=true, ws-path=' + (n.path || '/'); if (n.host) s += ', ws-headers=Host:' + n.host; }
    s += ', tls=true';
    if (n.sni) s += ', sni=' + n.sni;
    if (n.insecure) s += ', skip-cert-verify=true';
    return s;
  }
  if (n.type === 'ss') return nm + ' = ss, ' + n.server + ', ' + n.port + ', encrypt-method=' + n.method + ', password=' + n.password;
  if (n.type === 'socks5') {
    let s = nm + ' = socks5, ' + n.server + ', ' + n.port;
    if (n.username) s += ', username=' + n.username;
    if (n.password) s += ', password=' + n.password;
    return s;
  }
  if (n.type === 'http') {
    let s = nm + ' = http, ' + n.server + ', ' + n.port;
    if (n.username) s += ', username=' + n.username;
    if (n.password) s += ', password=' + n.password;
    return s;
  }
  return null;
}
function emitLoon(nodes) {
  const lines = [], skipped = [], names = [];
  nodes.forEach(n => {
    const l = loonLine(n);
    if (!l) { skipped.push('Loon 不支持：' + (n.name || n.server)); return; }
    let nm = cleanName(n), k = 2;
    while (names.includes(nm)) nm = cleanName(n) + '-' + (k++);
    names.push(nm);
    lines.push(l.replace(/^[^=]+(?= = )/, nm));
  });
  if (!lines.length) return { content: '', skipped };
  return { content: '[General]\n[Proxy]\n' + lines.join('\n') +
    '\n[Proxy Group]\nPROXY = select, ' + names.join(', ') + '\n[Rule]\nFINAL,PROXY\n', skipped };
}

module.exports = { parseNodes: parseNodes, emitFormat: emitFormat };
