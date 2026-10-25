'use strict';
// node2sub 自适应订阅转换服务：无状态，只负责按客户端身份实时转格式。
// 节点文件本身仍放在你自己的 GitHub 仓库（走 jsDelivr），本服务不存任何节点。
// 用法：GET /sub?src=<节点文件URL>&target=<可选：clash|singbox|surge|qx|loon|plain|base64>
// 不传 target 时按 User-Agent 识别：Clash/Mihomo/Stash -> clash，sing-box -> singbox，
// Surge -> surge，Quantumult X -> qx，Loon -> loon，其他一律按 Base64 订阅返回。
// 运行：PORT=18081 node server.js

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

if (typeof btoa === 'undefined') global.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
if (typeof atob === 'undefined') global.atob = (s) => Buffer.from(s, 'base64').toString('binary');

const { parseNodes, emitFormat } = require('./converters.js');

function targetFromUA(ua) {
  ua = (ua || '').toLowerCase();
  if (ua.includes('clash') || ua.includes('mihomo') || ua.includes('stash')) return 'clash';
  if (ua.includes('sing-box') || ua.includes('singbox')) return 'singbox';
  if (ua.includes('surge')) return 'surge';
  if (ua.includes('quantumult')) return 'qx';
  if (ua.includes('loon')) return 'loon';
  return 'base64';
}

function fetchText(url, redirects) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https:') ? https : http;
    const req = lib.get(url, { headers: { 'User-Agent': 'node2sub-converter' }, timeout: 15000 }, (res) => {
      const code = res.statusCode;
      if ((code === 301 || code === 302 || code === 307 || code === 308) && res.headers.location && redirects > 0) {
        fetchText(new URL(res.headers.location, url).toString(), redirects - 1).then(resolve, reject);
        return;
      }
      if (code !== 200) { reject(new Error('HTTP ' + code)); return; }
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve(data));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/' || u.pathname === '/index.html') {
    try {
      const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch (e) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('tool page not found');
    }
    return;
  }
  if (u.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }
  if (u.pathname !== '/sub') {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('usage: /sub?src=<node-file-url>&target=clash|singbox|surge|qx|loon|plain|base64');
    return;
  }
  const src = u.searchParams.get('src');
  if (!src) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('missing src');
    return;
  }
  const target = u.searchParams.get('target') || targetFromUA(req.headers['user-agent'] || '');
  try {
    const text = await fetchText(src, 3);
    let body;
    if (target === 'plain') {
      body = text.trim() + '\n';
    } else if (target === 'base64') {
      body = Buffer.from(text.trim() + '\n', 'utf8').toString('base64') + '\n';
    } else {
      const parsed = parseNodes(text);
      const out = emitFormat(target, parsed.nodes);
      if (!out.content) {
        res.writeHead(422, { 'Content-Type': 'text/plain' });
        res.end('no convertible nodes');
        return;
      }
      body = out.content;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(body);
  } catch (e) {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('fetch/convert failed: ' + e.message);
  }
});

const port = process.env.PORT || 18081;
server.listen(port, '0.0.0.0', () => {
  console.log('node2sub converter listening on ' + port);
});
