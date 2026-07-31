const express = require('express');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');

const app = express();
const PORT = process.env.PORT || 4000;
const TIMEOUT = 12000;

app.use(express.static(path.join(__dirname)));

function normalizeUrl(input) {
  let url = input.trim();
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  const parsed = new URL(url);
  if (!parsed.hostname) throw new Error('URL inválida');
  return parsed;
}

function request(opts) {
  return new Promise((resolve) => {
    const mod = opts.protocol === 'http:' ? http : https;
    const req = mod.request(opts, (res) => {
      const body = [];
      res.on('data', (c) => body.push(c));
      res.on('end', () => resolve({ res, body: Buffer.concat(body).toString() }));
    });
    req.setTimeout(TIMEOUT, () => req.destroy(new Error('timeout')));
    req.on('error', (err) => resolve({ err }));
    req.end();
  });
}

async function fetchHtml(parsed) {
  const { res, body, err } = await request({
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port,
    path: parsed.pathname + parsed.search,
    method: 'GET',
    headers: {
      'User-Agent': 'Mozilla/5.0 (WebSecAuditor/1.0)',
      Accept: 'text/html,application/xhtml+xml',
    },
    rejectUnauthorized: true,
  });
  if (err) return { err };
  return { res, body: body || '' };
}

function checkHeaders(res, findings) {
  const h = res.headers;
  const get = (k) => {
    const v = h[k];
    return Array.isArray(v) ? v.join(', ') : v || '';
  };

  if (!get('strict-transport-security')) {
    findings.push({
      cat: 'A05',
      title: 'Falta cabecera HSTS',
      sev: 'alto',
      desc: 'No se envía Strict-Transport-Security. Se recomienda forzar HTTPS mediante HSTS.',
    });
  }
  if (!get('x-frame-options') && !/frame-ancestors/i.test(get('content-security-policy'))) {
    findings.push({
      cat: 'A05',
      title: 'Ausencia de protección anti-clickjacking',
      sev: 'alto',
      desc: 'No se detecta X-Frame-Options ni CSP frame-ancestors. La web podría ser embebida en marcos de terceros.',
    });
  }
  if (!get('x-content-type-options')) {
    findings.push({
      cat: 'A05',
      title: 'Falta X-Content-Type-Options',
      sev: 'medio',
      desc: 'Cabecera ausente: riesgo de MIME sniffing.',
    });
  }
  if (!get('referrer-policy')) {
    findings.push({
      cat: 'A05',
      title: 'Falta Referrer-Policy',
      sev: 'bajo',
      desc: 'No se define qué información se envía al navegar a enlaces externos.',
    });
  }
  if (!get('content-security-policy')) {
    findings.push({
      cat: 'A05',
      title: 'Ausencia de Content-Security-Policy',
      sev: 'alto',
      desc: 'Sin CSP aumenta la exposición a XSS y carga de recursos no autorizados.',
    });
  }

  const server = get('server');
  if (server && server.length > 0) {
    findings.push({
      cat: 'A05',
      title: 'Cabecera Server expone software',
      sev: 'bajo',
      desc: `El servidor revela su identidad: "${server}". Conviene ocultarla o no incluir versiones.`,
    });
  }
  const powered = get('x-powered-by');
  if (powered) {
    findings.push({
      cat: 'A05',
      title: 'X-Powered-By expone tecnología',
      sev: 'bajo',
      desc: `Se revela la tecnología del backend: "${powered}".`,
    });
  }

  const acao = get('access-control-allow-origin');
  if (acao && acao.trim() === '*') {
    findings.push({
      cat: 'A05',
      title: 'CORS demasiado permisivo',
      sev: 'medio',
      desc: 'Access-Control-Allow-Origin está fijado a "*". Cualquier origen puede leer respuestas.',
    });
  }

  const cookies = (res.rawHeaders || []).filter((_, i) => i % 2 === 0 && res.rawHeaders[i].toLowerCase() === 'set-cookie');
  const cookieVals = [];
  for (let i = 0; i < res.rawHeaders.length; i += 2) {
    if (res.rawHeaders[i].toLowerCase() === 'set-cookie') cookieVals.push(res.rawHeaders[i + 1]);
  }
  if (cookieVals.length) {
    const insecure = cookieVals.filter((c) => !/;\s*secure/i.test(c));
    const noHttpOnly = cookieVals.filter((c) => !/;\s*httponly/i.test(c));
    if (insecure.length) {
      findings.push({
        cat: 'A07',
        title: 'Cookies sin atributo Secure',
        sev: 'alto',
        desc: `${insecure.length} cookie(s) pueden transmitirse por HTTP en claro.`,
      });
    }
    if (noHttpOnly.length) {
      findings.push({
        cat: 'A07',
        title: 'Cookies accesibles desde JavaScript',
        sev: 'medio',
        desc: `${noHttpOnly.length} cookie(s) sin HttpOnly: pueden leerse mediante XSS.`,
      });
    }
  } else {
    findings.push({
      cat: 'A07',
      title: 'No se detectan cookies de sesión',
      sev: 'info',
      desc: 'No se observaron cookies. Revisar si la sesión se gestiona de forma segura.',
    });
  }
}

async function checkHttpRedirect(hostname, findings) {
  const { res, err } = await request({
    protocol: 'http:',
    hostname,
    path: '/',
    method: 'HEAD',
    rejectUnauthorized: false,
  });
  if (err) return;
  const location = res.headers.location || '';
  const ok = res.statusCode >= 300 && res.statusCode < 400 && /^https:/i.test(location);
  if (ok) return;
  findings.push({
    cat: 'A02',
    title: 'HTTP no redirige a HTTPS',
    sev: 'alto',
    desc: `HTTP responde con estado ${res.statusCode} sin redirigir a la versión segura (o no responde).`,
  });
}

async function checkRobots(parsed, findings) {
  const robots = new URL('/robots.txt', parsed.origin);
  const { res, body, err } = await request({
    protocol: robots.protocol,
    hostname: robots.hostname,
    path: robots.pathname,
    method: 'GET',
    rejectUnauthorized: true,
  });
  if (err) return;
  if (res.statusCode === 200 && /disallow/i.test(body)) {
    findings.push({
      cat: 'A05',
      title: 'robots.txt revela rutas sensibles',
      sev: 'bajo',
      desc: 'El fichero robots.txt incluye reglas Disallow que pueden delatar directorios o endpoints internos.',
    });
  }
}

function fingerprint(body, findings) {
  const gen = (body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i) || [])[1];
  if (gen) {
    findings.push({
      cat: 'A06',
      title: `Tecnología detectada: ${gen}`,
      sev: 'info',
      desc: 'La plataforma declarada debe mantenerse actualizada para evitar CVEs conocidos.',
    });
  }
  if (/wp-content|wp-includes|wordpress/i.test(body)) {
    findings.push({
      cat: 'A06',
      title: 'Posible instalación WordPress',
      sev: 'info',
      desc: 'WordPress exige mantener core, temas y plugins actualizados y verificar su origen.',
    });
  }
  if (/<form[^>]*action=["'][^"']*(login|admin|wp-login)[^"']*["']/i.test(body)) {
    findings.push({
      cat: 'A07',
      title: 'Formulario de acceso detectado',
      sev: 'info',
      desc: 'Comprobar bloqueo por fuerza bruta, contraseñas robustas y caducidad de sesiones.',
    });
  }
  if (/(id|user|file|path|page|url|redirect)=\d+/i.test(body)) {
    findings.push({
      cat: 'A01',
      title: 'Parámetros en la URL (posible IDOR)',
      sev: 'medio',
      desc: 'Se observan parámetros numéricos en enlaces. Verificar que el control de acceso valide cada recurso.',
    });
  }
}

function computeScore(findings) {
  const weights = { critico: 10, alto: 6, medio: 3, bajo: 1, info: 0 };
  const total = findings.reduce((s, f) => s + (weights[f.sev] || 0), 0);
  const max = findings.length * 10;
  const score = max ? Math.max(0, Math.round(100 - (total / max) * 100)) : 100;
  return score;
}

async function scanTarget(rawUrl) {
  const parsed = normalizeUrl(rawUrl);
  const findings = [];

  const { res, body, err } = await fetchHtml(parsed);
  if (err) {
    findings.push({
      cat: 'A02',
      title: 'No se pudo conectar por HTTPS',
      sev: 'critico',
      desc: err.message,
    });
    return { url: rawUrl, score: 0, findings };
  }

  if (res.statusCode >= 500) {
    findings.push({
      cat: 'A05',
      title: 'Error de servidor expuesto',
      sev: 'alto',
      desc: `La web responde con estado ${res.statusCode}. Asegurarse de no mostrar trazas internas.`,
    });
  }

  checkHeaders(res, findings);
  await checkHttpRedirect(parsed.hostname, findings);
  await checkRobots(parsed, findings);
  fingerprint(body, findings);

  const meta = { httpStatus: res.statusCode, contentType: res.headers['content-type'] || 'n/a', bodyLength: body.length };
  return { url: parsed.href, score: computeScore(findings), findings, meta };
}

app.get('/api/scan', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ ok: false, error: 'Parámetro "url" requerido' });
  try {
    const result = await scanTarget(target);
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.get('/api/ping', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Landing OWASP en http://localhost:${PORT}`));
