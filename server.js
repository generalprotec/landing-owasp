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

async function follow(parsed, redirects = 0) {
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
  if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirects < 5) {
    try {
      const next = new URL(res.headers.location, parsed.origin);
      return follow(next, redirects + 1);
    } catch (e) {
      return { res, body: body || '' };
    }
  }
  return { res, body: body || '' };
}

async function fetchHtml(parsed) {
  return follow(parsed);
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

/* ============ ANÁLISIS DE EMPRESA ============ */

function stripTags(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&aacute;/g, 'á').replace(/&eacute;/g, 'é').replace(/&iacute;/g, 'í')
    .replace(/&oacute;/g, 'ó').replace(/&uacute;/g, 'ú').replace(/&ntilde;/g, 'ñ')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractLinks(html, base) {
  const links = [];
  const re = /<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html))) {
    links.push({ href: m[1], text: stripTags(m[2]) });
  }
  return links;
}

const ABOUT_RE = /\/(about|acerca-de|acerca|nosotros|quienes-somos|quienes_somos|nuestra-empresa|sobre-nosotros|conocenos|conocenos|historia|la-empresa|team|equipo|empresa|quienes)/i;
const CONTACT_RE = /\/(contact|contacto|contactanos|contactanos|ubicacion|localizacion|encuentranos)/i;
const LEGAL_RE = /(privacy|politica-de-privacidad|politica-privacidad|privacidad|aviso-legal|terminos|terms|legal)/i;

function classifyLink(link) {
  const href = link.href.toLowerCase();
  const text = link.text.toLowerCase();
  if (ABOUT_RE.test(href) || ABOUT_RE.test(text)) return 'about';
  if (CONTACT_RE.test(href) || CONTACT_RE.test(text)) return 'contact';
  if (LEGAL_RE.test(href) || LEGAL_RE.test(text)) return 'legal';
  return null;
}

function detectSocial(links) {
  const social = {};
  const map = {
    facebook: /(^|\.)facebook\.com/i,
    instagram: /(^|\.)instagram\.com/i,
    x: /(^|\.)(twitter|x)\.com/i,
    linkedin: /(^|\.)linkedin\.com/i,
    tiktok: /(^|\.)tiktok\.com/i,
    youtube: /(^|\.)youtube\.com/i,
    whatsapp: /wa\.me|whatsapp\.com/i,
  };
  for (const l of links) {
    for (const [name, re] of Object.entries(map)) {
      if (!social[name] && re.test(l.href)) social[name] = l.href;
    }
  }
  return social;
}

const SECTORS = [
  { name: 'Comercio electrónico / Retail', kw: ['tienda', 'compra', 'productos', 'carrito', 'envío', 'ecommerce', 'pedido', 'ofertas', 'catalogo'] },
  { name: 'Tecnología / Software', kw: ['software', 'desarrollo', 'aplicación', 'aplicaciones', 'digital', 'cloud', 'inteligencia artificial', 'api', 'plataforma', 'programación'] },
  { name: 'Salud / Bienestar', kw: ['salud', 'clínica', 'médico', 'médicos', 'hospital', 'farmacia', 'terapia', 'bienestar', 'nutrición', 'dentista'] },
  { name: 'Educación', kw: ['educación', 'curso', 'cursos', 'formación', 'academia', 'aprender', 'universidad', 'máster', 'beca', 'clases'] },
  { name: 'Hostelería / Restauración', kw: ['restaurante', 'cafetería', 'menú', 'cocina', 'chef', 'gastronomía', 'bar', 'hotel', 'comida'] },
  { name: 'Construcción / Reformas', kw: ['construcción', 'reformas', 'obra', 'arquitectura', 'albañilería', 'instalaciones', 'pintura', 'fontanería'] },
  { name: 'Finanzas / Seguros', kw: ['finanzas', 'seguro', 'seguros', 'banco', 'inversión', 'préstamo', 'crédito', 'contabilidad', 'asesor financiero'] },
  { name: 'Legal / Asesoría', kw: ['abogado', 'abogados', 'bufete', 'asesoría', 'legal', 'notaría', 'laboral', 'fiscal', 'derecho'] },
  { name: 'Turismo / Viajes', kw: ['viaje', 'viajes', 'turismo', 'vacaciones', 'vuelo', 'reserva', 'excursión', 'agencia de viajes'] },
  { name: 'Inmobiliaria', kw: ['inmobiliaria', 'propiedad', 'propiedades', 'piso', 'vivienda', 'alquiler', 'inmueble', 'hipoteca', 'venta de casas'] },
  { name: 'Transporte / Logística', kw: ['transporte', 'logística', 'envío', 'mensajería', 'flota', 'paquetería', 'reparto', 'delivery'] },
  { name: 'Marketing / Comunicación', kw: ['marketing', 'publicidad', 'agencia', 'branding', 'seo', 'diseño', 'comunicación', 'redes sociales'] },
  { name: 'Energía / Medio ambiente', kw: ['energía', 'solar', 'renovable', 'reciclaje', 'sostenible', 'medio ambiente', 'placas'] },
];

function detectSector(text) {
  const lower = text.toLowerCase();
  const scores = SECTORS.map((s) => ({ name: s.name, count: s.kw.reduce((n, k) => (lower.includes(k) ? n + 1 : n), 0) }));
  const found = scores.filter((s) => s.count > 0).sort((a, b) => b.count - a.count);
  return found.slice(0, 3);
}

function extractEmails(html) {
  const set = new Set();
  const re = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  let m;
  while ((m = re.exec(html))) {
    const e = m[0].toLowerCase().replace(/\.(png|jpg|jpeg|gif|webp|svg)$/i, '');
    if (/\.(png|jpg|jpeg|gif|webp|svg|css|js|woff|ttf)$/i.test(e)) continue;
    if (/example|sentry|wixpress|@2x|noreply|your@|email@|@tu/i.test(e)) continue;
    if (set.size < 5) set.add(e);
  }
  return [...set];
}

function extractPhones(html) {
  const set = new Set();
  const re = /(?:\+?\d{1,3}[ -]?)?(?:\(\d{2,4}\)[ -]?)?\d{3,4}[-.\s]?\d{3,4}(?:[-.\s]?\d{2,4})?/g;
  let m;
  while ((m = re.exec(html))) {
    const p = m[0].trim();
    const digits = p.replace(/\D/g, '');
    if (digits.length < 9 || digits.length > 13) continue;
    if (/(\d)\1{4,}/.test(digits)) continue;
    if (set.size < 4) set.add(p);
  }
  return [...set];
}

async function fetchPage(parsed, path) {
  const next = new URL(path, parsed.origin);
  const { res, body, err } = await follow(next);
  if (err) return null;
  return { res, body: body || '' };
}

async function analyzeCompany(rawUrl) {
  const parsed = normalizeUrl(rawUrl);
  const home = await fetchPage(parsed, parsed.pathname + parsed.search);
  if (!home) return { error: 'No se pudo conectar con la web' };

  const links = extractLinks(home.body, parsed);
  const mainHost = parsed.hostname.replace(/^www\./, '');
  const absLinks = links
    .map((l) => {
      try {
        const u = new URL(l.href, parsed.origin);
        const host = u.hostname.replace(/^www\./, '');
        if (host === mainHost || host.endsWith('.' + mainHost)) return { ...l, href: u.pathname + u.search };
      } catch (e) {}
      return null;
    })
    .filter(Boolean);

  const about = absLinks.filter((l) => classifyLink(l) === 'about').slice(0, 1);
  const contact = absLinks.filter((l) => classifyLink(l) === 'contact').slice(0, 1);
  const legal = absLinks.filter((l) => classifyLink(l) === 'legal').slice(0, 4);

  const pagesToFetch = [...about, ...contact].slice(0, 2);
  const extraBodies = [];
  for (const l of pagesToFetch) {
    const pg = await fetchPage(parsed, l.href);
    if (pg) extraBodies.push(pg.body);
  }

  const allHtml = [home.body, ...extraBodies].join(' ');
  const allText = stripTags(allHtml);

  const name = (home.body.match(/<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']+)["']/i) || [])[1]
    || (home.body.match(/<meta[^>]+name=["']application-name["'][^>]+content=["']([^"']+)["']/i) || [])[1]
    || (home.body.match(/<title[^>]*>([^<]+)<\/title>/i) || [])[1]?.replace(/\s*[|\-–—].*$/i, '').trim()
    || parsed.hostname;

  const description = (home.body.match(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["']/i) || [])[1]
    || (home.body.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i) || [])[1]
    || '';

  const aboutText = about.length ? stripTags(extraBodies[0] || '') : null;
  const contactText = contact.length ? stripTags(extraBodies[pagesToFetch.indexOf(contact[0])] || '') : null;

  return {
    name: name || null,
    description: description || null,
    sector: detectSector(allText),
    emails: extractEmails(allHtml),
    phones: extractPhones((contactText || '') + ' ' + allText),
    social: detectSocial(links),
    hasAbout: about.length > 0,
    aboutUrl: about.length ? about[0].href : null,
    aboutExcerpt: aboutText ? aboutText.slice(0, 400) : null,
    hasContact: contact.length > 0,
    contactUrl: contact.length ? contact[0].href : null,
    legalPages: legal.map((l) => l.href),
    pagesAnalyzed: [...about, ...contact].map((l) => l.href),
  };
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

app.get('/api/company', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ ok: false, error: 'Parámetro "url" requerido' });
  try {
    const result = await analyzeCompany(target);
    if (result.error) return res.status(502).json({ ok: false, error: result.error });
    res.json({ ok: true, company: result });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.get('/api/ping', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Landing OWASP en http://localhost:${PORT}`));
