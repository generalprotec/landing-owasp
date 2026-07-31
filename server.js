const express = require('express');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const dns = require('node:dns').promises;
const { generateReport } = require('./report');

const app = express();
app.use(express.json({ limit: '2mb' }));
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

function extractTaxId(text) {
  const found = new Set();
  const re = /(?<![0-9A-Z])([A-HJ-NP-SUVW][0-9]{7}[0-9A-J]|[XYZ][0-9]{7}[A-Z0-9]|[0-9]{8}[A-Z])(?![0-9])/g;
  let m;
  while ((m = re.exec(text))) found.add(m[1].toUpperCase());
  if (found.size) return [...found];
  const labeled = text.match(/(?:NIF|CIF|N\.I\.F|C\.I\.F|VAT)[:.\s]*([A-HJ-NP-SUVW][0-9]{7}[0-9A-J]|[XYZ0-9][0-9]{7}[A-Z0-9])/i);
  if (labeled) return [labeled[1].toUpperCase()];
  return [];
}

const PROVINCES = ['Álava','Albacete','Alicante','Almería','Asturias','Ávila','Badajoz','Barcelona','Burgos','Cáceres','Cádiz','Cantabria','Castellón','Ceuta','Ciudad Real','Córdoba','Cuenca','Girona','Granada','Guadalajara','Guipúzcoa','Huelva','Huesca','Illes Balears','Jaén','La Coruña','La Rioja','Las Palmas','León','Lleida','Lugo','Madrid','Málaga','Melilla','Murcia','Navarra','Ourense','Palencia','Pontevedra','Salamanca','Santa Cruz de Tenerife','Segovia','Sevilla','Soria','Tarragona','Teruel','Toledo','Valencia','Valladolid','Vizcaya','Zamora','Zaragoza'];

function extractAddress(text) {
  const addresses = new Set();
  const streetRe = /(?:C\/|Calle|Avenida|Avda|Av\.|Plaza|Pl\.|Paseo|P\.?º|Camino|Carretera|Polígono|Pol\.|Rúa|Gran Vía|Ctra\.?)\s+[A-Za-zÁÉÍÓÚÑÜáéíóúñü0-9ºª#\/.\- ]{3,70}/gi;
  let m;
  while ((m = streetRe.exec(text))) addresses.add(m[0].trim().replace(/[.,;:]+$/, ''));
  return [...addresses].slice(0, 3);
}

function extractPostalCodeCity(text) {
  const postal = /(?<![0-9])((?:[01][0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-2])\d{3})(?![0-9])/g;
  let m;
  while ((m = postal.exec(text))) {
    const after = text.slice(m.index + 5, m.index + 45).match(/^\s*([A-Za-zÁÉÍÓÚÑÜáéíóúñü]+(?:\s+[A-Za-zÁÉÍÓÚÑÜáéíóúñü]+)?)/);
    if (after && after[1].length >= 3) {
      return { postalCode: m[1], city: after[1] };
    }
  }
  return null;
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

  const locText = ((contactText || '') + ' ' + aboutText + ' ' + allText).slice(0, 20000);
  const addresses = extractAddress(locText);
  const pcCity = extractPostalCodeCity(locText);
  const hasMap = /(google\.com\/maps|maps\.google|embed\?map|goo\.gl\/maps|openstreetmap)/i.test(home.body + extraBodies.join(' '));

  return {
    name: name || null,
    description: description || null,
    sector: detectSector(allText),
    taxId: extractTaxId(allText),
    address: addresses,
    postalCode: pcCity ? pcCity.postalCode : null,
    city: pcCity ? pcCity.city : null,
    hasMap,
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

/* ============ SUPERFICIE DE ATAQUE (vista de un atacante) ============ */

async function lookupHost(name) {
  try {
    return await dns.lookup(name, { all: true });
  } catch (e) {
    return null;
  }
}

function dohQuery(name, type) {
  return new Promise((resolve) => {
    const url = 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(name) + '&type=' + type;
    const req = https.get(url, { timeout: 8000, headers: { accept: 'application/dns-json' } }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => {
        try {
          const j = JSON.parse(d);
          resolve(Array.isArray(j.Answer) ? j.Answer.map((a) => String(a.data).replace(/^"(.*)"$/, '$1')) : []);
        } catch (e) {
          resolve([]);
        }
      });
    });
    req.on('error', () => resolve([]));
    req.on('timeout', () => { req.destroy(); resolve([]); });
  });
}

async function getTxtRecords(name) {
  return dohQuery(name, 'TXT');
}

const COMMON_SUBDOMAINS = [
  'www', 'mail', 'smtp', 'pop', 'imap', 'mx', 'ns1', 'ns2', 'ftp', 'webmail',
  'admin', 'api', 'app', 'dev', 'staging', 'test', 'beta', 'blog', 'shop', 'store',
  'm', 'mobile', 'cdn', 'static', 'assets', 'images', 'portal', 'intranet', 'vpn',
  'owa', 'remote', 'autodiscover', 'docs', 'git', 'jenkins', 'status', 'help', 'support',
];

async function scanSubdomains(domain, findings) {
  const results = [];
  const checks = await Promise.all(
    COMMON_SUBDOMAINS.map(async (sub) => {
      const host = sub + '.' + domain;
      const recs = await lookupHost(host);
      if (!recs) return null;
      return { host, ips: recs.map((r) => r.address).slice(0, 3) };
    })
  );
  for (const r of checks) if (r) results.push(r);

  const ipCounts = new Map();
  for (const r of results) for (const ip of r.ips) ipCounts.set(ip, (ipCounts.get(ip) || 0) + 1);
  const wildcardIp = [...ipCounts.entries()].sort((a, b) => b[1] - a[1])[0];
  const wildcard = results.length > 5 && wildcardIp && wildcardIp[1] / results.length > 0.75;

  if (wildcard) {
    findings.push({
      cat: 'A05',
      title: 'Posible DNS comodín (wildcard)',
      sev: 'bajo',
      desc: 'La mayoría de subdominios resuelven a la misma IP (' + wildcardIp[0] + '), típico de DNS comodín. Imposible enumerar subdominios reales por DNS.',
    });
    return results;
  }

  const interesting = results.filter((r) => /admin|dev|staging|test|vpn|portal|intranet|git|jenkins|owa|api/i.test(r.host));
  if (interesting.length) {
    findings.push({
      cat: 'A05',
      title: 'Subdominios de alto interés expuestos',
      sev: 'medio',
      desc: 'Subdominios con nombres sensibles resolubles: ' + interesting.map((i) => i.host).join(', ') + '. Revisar que no expongan paneles ni entornos internos.',
    });
  }
  return results;
}

const SENSITIVE_PATHS = [
  { p: '/.git/HEAD', ok: /ref:\s*refs\/heads/i, sev: 'critico', label: 'repositorio .git expuesto' },
  { p: '/.git/config', ok: null, sev: 'critico', label: 'configuración .git expuesta' },
  { p: '/.env', ok: null, sev: 'critico', label: 'archivo .env expuesto' },
  { p: '/.env.production', ok: null, sev: 'critico', label: 'archivo .env.production expuesto' },
  { p: '/config.php', ok: null, sev: 'alto', label: 'config.php accesible' },
  { p: '/db.sql', ok: null, sev: 'critico', label: 'posible volcado de base de datos' },
  { p: '/backup.zip', ok: null, sev: 'critico', label: 'posible archivo de respaldo' },
  { p: '/dump.sql', ok: null, sev: 'critico', label: 'posible volcado SQL' },
  { p: '/phpinfo.php', ok: null, sev: 'medio', label: 'phpinfo() accesible' },
  { p: '/server-status', ok: null, sev: 'medio', label: 'estado del servidor accesible' },
  { p: '/server-info', ok: null, sev: 'medio', label: 'información del servidor accesible' },
  { p: '/.htaccess', ok: null, sev: 'bajo', label: '.htaccess accesible' },
  { p: '/wp-login.php', ok: null, sev: 'info', label: 'panel de login WordPress' },
  { p: '/wp-admin/', ok: null, sev: 'info', label: 'panel de administración WordPress' },
  { p: '/admin/', ok: null, sev: 'info', label: 'posible panel de administración' },
  { p: '/login', ok: null, sev: 'info', label: 'página de login' },
  { p: '/api', ok: null, sev: 'info', label: 'endpoint de API' },
  { p: '/swagger', ok: null, sev: 'info', label: 'documentación de API' },
];

async function probeSensitivePaths(parsed, findings) {
  const exposed = [];
  const results = await Promise.all(
    SENSITIVE_PATHS.map(async ({ p, ok, sev, label }) => {
      try {
        const { res, body } = await follow(new URL(p, parsed.origin));
        if (!res) return null;
        const code = res.statusCode;
        const exposedFlag =
          ok ? (code === 200 && ok.test(body)) : code === 200;
        if (exposedFlag && sev !== 'info') {
          return { p, code, sev, label };
        }
        if (code === 200 && sev === 'info') return { p, code, sev: 'info', label };
        if (code === 403) return { p, code, sev: 'info', label: label + ' (protegido)' };
        return null;
      } catch (e) {
        return null;
      }
    })
  );
  for (const r of results) if (r) exposed.push(r);

  const findingsOut = exposed.filter((e) => e.sev !== 'info');
  for (const e of findingsOut) {
    findings.push({
      cat: e.sev === 'critico' ? 'A05' : 'A05',
      title: e.label,
      sev: e.sev,
      desc: e.p + ' responde con HTTP 200.',
    });
  }
  return exposed;
}

async function checkEmailProtection(domain, findings) {
  const [spf, dmarc, dkim] = await Promise.all([
    getTxtRecords(domain),
    getTxtRecords('_dmarc.' + domain),
    Promise.all(['default', 'google', 's1'].map((s) => getTxtRecords(s + '._domainkey.' + domain))),
  ]);

  const spfRec = spf.find((r) => /^v=spf1/i.test(r));
  const dmarcRec = dmarc.find((r) => /^v=DMARC1/i.test(r));
  const dkimRec = dkim.flat().find((r) => /^v=DKIM1/i.test(r));

  if (!spfRec) {
    findings.push({ cat: 'A08', title: 'Sin registro SPF', sev: 'alto', desc: 'Cualquiera puede enviar correos falsificando este dominio (email spoofing).' });
  }
  if (!dmarcRec) {
    findings.push({ cat: 'A08', title: 'Sin registro DMARC', sev: 'alto', desc: 'Sin política DMARC no se protege el dominio frente a phishing corporativo.' });
  } else if (!/p=(reject|quarantine)/i.test(dmarcRec)) {
    findings.push({ cat: 'A08', title: 'Política DMARC débil', sev: 'medio', desc: 'La política DMARC debería ser p=reject o p=quarantine para bloquear correos falsificados.' });
  }
  if (!dkimRec) {
    findings.push({ cat: 'A08', title: 'Sin DKIM detectado', sev: 'medio', desc: 'No se detectaron selectores DKIM habituales. Verificar la firma de correos salientes.' });
  }

  return { spf: spfRec || null, dmarc: dmarcRec || null, dkim: dkimRec || null };
}

function getSslInfo(host) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate();
      if (!cert || !Object.keys(cert).length) { socket.destroy(); return resolve(null); }
      const info = {
        issuer: (cert.issuer && cert.issuer.O) || '—',
        subject: (cert.subject && cert.subject.CN) || '—',
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        san: (cert.subjectaltname || '').split(', ').filter(Boolean),
      };
      socket.destroy();
      resolve(info);
    });
    socket.on('error', () => resolve(null));
    socket.on('timeout', () => { socket.destroy(); resolve(null); });
  });
}

function checkSsl(info, findings) {
  if (!info) {
    findings.push({ cat: 'A02', title: 'No se pudo validar el certificado TLS', sev: 'medio', desc: 'No hay respuesta TLS en el puerto 443.' });
    return;
  }
  const exp = new Date(info.validTo);
  const days = Math.round((exp - Date.now()) / 86400000);
  info.expiresInDays = days;
  if (days < 0) {
    findings.push({ cat: 'A02', title: 'Certificado TLS caducado', sev: 'critico', desc: 'El certificado caducó hace ' + Math.abs(days) + ' días. Expiración: ' + info.validTo + '.' });
  } else if (days < 30) {
    findings.push({ cat: 'A02', title: 'Certificado TLS a punto de caducar', sev: 'medio', desc: 'El certificado caduca en ' + days + ' días (' + info.validTo + ').' });
  }
}

function checkBreach(email) {
  return new Promise((resolve) => {
    const safe = encodeURIComponent(email).replace(/'/g, "\\'");
    const req = https.get('https://api.xposedornot.com/v1/check-email/' + safe, { timeout: 10000 }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => {
        try {
          const json = JSON.parse(d);
          if (json.status === 'success') resolve({ email, breaches: (json.breaches || []).flat() });
          else resolve({ email, breaches: [] });
        } catch (e) {
          resolve({ email, breaches: [], error: true });
        }
      });
    });
    req.on('error', () => resolve({ email, breaches: [], error: true }));
    req.on('timeout', () => { req.destroy(); resolve({ email, breaches: [], error: true }); });
  });
}

const RDAP_REGISTRIES = {
  com: 'https://rdap.verisign.com/com/v1/domain/',
  net: 'https://rdap.verisign.com/net/v1/domain/',
  org: 'https://rdap.publicinterestregistry.org/rdap/domain/',
  es: 'https://rdap.nic.es/domain/',
  info: 'https://rdap.afilias.info/rdap/domain/',
  io: 'https://rdap.identitydigital.services/rdap/domain/',
  cat: 'https://rdap.nic.cat/domain/',
  eu: 'https://rdap.eu/domain/',
};

function parseRdap(j) {
  if (!j || Array.isArray(j) || j.errorCode) return null;
  const events = j.events || [];
  const findEvent = (type) => {
    const e = events.find((x) => (x.eventAction || '').toLowerCase() === type);
    return e ? e.eventDate : null;
  };
  return {
    registrar: (j.entities || []).map((e) => {
      if (!e.vcardArray || !e.vcardArray[1]) return null;
      const fn = e.vcardArray[1].find((r) => r[0] === 'fn');
      return fn ? fn[3] : null;
    }).filter(Boolean).join(', ') || '—',
    created: findEvent('registration'),
    updated: findEvent('last changed'),
    expiration: findEvent('expiration'),
    status: (j.status || []).slice(0, 6).join(', '),
  };
}

function getRdap(domain) {
  return new Promise((resolve) => {
    const tld = domain.split('.').pop();
    const base = RDAP_REGISTRIES[tld] || 'https://rdap.org/domain/';
    const req = https.get(base + encodeURIComponent(domain), { timeout: 10000, headers: { 'User-Agent': 'WebSecAuditor/1.0' } }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => {
        try {
          const j = JSON.parse(d);
          resolve(parseRdap(j));
        } catch (e) {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

function extractEmailDomains(html) {
  const set = new Set();
  const re = /[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
  let m;
  while ((m = re.exec(html))) {
    const d = m[1].toLowerCase().replace(/^www\./, '');
    if (!/\.(png|jpg|jpeg|gif|svg|webp|css|js|woff|ttf)$/i.test(d) && set.size < 10) set.add(d);
  }
  return [...set];
}

async function getMxNs(domain) {
  const [mxAns, nsAns] = await Promise.all([dohQuery(domain, 'MX'), dohQuery(domain, 'NS')]);
  const mx = mxAns.map((v) => v.split(/\s+/).pop().replace(/\.$/, '')).filter(Boolean);
  const ns = nsAns.map((v) => v.replace(/\.$/, '')).filter(Boolean).slice(0, 5);
  return { mx, ns };
}

function detectEmailProvider(mx) {
  if (!mx.length) return 'Sin registros MX (no usa email en este dominio)';
  const joined = mx.join(' ');
  if (/google\.com|googlemail/i.test(joined)) return 'Google Workspace';
  if (/outlook\.com|microsoft\.com|protection\.outlook/i.test(joined)) return 'Microsoft 365';
  if (/amazonaws|amazonses|amazon\.com/i.test(joined)) return 'AWS SES / Amazon';
  if (/zoho/i.test(joined)) return 'Zoho';
  if (/mailgun|mailchimp|sendgrid/i.test(joined)) return 'Servicio de email transaccional';
  const host = mx[0].replace(/^[a-z0-9]+\./, '');
  return 'Servidor propio / ' + host;
}

function baseDomain(host) {
  const parts = host.replace(/^www\./, '').split('.');
  return parts.length > 2 ? parts.slice(-2).join('.') : host;
}

/* ============ OTROS ACTIVOS DE LA EMPRESA ============ */

function detectEmailPattern(emails) {
  if (!emails.length) return null;
  const generic = /^(info|contacto|contact|admin|ventas|hola|hello|noreply|no-reply|no_reply|webmaster|support|soporte|atencion|atencionalcliente|pedidos|compras)$/i;
  const localParts = emails.map((e) => e.split('@')[0]).filter((l) => !generic.test(l));
  if (!localParts.length) return { type: 'Solo correos genéricos', detail: 'No se deduce un patrón de nombres de empleados', samples: emails.slice(0, 5) };
  const dotted = localParts.filter((l) => l.includes('.'));
  const dots = dotted.every((l) => l.split('.').length === 2);
  const type = dotted.length === 0 ? 'Sin separadores (ej. usuario)' : dots ? 'nombre.apellido' : 'Variable';
  const names = dotted.filter((l) => /^[a-z]+\.[a-z]+$/i.test(l)).length;
  const initials = localParts.filter((l) => /^[a-z]\.[a-z]+$/i.test(l) || /^[a-z]{1,2}[0-9]*$/i.test(l)).length;
  const detail = names ? 'Los correos parecen seguir el patrón nombre.apellido, útil para adivinar otros empleados' : initials ? 'Se observan iniciales u identificadores cortos' : 'Formato no uniforme';
  return { type, detail, samples: localParts.slice(0, 6) };
}

const JOB_TECH = [
  'react', 'angular', 'vue', 'node.js', 'nodejs', 'python', 'java', 'php', 'laravel', 'symfony',
  'django', 'ruby', 'golang', 'go ', 'typescript', 'javascript', 'docker', 'kubernetes', 'k8s',
  'aws', 'azure', 'gcp', 'google cloud', 'mysql', 'postgresql', 'postgres', 'mongodb', 'redis',
  'wordpress', 'devops', 'ci/cd', 'linux', 'terraform', 'sap', 'oracle', 'salesforce', 'office 365',
  '.net', 'c#', 'kotlin', 'swift', 'flutter', 'microservicios', 'gitlab', 'jenkins', 'grafana',
];

async function analyzeJobs(parsed, links) {
  const jobLink = links.find((l) =>
    /\/(empleo|empleos|trabaja-con-nosotros|trabaja-con-nosotros|careers|career|jobs|trabaja|vacantes|ofertas-de-empleo|unete|únete)/i.test(l.href) ||
    /(empleo|ofertas de empleo|trabaja con nosotros|trabaja para nosotros|unete al equipo|únete al equipo|carreras)/i.test(l.text)
  );
  if (!jobLink) return null;
  const page = await fetchPage(parsed, jobLink.href);
  if (!page) return null;
  const text = stripTags(page.body).toLowerCase();
  const techs = [...new Set(JOB_TECH.filter((t) => text.includes(t)))];
  return { url: jobLink.href, techs: techs.slice(0, 12) };
}

function findGithub(links) {
  for (const l of links) {
    try {
      const u = new URL(l.href);
      if (!/^github\.com$/i.test(u.hostname)) continue;
      const parts = u.pathname.split('/').filter(Boolean);
      if (!parts[0] || /^(sponsors|features|topics|marketplace|explore|collections|settings|login|signup|about|orgs|search)$/i.test(parts[0])) continue;
      return { org: parts[0], url: 'https://github.com/' + parts[0] };
    } catch (e) {}
  }
  return null;
}

function getGithubOrg(org) {
  return new Promise((resolve) => {
    const req = https.get('https://api.github.com/orgs/' + encodeURIComponent(org), { timeout: 8000, headers: { 'User-Agent': 'WebSecAuditor/1.0', Accept: 'application/vnd.github+json' } }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => {
        try {
          const j = JSON.parse(d);
          if (j.message && !j.public_repos) return resolve(null);
          resolve({ name: j.name || org, repos: j.public_repos, created: j.created_at, blog: j.blog, location: j.location });
        } catch (e) {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

async function getWayback(domain) {
  const base = 'https://web.archive.org/cdx/search/cdx?url=' + encodeURIComponent(domain) + '&output=json&fl=timestamp,statuscode&filter=statuscode:200&collapse=timestamp:6';
  const get = (suffix) => new Promise((resolve) => {
    const req = https.get(base + suffix, { timeout: 15000 }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => {
        try {
          const j = JSON.parse(d);
          resolve(Array.isArray(j) && j.length > 1 ? j[1] : null);
        } catch (e) {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
  const [oldest, newest] = await Promise.all([get('&limit=1'), get('&limit=-1')]);
  return { oldest, newest };
}

async function getSitemap(parsed) {
  const page = await fetchPage(parsed, '/sitemap.xml');
  if (!page || page.res.statusCode !== 200) return null;
  const urls = [...page.body.matchAll(/<loc>([^<]+)<\/loc>/gi)].map((m) => m[1]);
  const interesting = [...new Set(urls.filter((u) => /admin|login|private|intranet|backup|old|dev|test|wp-admin|phpmyadmin|git|\.sql|\.env|api/i.test(u)))].slice(0, 12);
  return { urlCount: urls.length, interesting };
}

function httpJson(url, timeout) {
  return new Promise((resolve) => {
    const req = https.get(url, { timeout, headers: { 'User-Agent': 'Mozilla/5.0 (WebSecAuditor/1.0)', Accept: 'application/json' } }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(d) });
        } catch (e) {
          resolve({ status: res.statusCode, body: null });
        }
      });
    });
    req.on('error', () => resolve({ status: 0, body: null }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: null }); });
  });
}

async function ctViaCertspotter(domain) {
  const { status, body } = await httpJson('https://api.certspotter.com/v1/issuances?domain=' + encodeURIComponent(domain) + '&include_subdomains=true&expand=dns_names', 12000);
  if (status !== 200 || !Array.isArray(body)) return null;
  const names = new Set();
  for (const r of body) {
    for (const n of r.dns_names || []) {
      const nn = String(n).trim().toLowerCase().replace(/^\*\./, '');
      if (nn.endsWith('.' + domain)) names.add(nn);
    }
  }
  return [...names].sort().slice(0, 50);
}

async function ctViaCrt(domain) {
  const { status, body } = await httpJson('https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json', 15000);
  if (status !== 200 || !Array.isArray(body)) return null;
  const names = new Set();
  for (const r of body) {
    for (const n of String(r.name_value || '').split('\n')) {
      const nn = n.trim().toLowerCase().replace(/^\*\./, '');
      if (nn.endsWith('.' + domain)) names.add(nn);
    }
  }
  return [...names].sort().slice(0, 50);
}

async function getCtSubdomains(domain) {
  const fromSpotter = await ctViaCertspotter(domain);
  if (fromSpotter !== null) return fromSpotter;
  return (await ctViaCrt(domain)) || [];
}

async function analyzeAttackSurface(rawUrl) {
  const parsed = normalizeUrl(rawUrl);
  const domain = parsed.hostname.replace(/^www\./, '');
  const findings = [];
  const surface = { domain };

  const [subdomains, exposed, ssl, mxns] = await Promise.all([
    scanSubdomains(domain, findings),
    probeSensitivePaths(parsed, findings),
    getSslInfo(parsed.hostname),
    getMxNs(domain),
  ]);

  surface.subdomains = subdomains;
  surface.exposed = exposed;
  surface.mx = mxns.mx;
  surface.ns = mxns.ns;
  surface.emailProvider = detectEmailProvider(mxns.mx);
  checkSsl(ssl, findings);
  surface.ssl = ssl;

  if (mxns.mx.length) {
    const mxBase = baseDomain(mxns.mx[0]);
    if (!/google|microsoft|outlook|zoho|amazonaws|amazonses|mailgun|sendgrid/i.test(mxns.mx.join(' '))) {
      findings.push({
        cat: 'A05',
        title: 'Email gestionado en infraestructura propia',
        sev: 'bajo',
        desc: 'Los registros MX apuntan a servidores propios (' + mxBase + '). El atacante intentará atacar el servidor de correo directamente.',
      });
    }
  }

  /* Dominios relacionados: desde emails de la web y del registro MX */
  let emails = [];
  let homeHtml = '';
  try {
    const home = await fetchPage(parsed, '/');
    if (home) {
      homeHtml = home.body;
      const set = new Set();
      const re = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      let m;
      while ((m = re.exec(home.body))) {
        const e = m[0].toLowerCase();
        if (/\.(png|jpg|jpeg|gif|svg|webp|css|js|woff|ttf)$/i.test(e)) continue;
        if (set.size < 8) set.add(e);
      }
      emails = [...set];
    }
  } catch (e) {}

  surface.emails = emails;
  surface.emailPattern = detectEmailPattern(emails);
  surface.breaches = await Promise.all(emails.slice(0, 5).map(checkBreach));

  const homeLinks = homeHtml ? extractLinks(homeHtml, parsed) : [];

  const [jobs, github, wayback, sitemap, crt] = await Promise.all([
    homeLinks.length ? analyzeJobs(parsed, homeLinks) : null,
    (async () => {
      const gh = findGithub(homeLinks);
      if (!gh) return null;
      const org = await getGithubOrg(gh.org);
      return { ...gh, info: org };
    })(),
    getWayback(domain),
    getSitemap(parsed),
    getCtSubdomains(domain),
  ]);

  surface.jobs = jobs;
  surface.github = github;
  surface.wayback = wayback;
  surface.sitemap = sitemap;
  surface.ctSubdomains = crt;

  if (jobs && jobs.techs && jobs.techs.length) {
    findings.push({
      cat: 'A06',
      title: 'Ofertas de empleo revelan el stack tecnológico',
      sev: 'medio',
      desc: 'La página de empleo (' + jobs.url + ') menciona: ' + jobs.techs.join(', ') + '. Un atacante usará esto para buscar CVEs concretos.',
    });
  }
  if (github && github.info) {
    findings.push({
      cat: 'A08',
      title: 'Organización de GitHub con repositorios públicos',
      sev: 'bajo',
      desc: github.org + ' tiene ' + github.info.repos + ' repos públicos en ' + github.url + '. Revisar que no filtren secretos ni código interno.',
    });
  }
  if (wayback && (wayback.oldest || wayback.newest)) {
    findings.push({
      cat: 'A05',
      title: 'Versiones históricas de la web archivadas',
      sev: 'bajo',
      desc: 'Existen copias de la web en Wayback Machine' + (wayback.oldest ? ' desde ' + wayback.oldest[0] : '') + (wayback.newest ? ' hasta ' + wayback.newest[0] : '') + '. Configuraciones o archivos antiguos podrían recuperarse.',
    });
  }
  if (sitemap && sitemap.interesting && sitemap.interesting.length) {
    findings.push({
      cat: 'A05',
      title: 'Sitemap revela rutas sensibles',
      sev: 'medio',
      desc: 'El sitemap.xml contiene URLs potencialmente sensibles: ' + sitemap.interesting.slice(0, 6).join(', '),
    });
  }
  if (crt && crt.length) {
    const sens = crt.filter((s) => /admin|dev|staging|test|vpn|portal|intranet|git|jenkins|owa|api|mail|ftp/i.test(s));
    if (sens.length) {
      findings.push({
        cat: 'A05',
        title: 'Subdominios sensibles en certificados (CT logs)',
        sev: 'medio',
        desc: 'Los certificados públicos revelan ' + sens.length + ' subdominios de interés: ' + sens.slice(0, 8).join(', '),
      });
    }
  }

  const related = new Set(extractEmailDomains(emails.join(' ')));
  if (mxns.mx.length && /^[a-z0-9.-]+$/.test(mxns.mx[0])) {
    const mb = baseDomain(mxns.mx[0]);
    if (!/^(google|googlemail|gmail|outlook|microsoft|zoho|mailgun|sendgrid|amazonaws|amazonses|poczta|secureserver|hostgator|dreamhost|registrar\.)/i.test(mb)) related.add(mb);
  }
  related.delete(domain);
  surface.relatedDomains = [...related].slice(0, 5);

  /* Protección de email del dominio principal + dominios relacionados */
  try {
    surface.emailProtection = await checkEmailProtection(domain, findings);
  } catch (e) {
    surface.emailProtection = null;
  }

  surface.relatedEmailProtection = {};
  for (const rd of surface.relatedDomains.slice(0, 3)) {
    try {
      const prot = await checkEmailProtection(rd, []);
      surface.relatedEmailProtection[rd] = prot;
    } catch (e) {
      surface.relatedEmailProtection[rd] = null;
    }
  }

  /* Datos del dominio (RDAP) */
  try {
    surface.rdap = await getRdap(domain);
  } catch (e) {
    surface.rdap = null;
  }
  if (surface.rdap && surface.rdap.created) {
    const ageDays = (Date.now() - new Date(surface.rdap.created).getTime()) / 86400000;
    surface.domainAgeDays = Math.round(ageDays);
    if (ageDays < 180) {
      findings.push({
        cat: 'A05',
        title: 'Dominio registrado hace poco',
        sev: 'bajo',
        desc: 'El dominio se registró hace ' + Math.round(ageDays) + ' días. Los dominios recientes son indicador de phishing o infraestructura efímera.',
      });
    }
  }

  surface.findings = findings;
  return surface;
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

app.get('/api/osint', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ ok: false, error: 'Parámetro "url" requerido' });
  try {
    const surface = await analyzeAttackSurface(target);
    res.json({ ok: true, surface });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.post('/api/report', async (req, res) => {
  const { url, scan, company, surface } = req.body || {};
  if (!url) return res.status(400).json({ ok: false, error: 'Falta la URL del objetivo' });
  try {
    const buf = await generateReport({ url, scan, company, surface });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="informe-seguridad-' + Date.now() + '.pdf"');
    res.send(buf);
  } catch (e) {
    console.error('Report error:', e);
    res.status(500).json({ ok: false, error: 'Error al generar el PDF: ' + e.message });
  }
});

app.get('/api/ping', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Landing OWASP en http://localhost:${PORT}`));
