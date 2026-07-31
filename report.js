const PDFDocument = require('pdfkit');

function clean(text) {
  if (text == null) return '—';
  return String(text)
    .replace(/[\u{1F000}-\u{1FFFF}]/gu, '')
    .replace(/[\u2600-\u27BF]/gu, '')
    .replace(/[\uFE00-\uFE0F]/gu, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function sevColor(sev) {
  switch (sev) {
    case 'critico': return '#e03131';
    case 'alto': return '#e8590c';
    case 'medio': return '#f08c00';
    case 'bajo': return '#1971c2';
    default: return '#868e96';
  }
}

function sevLabel(sev) {
  return { critico: 'Crítico', alto: 'Alto', medio: 'Medio', bajo: 'Bajo', info: 'Info' }[sev] || sev;
}

function sectionTitle(doc, text) {
  doc.moveDown(0.5);
  doc.font('Helvetica-Bold').fontSize(13).fillColor('#1971c2').text(text);
  doc.moveDown(0.2);
  doc.moveTo(40, doc.y).lineTo(570, doc.y).strokeColor('#adb5bd').lineWidth(0.5).stroke();
  doc.moveDown(0.4);
}

function generateReport({ url, scan, company, surface, date }) {
  const doc = new PDFDocument({ size: 'A4', margin: 40, bufferPages: true });
  const chunks = [];
  doc.on('data', (c) => chunks.push(c));

  const now = new Date(date || Date.now()).toLocaleString('es-ES');

  doc.rect(0, 0, 595, 130).fill('#0b1020');
  doc.fill('#ffffff').font('Helvetica-Bold').fontSize(22).text('WebSec Auditor', 40, 30);
  doc.fill('#93a1c8').font('Helvetica').fontSize(11).text('Informe de análisis de seguridad web · OWASP Top 10 (2021)', 40, 62);
  doc.fill('#93a1c8').fontSize(9).text('Generado: ' + now, 40, 80);
  doc.fill('#c8d3f5').fontSize(12).text('Objetivo: ' + clean(url), 40, 100);

  doc.y = 150;

  /* ===== Resumen ===== */
  if (scan) {
    sectionTitle(doc, 'Resumen del análisis');
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#212529').text('Puntuación de seguridad: ' + scan.score + ' / 100');
    doc.font('Helvetica').fontSize(9).fillColor('#495057').text('Hallazgos totales: ' + (scan.findings || []).length + ' · ' + clean(scan.meta && scan.meta.httpStatus ? 'HTTP ' + scan.meta.httpStatus : ''));

    const bySev = {};
    for (const f of scan.findings || []) bySev[f.sev] = (bySev[f.sev] || 0) + 1;
    doc.moveDown(0.3);
    doc.font('Helvetica').fontSize(9).fillColor('#495057')
      .text('Críticos: ' + (bySev.critico || 0) + '   ·   Altos: ' + (bySev.alto || 0) + '   ·   Medios: ' + (bySev.medio || 0) + '   ·   Bajos: ' + (bySev.bajo || 0) + '   ·   Info: ' + (bySev.info || 0));

    sectionTitle(doc, 'Hallazgos de seguridad');
    for (const f of scan.findings || []) {
      doc.font('Helvetica-Bold').fontSize(9).fillColor(sevColor(f.sev)).text('[' + sevLabel(f.sev) + '] ' + f.cat + ' · ' + clean(f.title));
      doc.font('Helvetica').fontSize(8.5).fillColor('#495057').text(clean(f.desc), { indent: 12 });
      doc.moveDown(0.3);
    }
  }

  /* ===== Empresa ===== */
  if (company) {
    sectionTitle(doc, 'Perfil de la empresa');
    const c = company;
    const fields = [
      ['Nombre', clean(c.name)],
      ['Descripción', clean(c.description)],
      ['Sector', (c.sector || []).map((s) => s.name).join(', ')],
      ['Emails', (c.emails || []).join(', ')],
      ['Teléfonos', (c.phones || []).join(', ')],
      ['Redes sociales', Object.entries(c.social || {}).map(([k, v]) => k + ': ' + v).join('\n') || '—'],
      ['Acerca de', clean(c.aboutUrl)],
      ['Contacto', clean(c.contactUrl)],
      ['Páginas legales', (c.legalPages || []).join(', ')],
    ];
    for (const [k, v] of fields) {
      doc.font('Helvetica-Bold').fontSize(9).fillColor('#212529').text(k + ': ', { continued: true });
      doc.font('Helvetica').fontSize(9).fillColor('#495057').text(v || '—');
    }
    if (c.aboutExcerpt) {
      doc.moveDown(0.2);
      doc.font('Helvetica-Oblique').fontSize(8.5).fillColor('#495057').text('Extracto "Acerca de": ' + clean(c.aboutExcerpt) + '…');
    }
  }

  /* ===== Superficie de ataque ===== */
  if (surface) {
    sectionTitle(doc, 'Superficie de ataque');

    doc.font('Helvetica-Bold').fontSize(10).fillColor('#212529').text('Protección de email');
    const ep = surface.emailProtection || {};
    const rows = [
      ['SPF', ep.spf ? 'Configurado: ' + clean(ep.spf) : 'NO CONFIGURADO'],
      ['DMARC', ep.dmarc ? 'Configurado: ' + clean(ep.dmarc) : 'NO CONFIGURADO'],
      ['DKIM', ep.dkim ? 'Detectado' : 'No detectado'],
    ];
    for (const [k, v] of rows) {
      doc.font('Helvetica').fontSize(8.5).fillColor('#495057').text('  • ' + k + ': ' + v);
    }

    if (surface.ssl) {
      doc.moveDown(0.3);
      doc.font('Helvetica-Bold').fontSize(10).fillColor('#212529').text('Certificado TLS');
      doc.font('Helvetica').fontSize(8.5).fillColor('#495057')
        .text('  • Emisor: ' + clean(surface.ssl.issuer))
        .text('  • Dominio: ' + clean(surface.ssl.subject))
        .text('  • Validez: ' + clean(surface.ssl.validFrom) + ' → ' + clean(surface.ssl.validTo))
        .text('  • Caduca en: ' + surface.ssl.expiresInDays + ' días')
        .text('  • SANs: ' + (surface.ssl.san || []).slice(0, 10).join(', '));
    }

    const exposed = (surface.exposed || []).filter((e) => e.sev !== 'info');
    doc.moveDown(0.3);
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#212529').text('Rutas sensibles detectadas (' + exposed.length + ')');
    for (const e of exposed) {
      doc.font('Helvetica').fontSize(8.5).fillColor('#495057').text('  • ' + clean(e.p) + ' → HTTP ' + e.code + ' (' + clean(e.label) + ')');
    }
    if (!exposed.length) doc.font('Helvetica').fontSize(8.5).fillColor('#495057').text('  • No se detectaron rutas sensibles accesibles.');

    doc.moveDown(0.3);
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#212529').text('Subdominios encontrados (' + (surface.subdomains || []).length + ')');
    const subs = (surface.subdomains || []).map((s) => s.host + ' (' + s.ips.join(', ') + ')').join('\n');
    doc.font('Helvetica').fontSize(8.5).fillColor('#495057').text(subs || '  • Ninguno.');

    doc.moveDown(0.3);
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#212529').text('Correos en brechas conocidas');
    const breaches = surface.breaches || [];
    for (const b of breaches) {
      const found = b.breaches && b.breaches.length;
      doc.font('Helvetica').fontSize(8.5).fillColor(found ? '#e03131' : '#37b24d')
        .text('  • ' + clean(b.email) + ': ' + (found ? 'filtrado en ' + b.breaches.length + ' brecha(s)' : 'sin filtraciones conocidas'));
    }

    doc.moveDown(0.3);
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#212529').text('Hallazgos de superficie');
    for (const f of surface.findings || []) {
      doc.font('Helvetica-Bold').fontSize(9).fillColor(sevColor(f.sev)).text('[' + sevLabel(f.sev) + '] ' + f.cat + ' · ' + clean(f.title));
      doc.font('Helvetica').fontSize(8.5).fillColor('#495057').text(clean(f.desc), { indent: 12 });
      doc.moveDown(0.25);
    }
  }

  sectionTitle(doc, 'Recomendaciones generales');
  const recs = [
    'Mantener HTTPS obligatorio con HSTS y certificado renovado antes de caducar.',
    'Añadir SPF, DKIM y DMARC con p=reject para evitar suplantación de email.',
    'Bloquear acceso a .git, .env, backups y paneles administrativos.',
    'Mantener actualizados CMS, plugins y dependencias; revisar CVEs.',
    'Registrar y monitorizar intentos fallidos de acceso e inyección.',
    'Validar y controlar acceso a recursos por ID en el servidor.',
    'No mostrar errores internos ni cabeceras con versiones del software.',
  ];
  for (const r of recs) doc.font('Helvetica').fontSize(9).fillColor('#495057').text('  • ' + r);

  doc.moveDown(1);
  doc.font('Helvetica-Oblique').fontSize(8).fillColor('#868e96').text('Informe generado automáticamente por WebSec Auditor. Uso educativo y preventivo; analice solo sitios propios o con autorización.');

  doc.end();
  return new Promise((resolve) => {
    doc.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

module.exports = { generateReport };
