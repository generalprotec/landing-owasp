# 🛡️ WebSec Auditor — Análisis de Seguridad Web (OWASP Top 10)

> **Landing + escáner** que analiza los 10 riesgos de seguridad más críticos de una web, según el estándar **OWASP Top 10 (2021)**.

![Stack](https://img.shields.io/badge/Node.js-Express-339933?logo=nodedotjs&logoColor=white)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20(2021)-4F8CFF)

---

## ✨ Características

- 🔍 **Análisis en tiempo real**: introduce una URL y obtén el análisis al momento.
- 📋 **10 categorías OWASP** (A01–A10), cada una con su severidad y hallazgos.
- 🎯 **Score de seguridad** de 0 a 100 según los riesgos detectados.
- 🧩 **Filtros por severidad**: críticos, altos y medios.
- 🏢 **Análisis de la empresa**: extrae nombre, sector, contacto, redes sociales y páginas legales de su web.
- ⚡ **100% responsive** con tema oscuro.

## 🔎 Qué comprueba el escáner

| Categoría | Chequeos |
|---|---|
| **A01** Pérdida de Control de Acceso | Parámetros IDOR en la URL |
| **A02** Fallos Criptográficos | HTTPS, redirección HTTP→HTTPS, conexión TLS |
| **A03** Inyección (SQLi / XSS) | Estructura de formularios y parámetros |
| **A05** Configuración Incorrecta | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, CORS, cabecera Server, errores 5xx, robots.txt |
| **A06** Componentes Vulnerables | Fingerprint de tecnologías (WordPress, generadores) |
| **A07** Identificación y Autenticación | Atributos `Secure` y `HttpOnly` en cookies, formularios de login |

> Las categorías A04, A08, A09 y A10 requieren análisis de lógica de negocio o de la propia aplicación y se marcan como revisión manual.

## 🏢 Análisis de la empresa

Tras el escaneo, el botón **"Analizar la empresa"** revisa el contenido de la web (página de inicio, "Acerca de" y contacto) y extrae:

- **Identificación**: nombre, descripción y sector detectado por palabras clave.
- **Contacto**: emails, teléfonos y redes sociales (X, Facebook, Instagram, LinkedIn, TikTok, YouTube, WhatsApp).
- **Páginas de la web**: enlaces "Acerca de", contacto y páginas legales (privacidad, aviso legal, términos).

## 🎯 Superficie de ataque

El botón **"Superficie de ataque"** analiza lo que vería un atacante antes de intentar entrar:

- **Protección de email**: registros SPF, DMARC y DKIM. Si faltan, cualquiera puede enviar correos falsificando el dominio (phishing).
- **Rutas sensibles**: busca `.git`, `.env`, volcados SQL, `phpinfo.php`, paneles (`/admin`, `/wp-admin`), `security.txt`, etc.
- **Subdominios**: enumera ~40 subdominios comunes (mail, api, admin, vpn, git, dev…) y detecta DNS comodín.
- **Certificado TLS**: emisor, validez, días restantes y SANs.
- **Brechas**: comprueba los emails del dominio en el API de filtraciones (xposedornot).

## 🚀 Puesta en marcha

### Local
```bash
npm install
npm start
# Abre http://localhost:4000
```

### Despliegue (Render)
1. Sube el repo a GitHub.
2. En [render.com](https://render.com): **New → Blueprint**.
3. Selecciona el repo. Render detecta `render.yaml` y despliega solo.
4. Obtén tu URL pública, por ejemplo `https://landing-owasp.onrender.com`.

## 🌐 API

```
GET /api/scan?url=tudominio.com
GET /api/company?url=tudominio.com
GET /api/osint?url=tudominio.com
```

Respuesta de `/api/scan`:

```json
{
  "ok": true,
  "url": "https://tudominio.com/",
  "score": 72,
  "findings": [
    { "cat": "A05", "title": "Falta cabecera HSTS", "sev": "alto", "desc": "..." }
  ]
}
```

Respuesta de `/api/company`:

```json
{
  "ok": true,
  "company": {
    "name": "Mi Empresa",
    "description": "...",
    "sector": [{ "name": "Tecnología / Software", "count": 3 }],
    "emails": ["info@miespresa.com"],
    "phones": ["+34 600 000 000"],
    "social": { "linkedin": "https://linkedin.com/company/mi-empresa" },
    "hasAbout": true,
    "aboutUrl": "/acerca-de",
    "hasContact": true,
    "contactUrl": "/contacto",
    "legalPages": ["/politica-de-privacidad"]
  }
}
```

## 📁 Estructura

```
landing-owasp/
├── index.html      # Landing y frontend del escáner
├── server.js       # Backend Express + motor de escaneo
├── package.json
├── render.yaml     # Blueprint de despliegue en Render
└── .gitignore
```

## ⚠️ Aviso

Herramienta de **uso educativo y preventivo**. Analiza solo webs de las que seas propietario o tengas autorización expresa.

---

Hecho con ❤️ y el estándar **OWASP Top 10 (2021)**.
