# AI Secure Campus Dashboards

Scripts Python para generar páginas HTML estáticas a partir de datos de Elasticsearch / Security Onion. Están pensados para cartelería digital, pantallas informativas o modo kiosk, evitando incrustar Kibana mediante `iframe`.

Los HTML se generan periódicamente mediante `cron` y se refrescan automáticamente en el navegador cada 10 minutos.

## Dashboards incluidos

### 1. Network traffic

Script:

```bash
scripts/so_dashboard_html.py
```

Genera por defecto:

```bash
dashboard_so.html
```

Muestra:

- Unique connections
- Total traffic
- Egress
- Ingress
- Unique connections trend
- Top source IPs
- Top destination IPs

Las animaciones se aplican solo a los paneles **Top source IPs** y **Top destination IPs**. La gráfica de conexiones queda sin animación para evitar cortes visuales.

### 2. Security overview

Script:

```bash
scripts/so_security_overview_html.py
```

Genera por defecto:

```bash
security_overview.html
```

Muestra:

- Protocols
- Organization name
- Top detections
- Top DNS queries

## Requisitos

Python 3 y el paquete `requests`.

En Debian/Ubuntu/LliureX:

```bash
sudo apt update
sudo apt install python3 python3-requests
```

O con `pip`:

```bash
python3 -m pip install -r requirements.txt
```

## Configuración

Los scripts no contienen credenciales. Toda la configuración sensible se pasa mediante variables de entorno.

Copia el fichero de ejemplo:

```bash
cp .env.example .env.local
nano .env.local
```

Ejemplo mínimo:

```bash
export SO_ES_URL="https://10.100.22.4:9200"
export SO_ES_INDEX="logs-*"
export SO_ES_USER="usuario_solo_lectura"
export SO_ES_PASS="password"
export SO_VERIFY_TLS="false"
export SO_TIME_FROM="now-24h"
export SO_TIME_TO="now"
export SO_TIME_ZONE="Europe/Madrid"
export SO_HTML_REFRESH_SECONDS="600"
export SO_LOGO_FILE="/home/lliurex/kibanadash/logo_institut.png"
```

> No subas `.env.local` a GitHub. Ya está incluido en `.gitignore`.

## Uso manual

### Generar Network traffic

```bash
cd ai-secure-campus-dashboards
source .env.local
export SO_OUTPUT_HTML="/home/lliurex/cartelleria-digital/dist/layouts/media/dashboard_so.html"
python3 scripts/so_dashboard_html.py
```

### Generar Security overview

```bash
cd ai-secure-campus-dashboards
source .env.local
export SO_OUTPUT_HTML="/home/lliurex/cartelleria-digital/dist/layouts/media/security_overview.html"
python3 scripts/so_security_overview_html.py
```

## Servir los HTML en local

Para pruebas:

```bash
cd /home/lliurex/cartelleria-digital/dist/layouts/media
python3 -m http.server 8080
```

Abrir en el navegador:

```text
http://localhost:8080/dashboard_so.html
http://localhost:8080/security_overview.html
```

## Ejecución automática con cron

Edita el crontab:

```bash
crontab -e
```

Ejemplo para generar ambos HTML cada 10 minutos:

```cron
*/10 * * * * cd /ruta/ai-secure-campus-dashboards && . ./.env.local && export SO_OUTPUT_HTML="/home/lliurex/cartelleria-digital/dist/layouts/media/dashboard_so.html" && /usr/bin/python3 scripts/so_dashboard_html.py >> /home/lliurex/kibanadash/so_dashboard_html.log 2>&1
*/10 * * * * cd /ruta/ai-secure-campus-dashboards && . ./.env.local && export SO_OUTPUT_HTML="/home/lliurex/cartelleria-digital/dist/layouts/media/security_overview.html" && /usr/bin/python3 scripts/so_security_overview_html.py >> /home/lliurex/kibanadash/so_security_overview_html.log 2>&1
```

Comprueba los logs:

```bash
tail -f /home/lliurex/kibanadash/so_dashboard_html.log
tail -f /home/lliurex/kibanadash/so_security_overview_html.log
```

## Campos de Elasticsearch utilizados

Los scripts detectan automáticamente los primeros campos disponibles entre varios candidatos.

### Network traffic

- Conexiones: `network.community_id`
- Tráfico: `client.bytes/server.bytes`, `source.bytes/destination.bytes` o `network.bytes`
- IP origen: `client.ip` o `source.ip`
- IP destino: `server.ip` o `destination.ip`

### Security overview

- Detecciones: `rule.name`, `alert.signature`, `suricata.eve.alert.signature`, `event.reason`
- DNS: `dns.query.name`, `dns.question.name`, `dns.question.registered_domain`, `dns.question.top_level_domain`
- Protocolos: `network.protocol`, `network.transport`, `zeek.proto`
- Organización: `destination.as.organization.name`, `server.as.organization.name`, `source.as.organization.name`, `client.as.organization.name`, `as.organization.name`

## Seguridad

- Usa un usuario de Elasticsearch/Security Onion de solo lectura.
- No subas credenciales al repositorio.
- No publiques `.env.local`, logs ni HTML generados si contienen datos sensibles.
- Si alguna credencial se ha incluido alguna vez en un fichero que pueda haberse compartido o subido, cámbiala antes de publicar el repositorio.

## Estructura recomendada

```text
ai-secure-campus-dashboards/
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
└── scripts/
    ├── so_dashboard_html.py
    └── so_security_overview_html.py
```
