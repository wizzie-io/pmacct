# pmacctd (Wizzie)

Capturador de tráfico de Wizzie basado en [pmacct](https://github.com/pmacct/pmacct). Escucha
en una o varias interfaces con libpcap (por ejemplo, un puerto espejo), clasifica cada flujo
por aplicación con nDPI, agrega el tráfico por intervalos y lo publica en el endpoint HTTP de
ingesta de Wizzie (Kong + http2k), como el resto de conectores.

Es la rama `1.8.0-wizzie` del fork `wizzie-io/pmacct`. Lo que añade sobre el upstream:

- El plugin `http` (`src/http_plugin.c`), que publica los agregados como objetos JSON
  concatenados en `POST <HTTP_ENDPOINT>/v1/data/<EVENTS_TOPIC>` con la cabecera `apikey`,
  compatible con [n2kafka](https://github.com/wizzie-io/n2kafka) (decoder http2k). Las claves
  `http_*` están documentadas en `CONFIG-KEYS`.
- Este directorio, `pyflow/`: la imagen (`Dockerfile`) y su proceso principal, **pyflow**
  (`pyflow.py` y el paquete `wizzie/`). pyflow lee las variables de entorno, genera los ficheros
  de configuración de pmacctd, lo lanza y lo vigila: si pmacctd termina, pyflow termina con su
  mismo código, y al parar el contenedor para pmacctd de forma ordenada. Es la base del
  futuro manager de Insight, al estilo de pykatok o pyprobes. `launch.sh` solo arranca pyflow.
- `ci/http-plugin/`: la prueba funcional del plugin.

Todo lo propio de Wizzie, salvo el plugin y su prueba, está en `pyflow/`.

### Mensajes publicados

Cada `REFRESH_TIME` segundos se publica un mensaje por cada combinación de los campos de
`AGGREGATE` vista en el intervalo, con sus paquetes y bytes acumulados:

```json
{
  "event_type": "pmacct_flow", "class": "TLS/Github", "l7_protocol": "TLS", "application": "Github",
  "application_category": "Collaborative", "ip_owner": "Azure",
  "mac_src": "14:98:77:39:28:b5", "mac_dst": "8c:ed:e1:14:74:4c", "vlan": 0, "etype": "800",
  "ip_src": "192.168.102.9", "ip_dst": "20.250.119.67", "port_src": 63979, "port_dst": 443,
  "tcp_flags": "24", "ip_proto": "tcp", "tos": 2,
  "stamp_inserted": "2026-10-22 15:57:00", "stamp_updated": "2026-10-22 15:58:01",
  "packets": 6, "bytes": 3941, "writer_id": "wdp/10",
  "timestamp": 1792684620, "event_source": "pmacct", "pmacct_event_type": "purge",
  "direction": "out"
}
```

- `timestamp`: inicio del intervalo, en segundos Unix. Es el tiempo del evento; `stamp_updated`
  es la hora a la que se envió.
- `event_type` / `event_source`: los campos comunes de los conectores de Wizzie. El valor que
  pone pmacct en `event_type` (`purge`) se conserva en `pmacct_event_type`.
- `class`: clasificación de nDPI, como `<protocolo maestro>/<protocolo de aplicación>`. El
  maestro es lo que transporta la aplicación (TLS, QUIC, DNS…) y es `Unknown` cuando nDPI solo
  reconoce un nivel: `QUIC/YouTube` es YouTube sobre QUIC, `Unknown/QUIC` es QUIC sin aplicación
  identificada y `DNS/Facebook` son consultas DNS de dominios de Facebook. Los primeros paquetes
  de un flujo, antes de que nDPI lo identifique, salen como `Unknown/Unknown`.
- `l7_protocol` / `application`: `class` separada en dos campos (`CLASS_SPLIT`), para agrupar
  sin partir la cadena. `l7_protocol` es el maestro o, si es `Unknown`, el de aplicación;
  `application` es el de aplicación. `Unknown/QUIC` da `QUIC` en los dos. Que coincidan solo
  indica que nDPI reconoce un único nivel: en `SNMP` o `DNS` es la clasificación completa, en
  `TLS` o `QUIC` la aplicación de dentro es desconocida.
- `application_category` / `ip_owner` (`CLASS_DETAILS`): la categoría de nDPI (`Web`,
  `Network`, `Streaming`…) y a quién asocia nDPI las IPs del flujo, independientemente del
  contenido (`AmazonAWS`, `Google`…; `Unknown` si a nadie). `ip_owner` da pistas cuando la
  aplicación no se ha identificado, p. ej. en un `Unknown/TLS` sin SNI.
- `direction`: solo con `LOCAL_NETWORKS`. `out` (sale de las redes locales, subida), `in`
  (entra, bajada) o `local` (entre redes locales, o hacia multicast/broadcast).
- La conversación en cada sentido es un mensaje distinto, como en NetFlow/IPFIX.

En Kafka, http2k antepone el consumer de Kong de la `API_KEY` al topic: lo publicado en
`EVENTS_TOPIC` acaba en `<consumer_id>_<EVENTS_TOPIC>`. Para que el tráfico llegue a la
analítica de Insight, `EVENTS_TOPIC` tiene que ser `default_index`.

### Construyendo la imagen docker

Las versiones se marcan con etiquetas `wizzie-v<versión de pmacct>-<revisión>`, por ejemplo
`wizzie-v1.8.0-1`, y la imagen toma esa etiqueta como versión (`VERSION`, que pyflow muestra al
arrancar). Se construye desde la raíz del repositorio, porque compila el código de pmacct:

```sh
$ git clone git@github.com:wizzie-io/pmacct.git
$ cd pmacct
$ git checkout 1.8.0-wizzie
$ git fetch --tags
$ V=$(git describe --tags --match "wizzie-v*")
$ docker buildx build -f pyflow/Dockerfile --platform=linux/amd64 --build-arg VERSION=$V -t europe-west1-docker.pkg.dev/wizzie-registry/wdp-public/pmacctd:$V .
```

Para publicar una versión nueva, se etiqueta el commit, se construye y se sube la imagen:

```sh
$ git tag -a wizzie-v1.8.0-1 -m "pmacctd wizzie v1.8.0-1"
$ git push origin wizzie-v1.8.0-1
$ gcloud auth configure-docker europe-west1-docker.pkg.dev   # una vez por máquina
$ V=$(git describe --tags --match "wizzie-v*")
$ docker buildx build -f pyflow/Dockerfile --platform=linux/amd64 --build-arg VERSION=$V -t europe-west1-docker.pkg.dev/wizzie-registry/wdp-public/pmacctd:$V --push .
```

- Con `--platform=linux/amd64,linux/arm64` se sube una imagen multiarquitectura. En una máquina
  de otra arquitectura la compilación va emulada y tarda bastante más.
- Fuera de un commit etiquetado, `git describe` da `wizzie-v1.8.0-1-3-g<hash>`: sirve para
  imágenes de prueba, pero no se deben subir como versión.
- `pyflow/Dockerfile` compila solo los demonios de tráfico con los backends que usa esta
  imagen (`http`, nDPI, jansson, GeoIP y H3). El `docker/` del upstream no se modifica.

Antes de etiquetar, conviene pasar la prueba del plugin (unos 3 minutos, necesita Docker) y las
de pyflow (generación de la configuración, solo Python 3.10 o posterior):

```sh
$ ci/http-plugin/run.sh
$ (cd pyflow && python3 -m unittest discover tests)
```

### Ejecución

El contenedor necesita la red del host y permisos de captura:

```yaml
services:
  pmacctd:
    image: europe-west1-docker.pkg.dev/wizzie-registry/wdp-public/pmacctd:wizzie-v1.8.0-1
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    restart: unless-stopped
    environment:
      PCAP_INTERFACE: enx00e04c5a5480
      HTTP_ENDPOINT: http://192.168.102.9:8880
      API_KEY: <api key del cliente>
      EVENTS_TOPIC: default_index
      LOCAL_NETWORKS: 192.168.102.0/24
```

Al arrancar, pyflow escribe en el log la configuración generada (con la API key oculta) y
el `pretag.map`. Cada purga termina con `Purging cache - END (... QN: n/m ...)`: `n` mensajes
entregados de `m`. Es normal que `n` sea algo menor que `m`, porque lo que llega durante el
cambio de minuto se envía en la purga siguiente. Si una entrega falla, se reintenta y después
se descarta con un `ERROR` en el log.

### GeoIP

Con `GEOIPV2_FILE`, cada mensaje lleva el país (y, según `GEOIP_FIELDS`, el código postal y las
coordenadas) de las dos IPs del flujo; con `GEOIP_ASN_FILE`, su sistema autónomo (número y
organización, p. ej. `15169` / `Google LLC`). GeoLite2-City incluye todo lo de GeoLite2-Country,
así que basta con City y ASN. La base de datos no va en la imagen: GeoLite2 es gratuita
pero su licencia no permite redistribuirla, así que cada despliegue la descarga con su propia
cuenta de MaxMind mediante el contenedor oficial `geoipupdate`, en un volumen compartido:

```yaml
services:
  geoipupdate:
    image: ghcr.io/maxmind/geoipupdate
    restart: unless-stopped
    environment:
      GEOIPUPDATE_ACCOUNT_ID: <id de cuenta de MaxMind>
      GEOIPUPDATE_LICENSE_KEY: <clave de licencia>
      GEOIPUPDATE_EDITION_IDS: GeoLite2-City GeoLite2-ASN
      GEOIPUPDATE_FREQUENCY: 72                   # horas; sin ella se ejecuta una vez y sale
    volumes:
      - geoip:/usr/share/GeoIP

  pmacctd:
    # ... como en Ejecución, más:
    volumes:
      - geoip:/geoip:ro
    environment:
      GEOIPV2_FILE: /geoip/GeoLite2-City.mmdb
      GEOIP_ASN_FILE: /geoip/GeoLite2-ASN.mmdb

volumes:
  geoip:
```

- Al arrancar, pyflow espera hasta `GEOIPV2_WAIT` segundos a que `geoipupdate` haya descargado
  la base de datos. Si no llega, pmacctd arranca sin ella (un `WARN` en el log y los campos de
  país vacíos) y la carga en cuanto aparece.
- Cada vez que `geoipupdate` deja una versión nueva de `GEOIPV2_FILE`, pyflow se lo indica a
  pmacctd (`SIGUSR2`) y la carga sin cortar la captura. En el log: `new version of GEOIPV2_FILE
  ...` y `geoipv2_file database ... loaded`. `GEOIP_ASN_FILE` lo abre el plugin http en cada
  envío, así que una versión nueva se usa sin más.
- Los campos de AS no los da pmacct (sus primitivas `src_as`/`dst_as` solo se rellenan desde BGP
  o `networks_file`): los añade el plugin http (`http_geoip_asn_file`) al componer cada mensaje,
  a partir de las IPs del flujo. Las direcciones que no están en la base de datos, como las
  privadas, no llevan estos campos.
- Las IPs privadas no están en la base de datos: su país sale vacío (`""`). Las coordenadas de
  esas IPs salen como `0`/`0`, un punto real en el mapa, así que en un despliegue con redes
  locales conviene quedarse con `country` o filtrarlas en la analítica.
- **Ciudad y región** (`city` en `GEOIP_FIELDS`): pmacct no tiene primitivas para ellas, así que
  las añade el plugin http con la misma base de `GEOIPV2_FILE`: `city_ip_*` y `region_ip_*`
  (primer nivel de subdivisión: en España, la comunidad autónoma), en `GEOIP_LANG`. GeoLite2
  trae el español para muchas ciudades y regiones; DB-IP Lite solo en inglés. Es el dato menos
  fiable de GeoIP: en muchas IPs falta o es la del nodo del operador o de la CDN.
- **Celdas H3** ([h3geo.org](https://h3geo.org)): con `coords`, cada extremo con coordenadas lleva
  sus celdas H3 en texto hexadecimal, como `h3_cell` de pykatok: `h3_src`/`h3_dst` con la
  resolución de `H3_RESOLUTION` y, con resoluciones fijas, `h3_city_*` (5), `h3_region_*` (3) y
  `h3_country_*` (2). Son hexágonos, no límites administrativos: `h3_country_*` es la celda que
  contiene el punto, no el país (para eso está `country_ip_*`). Las coordenadas de GeoIP son el
  centro aproximado de una ciudad, con errores de kilómetros, así que una resolución por encima
  de 7 da una precisión que el dato no tiene. Las IPs sin coordenadas (`0, 0`) no llevan celdas.
- **IPs locales**: con `LOCAL_NETWORKS`, las IPs de las redes locales reciben en los campos que
  GeoIP deja vacíos los datos de la sede: país, AS de su salida a Internet y, con `coords` y
  `city`, sus coordenadas (y con ellas sus celdas H3), ciudad y región. Se toman de `LOCAL_COUNTRY`, `LOCAL_ASN`, `LOCAL_AS_ORG`, `LOCAL_COORDS`,
  `LOCAL_CITY` y `LOCAL_REGION` y, para lo que no esté definido, de ipinfo.io, que localiza la IP
  pública con la que sale la sonda. La ciudad y la región no se toman de ipinfo.io sino de la base
  de GeoIP para esa IP, para que vayan en el mismo idioma que las demás. Lo que
  se aplica queda en el log (`local networks: country ES (ipinfo.io)`). Si la sonda sale a
  Internet por una VPN o desde la nube, esa IP no es la de la sede: conviene definir las
  variables. La consulta revela a ipinfo.io la IP pública de la sede; `LOCAL_GEO_LOOKUP=False`
  la evita. Las IPs que no son locales ni están en la base (multicast, broadcast) se quedan sin
  datos.
- Sin cuenta de MaxMind, [DB-IP Lite](https://db-ip.com/db/lite.php) ofrece bases Country y City
  en el mismo formato, con licencia CC BY 4.0 (exige atribución) y actualización mensual.

### Variables de entorno

Las variables marcadas con *vacía desactiva* tienen un valor por defecto que se aplica si no
se definen; si se definen vacías, se desactiva lo que hacen.

| Variable | Por defecto | Descripción |
|---|---|---|
| `HTTP_ENDPOINT` | — | **Obligatoria.** URL base del endpoint de ingesta (Kong), p. ej. `http://kong:8080`. Se publica en `<HTTP_ENDPOINT>/v1/data/<EVENTS_TOPIC>` |
| `API_KEY` | — | **Obligatoria.** API key del cliente, enviada en la cabecera `apikey` |
| `PCAP_INTERFACE` | — | **Obligatoria.** Interfaz de captura, o varias separadas por comas. Con varias, cada mensaje lleva el índice de su interfaz si se añade `in_iface` a `AGGREGATE` |
| `EVENTS_TOPIC` | `pmacct` | Topic de publicación. `default_index` para que llegue a la analítica de Insight |
| `PCAP_FILTER` | `""` | Filtro de captura, en sintaxis de tcpdump |
| `PCAP_EXCLUDE_ENDPOINT` | `True` | Excluye de la captura el tráfico hacia `HTTP_ENDPOINT` (host y puerto), para no contabilizar los propios envíos. Un nombre se resuelve a sus IPs al arrancar; si no se puede resolver, se avisa en el log y no se excluye (el resto de `PCAP_FILTER` se mantiene) |
| `PROMISC` | `True` | Modo promiscuo en la interfaz |
| `SNAPLEN` | `700` | Bytes capturados de cada paquete. Suficiente para cabeceras y para la clasificación |
| `AGGREGATE` | `class, etype, src_mac, dst_mac, vlan, src_host, dst_host, src_port, dst_port, proto, tos, tcpflags` | Campos por los que se agrega el tráfico (primitivas de `aggregate` de pmacct; la lista de pmacctd se obtiene con `pmacctd -a`). `tos` incluye el bit ECN, que puede partir una misma conexión en dos mensajes |
| `REFRESH_TIME` | `60` | Segundos entre publicaciones |
| `HISTORY` | `1m` | Duración de cada intervalo de agregación (`30s`, `1m`, `5m`…). Conviene que coincida con `REFRESH_TIME` |
| `HISTORY_ROUNDOFF` | `m` | Alineación del inicio de los intervalos (`m`, `h`, `d`, `w`, `M`). *Vacía desactiva* |
| `TIMESTAMP_FIELD` | `timestamp` | Campo con el inicio del intervalo en segundos Unix. *Vacía desactiva* |
| `EVENT_SOURCE` | `pmacct` | Valor del campo `event_source`. *Vacía desactiva* |
| `EVENT_TYPE` | `pmacct_flow` | Valor del campo `event_type`, en lugar de `purge`. *Vacía desactiva* |
| `OVERRIDE_PREFIX` | `pmacct_` | Prefijo con el que se conserva un campo que se sustituye (`event_type` → `pmacct_event_type`; también `l7_protocol`, `application`, `application_category` e `ip_owner` si ya venían). *Vacía desactiva* |
| `LOCAL_NETWORKS` | `""` | Redes locales separadas por comas (IPv4 o IPv6), p. ej. `192.168.102.0/24,10.0.0.0/8`. Activa el campo `direction` |
| `LOCAL_MULTICAST` | `True` | Con `LOCAL_NETWORKS`, cuenta como `local` el tráfico hacia multicast y broadcast y el IPv6 link-local |
| `NET_FIELDS` | `False` | Con `LOCAL_NETWORKS`, añade `net_src` y `net_dst`: la red local de cada extremo, o `0.0.0.0` si es externo |
| `CLASSIFIER_NUM_ROOTS` | `512` | nDPI: buckets de la tabla hash de flujos. Más buckets, más memoria al arrancar y búsquedas más rápidas |
| `CLASSIFIER_MAX_FLOWS` | `200000` | nDPI: máximo de flujos simultáneos en seguimiento (pmacct, sin definir, permite 200 millones) |
| `CLASSIFIER_PROTO_GUESS` | `True` | nDPI: si no identifica un flujo, intenta deducir la aplicación por puertos y protocolo |
| `CLASS_SPLIT` | `True` | Añade `l7_protocol` y `application` a partir de `class` (ver *Mensajes publicados*). Solo con `class` en `AGGREGATE` |
| `CLASS_DETAILS` | `True` | Añade `application_category` e `ip_owner` (ver *Mensajes publicados*). Solo con `class` en `AGGREGATE` |
| `GEOIPV2_FILE` | `""` | Base de datos GeoIP (`.mmdb`, MaxMind GeoLite2/GeoIP2 o DB-IP) en un volumen. Activa los campos de `GEOIP_FIELDS`; ver *GeoIP* |
| `GEOIP_FIELDS` | `country` | Con `GEOIPV2_FILE`, campos de GeoIP separados por comas: `country` (`country_ip_src`/`_dst`), `pocode` (código postal), `coords` (`lat_ip_*`/`lon_ip_*`) y `city` (`city_ip_*` y `region_ip_*`, la ciudad y la región o comunidad autónoma, que añade el plugin http porque pmacct no tiene primitivas para ellas). `pocode`, `coords` y `city` necesitan una base de datos City. *Vacía desactiva* (las primitivas se ponen a mano en `AGGREGATE`) |
| `H3_RESOLUTION` | `7` | Con `coords` en `GEOIP_FIELDS`, resolución (0 a 15) de las celdas H3 `h3_src`/`h3_dst` (7: unos 5 km²). Además salen `h3_city_*` (5, ~250 km²), `h3_region_*` (3, ~12.400 km²) y `h3_country_*` (2, ~87.000 km²). *Vacía desactiva*; ver *GeoIP* |
| `GEOIP_LANG` | `es` | Idioma de los nombres de ciudad y región (`es`, `en`, `de`, `fr`, `pt-BR`…). Si la base no tiene el nombre en ese idioma, va en inglés |
| `GEOIP_ASN_FILE` | `""` | Base de datos GeoLite2-ASN (`.mmdb`) en un volumen. Añade `asn_ip_src`/`asn_ip_dst` (número de AS) y `as_org_ip_src`/`as_org_ip_dst` (organización). Necesita `src_host` y `dst_host` en `AGGREGATE`; ver *GeoIP* |
| `LOCAL_COUNTRY` | `""` | Con `LOCAL_NETWORKS`, país (código ISO, p. ej. `ES`) que se da a las IPs locales, que no están en la base de GeoIP. Sin definir, se pregunta a ipinfo.io (`LOCAL_GEO_LOOKUP`); ver *GeoIP* |
| `LOCAL_ASN` | `""` | Igual, el AS de la salida a Internet de la sede (p. ej. `3352`), para `asn_ip_*` de las IPs locales. Solo con `GEOIP_ASN_FILE` |
| `LOCAL_AS_ORG` | `""` | Igual, la organización de ese AS (p. ej. `TELEFONICA DE ESPANA S.A.U.`) |
| `LOCAL_CITY`, `LOCAL_REGION` | `""` | Igual, ciudad y región de la sede, con `city` en `GEOIP_FIELDS`. Sin definir, son las que la base de `GEOIPV2_FILE` da a la IP pública de la sede, en `GEOIP_LANG` (no se toman de ipinfo.io, que las da en inglés) |
| `LOCAL_IP` | `""` | IP pública de la sede para lo anterior. Sin definir, la que da ipinfo.io |
| `LOCAL_COORDS` | `""` | Igual, las coordenadas de la sede como `<latitud>,<longitud>`. Solo con `coords` en `GEOIP_FIELDS` |
| `LOCAL_GEO_LOOKUP` | `True` | Pregunta a `https://ipinfo.io/json` al arrancar lo que las cuatro anteriores no definen. `False` para no consultar a un tercero |
| `IPINFO_TOKEN` | `""` | Token de ipinfo.io, por si se supera su uso gratuito (unas 50.000 consultas al mes; pyflow hace una al arrancar) |
| `GEOIPV2_WAIT` | `120` | Segundos que se espera al arrancar a que existan `GEOIPV2_FILE` y `GEOIP_ASN_FILE`. Pasado ese tiempo pmacctd arranca igual, con los campos de GeoIP vacíos, y carga la base de datos en cuanto aparece |
| `GEOIPV2_CHECK_SECONDS` | `60` | Cada cuántos segundos se comprueba si `GEOIPV2_FILE` ha cambiado. Si cambia, pmacctd la vuelve a cargar sin reiniciarse |
| `HTTP_TIMEOUT` | `10` | Segundos máximos de cada envío |
| `HTTP_RETRIES` | `3` | Intentos por envío. Se reintentan errores de red, 5xx, 408 y 429; el resto de 4xx (p. ej. API key rechazada) no |
| `HTTP_MULTI_VALUES` | `131072` | Bytes máximos de cada envío; los mensajes de un intervalo se reparten en tantos envíos como haga falta |
| `CACHE_ENTRIES` | `""` | Tamaño de la tabla de agregación (por defecto el de pmacct, 16411). Subirlo si el log avisa de que se llena |
| `DEBUG` | `False` | Log de depuración de pmacctd, que incluye cada mensaje publicado |
| `EXTRA_CONFIG` | `""` | Líneas de configuración de pmacctd que se añaden al final, para claves no cubiertas por estas variables (ver `CONFIG-KEYS`). El plugin se llama `wdp`, p. ej. `http_markers[wdp]: true` |
| `LOG_LEVEL` | `INFO` | Nivel del log de pyflow (`DEBUG`, `INFO`, `WARNING`, `ERROR`). El de pmacctd va con `DEBUG` |
| `CONFIG_DIR` | `/tmp/pmacct` | Directorio donde se generan los ficheros de configuración |
| `PMACCTD_CONFIG_FILE` | `""` | Configuración completa de pmacctd montada en el contenedor. Si se define, se usa tal cual y se ignoran las demás variables |
| `PCAP_SAVEFILE` | `""` | Pruebas: lee los paquetes de un fichero pcap en lugar de una interfaz y termina al acabarlo |

### Configuración generada

Con las variables del ejemplo de ejecución, pyflow genera en `CONFIG_DIR`:

- `pmacctd.conf`: captura, clasificación y el plugin `http` (instancia `wdp`).
- `pretag.map`: con `LOCAL_NETWORKS`, las reglas que ponen `direction`. Se aplica la primera
  que coincide: `local` (origen y destino locales), `out` (origen local) e `in` (destino local).
  El valor viaja como etiqueta de pmacct y el plugin lo saca al primer nivel del mensaje.
- `networks.lst`: con `NET_FIELDS`, las redes locales para `net_src` y `net_dst`.
- `pcap_interfaces.map`: con varias interfaces en `PCAP_INTERFACE`.

Si el tráfico capturado llega con etiqueta VLAN, los filtros de `pretag.map` (`src net …`) no
lo reconocen. En ese caso hay que escribir las reglas a mano y pasar la configuración completa
con `PMACCTD_CONFIG_FILE`.
