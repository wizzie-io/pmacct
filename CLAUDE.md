# CLAUDE.md

Este fichero sirve de guía a Claude Code (claude.ai/code) para trabajar con el código de este repositorio.

## Qué es esto

pmacct es un conjunto de demonios de telemetría de red escritos en C y construidos a partir de una única base de código compartida: `pmacctd` (libpcap), `nfacctd` (NetFlow/IPFIX), `sfacctd` (sFlow), `uacctd` (NFLOG de Linux), `pmbgpd` (BGP), `pmbmpd` (BMP), `pmtelemetryd` (streaming telemetry), más el cliente `pmacct` para la tabla en memoria. La rama `1.8.0-wizzie` es el fork de Wizzie sobre el upstream `pmacct/pmacct` (`master`, de Paolo Lucente). Añade el plugin `http`, que publica en la ingesta de Wizzie (Kong + http2k), y la imagen Docker con su proceso principal pyflow, en `pyflow/` (ver las secciones de Wizzie más abajo).

## Compilación

Proyecto autotools. `src/external_libs/libcdada` es un submódulo git que `make` clona y compila automáticamente (necesita un compilador de C++); no hace falta inicializarlo a mano.

```bash
./autogen.sh
./configure --enable-debug --enable-jansson --enable-kafka   # ver ./configure --help
make -j
src/nfacctd -V        # muestra la versión y las opciones compiladas
```

- `--enable-debug` cambia a `-O0 -g -Wall -Werror`. La CI compila con esa opción, así que los warnings rompen la compilación: compila con ella antes de dar un cambio por terminado.
- Cada backend opcional es una opción `--enable-<x>` que se resuelve mediante pkg-config (`mysql pgsql sqlite3 rabbitmq zmq kafka http redis gnutls geoipv2 jansson avro serdes ndpi unyte-udp-notif grpc-collector ebpf nflog`). Cada una define `WITH_<X>` tanto como condicional de automake (qué ficheros se compilan, ver `src/Makefile.am`) como macro de C (`#ifdef WITH_KAFKA`). El código que toque una funcionalidad opcional debe seguir compilando con esa funcionalidad desactivada; la CI compila una matriz de combinaciones de flags (`.github/workflows/ci.yaml`), desde ningún flag hasta todo activado.
- `--disable-traffic-bins`, `--disable-bgp-bins`, `--disable-bmp-bins`, `--disable-st-bins` omiten grupos de demonios.
- `ci/script.sh` es lo que ejecuta la CI dentro de las imágenes de compilación (`ci/Dockerfile-*`); `ci/deps.sh` compila desde el código fuente las dependencias de terceros.
- Imágenes Docker del upstream: `cd docker && make` (imagen base más una imagen por demonio, con la etiqueta `_build`). La de Wizzie es otra: `pyflow/Dockerfile` (ver *Imagen de Wizzie: pyflow*).

El código C no tiene linter ni tests unitarios. La verificación consiste en compilar con `-Werror` y pasar el framework de regresión descrito abajo; lo de Wizzie tiene además sus propias pruebas (`ci/http-plugin/` y `pyflow/tests/`).

## Tests de regresión (`test-framework/` + `tests/`)

pytest orquesta contenedores Docker: un stack de Kafka, el demonio de pmacct bajo prueba y un reproductor de tráfico que reinyecta un pcap. La salida en Kafka (y el log del demonio) se compara con ficheros esperados. Prueba las imágenes Docker, no los binarios locales de `src/`, así que hay que reconstruir las imágenes tras cada cambio de código.

```bash
cd test-framework
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
tools/pcap_player/build_docker_image.sh        # una vez (usa el submódulo traffic-reproducer)
tools/pmacct_build/build_docker_images.sh      # tras cada cambio en el código de pmacct

sudo env PATH="$PATH" ./runtest.sh 100                 # un test, todos los escenarios
sudo env PATH="$PATH" ./runtest.sh 103:02              # un escenario
sudo env PATH="$PATH" ./runtest.sh '2*' --exitfirst    # todos los tests de BMP
sudo env PATH="$PATH" ./runtest.sh '*' --mark=light    # por marcador de pytest (ver pytest.ini)
sudo env PATH="$PATH" ./runtest.sh --dry '4*'          # solo recolectar
sudo env PATH="$PATH" OVERWRITE=true ./runtest.sh 203  # regenerar los ficheros de salida esperada
tools/stop_all.sh                                      # limpiar contenedores que hayan quedado
```

- Hay que ejecutarlo desde `test-framework/`. Los resultados quedan en `test-framework/results/<test>/` (logs de pmacct en `pmacct_mount/`, `report.html`, `pytestlog.log`).
- La construcción de la imagen falla si el árbol contiene artefactos de una compilación local: ejecuta antes `make distclean` / `git clean` y vacía `src/external_libs/libcdada`.
- Numeración de los tests: 1XX IPFIX/NFv9, 2XX BMP, 3XX BGP, 4XX IPFIX+BMP, 5XX IPFIX+BGP, 8XX telemetría YANG, 9XX varios. Cada `tests/NNN-nombre/` contiene `NNN_test.py`, `container-setup.yml`, `<demonio>-00.conf`, `traffic-00.pcap`, `traffic-reproducer-00.yml`, `output-<tipo>-00.json`; las subcarpetas `scenario-NN/` sobrescriben ficheros concretos del escenario por defecto (`00`).
- Los helpers están en `test-framework/library/py/` (`test_helper.py` → `KTestHelper`).

## Plugin http (`src/http_plugin.c`)

Plugin propio de Wizzie (`--enable-http`, necesita libcurl y jansson): publica los agregados como objetos JSON concatenados en `POST <http_endpoint>/v1/data/<http_topic>` con la cabecera `apikey`, el contrato de http2k detrás de Kong. Su bucle principal reproduce el de `kafka_plugin.c`. Las claves `http_*` están en `CONFIG-KEYS`.

- El JSON lo compone `compose_json()`/`cjhandler[]` como en los demás plugins; lo propio de Wizzie se añade en `http_cache_purge()` sobre ese objeto, antes de serializarlo: `http_timestamp_field`, `http_event_source`, `http_event_type`, `http_label_flatten`, `http_class_split`, `http_class_details` y `http_geoip_asn_file` (AS de cada IP con libmaxminddb; la base de datos se abre en cada purga, que corre en un proceso hijo, para tomar las versiones nuevas sin recargas).
- Un campo que el plugin sustituye pasa por `p_http_override()`, que conserva el valor original con `http_override_prefix` (p. ej. `pmacct_event_type`).
- Lo que usa nDPI va entre `#if defined (WITH_NDPI)` y lo que usa libmaxminddb entre `#if defined (WITH_GEOIPV2)`: el plugin tiene que compilar sin ellos. `pm_class2_t` es `struct ndpi_proto` entera (protocolos, `protocol_by_ip`, `category`), de ahí salen `application_category` e `ip_owner`.
- Una clave nueva sigue los pasos de *Configuración* (abajo), más un caso en `ci/http-plugin/harness.py`, su variable en `pyflow/wizzie/` y su fila en `pyflow/README.md`.

## Prueba del plugin http (`ci/http-plugin/`)

El framework de regresión no cubre el plugin `http`, que es propio de Wizzie. Lo cubre una prueba funcional aparte, `ci/http-plugin/run.sh`. Compila `nfacctd` (`--enable-debug --enable-jansson --enable-http --enable-geoipv2`) en un contenedor, a partir de una copia del árbol (no lo ensucia), y `harness.py` le envía NetFlow v5 mientras un servidor HTTP falso hace de Kong + http2k. Necesita Docker y red, y tarda unos 3 minutos.

```bash
ci/http-plugin/run.sh                         # todos los casos
ci/http-plugin/run.sh retry_5xx no_retry_4xx  # solo esos
```

Casos: entrega en lotes con las cabeceras del contrato (`delivery`), `http_apikey_header`, `http_timestamp_field` con y sin `http_history`, `http_event_type` (los marcadores conservan el suyo) con y sin `http_override_prefix`, `http_label_flatten` (etiquetas del `pre_tag_map` como campos de primer nivel), `http_class_split` (`l7_protocol` y `application` a partir de `class`; sin nDPI solo se prueba el caso sin `/`, la separación real se comprueba con la imagen de `pyflow/Dockerfile` y tráfico real), `http_class_details` sin nDPI (aviso; los campos `application_category` e `ip_owner` se comprueban igual, con la imagen y tráfico real), `http_geoip_asn_file` con la base de pruebas de MaxMind (descargada de `maxmind/MaxMind-DB` en un commit fijo) y sin el fichero, reintento de 5xx y descarte, 401 sin reintento, `http_apikey` obligatoria. Al cambiar el plugin, añade aquí el caso correspondiente.

## Imagen de Wizzie: pyflow (`pyflow/`)

Todo lo de Wizzie que no es el plugin ni su prueba vive en `pyflow/`, para acotar los cambios sobre el árbol del upstream:

- `pyflow/Dockerfile`: compila pmacctd con `http`, nDPI, jansson y GeoIP, sin los demonios BGP/BMP/telemetría. Se construye desde la raíz, porque compila el código de pmacct: `docker buildx build -f pyflow/Dockerfile --build-arg VERSION=<versión> .`. nDPI se clona de la rama `4.14-stable` (la misma que `ci/deps.sh`) sin fijar commit.
- `pyflow/pyflow.py` + paquete `pyflow/wizzie/`: el proceso principal (bajo `tini`), en Python solo con la biblioteca estándar. `common.py` lee las variables de entorno (`Configuration`); `geoip.py` espera a las bases de datos (`GEOIPV2_FILE`, `GEOIP_ASN_FILE`) y detecta las versiones nuevas de `GEOIPV2_FILE` (que se cargan con `SIGUSR2`, sin reiniciar pmacctd); `pmacctd.py` genera `pmacctd.conf`, `pretag.map`, `networks.lst` y `pcap_interfaces.map` (`PmacctdConfig`) y gestiona el proceso (`Pmacctd`: arranque, `SIGUSR2` para recargar mapas, `SIGUSR1` para estadísticas, parada ordenada). Si pmacctd termina, pyflow termina con su código. `pyflow/launch.sh` solo arranca pyflow.
- Será el manager gRPC de pmacct en Insight, al estilo de pykatok y pyprobes. Su contrato se define desde el proyecto Insight.
- `pyflow/README.md`: mensajes publicados, construcción, versionado y la tabla de variables de entorno. Las variables se documentan ahí.

```bash
(cd pyflow && python3 -m unittest discover tests)   # generación de la configuración, Python 3.10+
```

### Versiones

Etiquetas anotadas `wizzie-v<versión de pmacct>-<revisión>` (`wizzie-v1.8.0-4`…) sobre la rama; la imagen toma `git describe --tags --match "wizzie-v*"` como versión. Se publica en `europe-west1-docker.pkg.dev/wizzie-registry/wdp-public/pmacctd` con la etiqueta de la versión y `latest`, para amd64 (en un Mac arm64 la compilación va emulada y tarda varios minutos):

```bash
V=$(git describe --tags --match "wizzie-v*")
R=europe-west1-docker.pkg.dev/wizzie-registry/wdp-public/pmacctd
docker buildx build -f pyflow/Dockerfile --platform=linux/amd64 --build-arg VERSION=${V} -t ${R}:${V} -t ${R}:latest --push .
```

En zsh, usar siempre `${V}`/`${R}`: `$R:latest` aplica el modificador `:l` de zsh y sube otra imagen.

## Fork Wizzie: llevar los cambios a una release nueva del upstream

La rama `1.8.0-wizzie` (remoto `origin`, `wizzie-io/pmacct`) parte de `77fd693a` (`* Release 1.7.10 rebranded as 1.8.0`) del upstream (remoto `upstream`, `pmacct/pmacct`, de Paolo Lucente). Lo propio de Wizzie está en commits separados encima de ese punto. Para verlos: `git log --oneline $(git merge-base 1.8.0-wizzie master)..1.8.0-wizzie`. Son el plugin `http` y sus ampliaciones (asunto `* http plugin: ...`), su prueba en `ci/http-plugin`, `pyflow/` (asunto `* wizzie: ...`), este fichero y cambios en `.gitignore`.

Procedimiento con cada release:

1. `git fetch upstream --tags` y crear una rama nueva desde la etiqueta de la release, p. ej. `git switch -c <versión>-wizzie <etiqueta>`.
2. Reaplicar los commits de Wizzie con `git cherry-pick` (en orden), sin hacer *merge*, para que sigan siendo un bloque aparte y revisable.
3. Conflictos previsibles, en los puntos de registro que el plugin comparte con los demás: `dictionary[]` y `plugin_types_list[]` en `src/cfg.c`, `PLUGIN_ID_HTTP` en `src/pmacct-data.h` (si el upstream ocupa el 11, coger el siguiente libre), los bloques de plugins y `AM_CONDITIONAL` en `configure.ac`, `src/Makefile.am`, `src/cfg.h`, `src/util.c` (listas de librerías y plugins de `-V`) y `CONFIG-KEYS`. `docker/` no se toca y `pyflow/` no da conflictos.
4. Lo que no sale como conflicto: `http_plugin.c` reproduce el bucle principal de `kafka_plugin.c` y usa la API interna de los plugins (`P_cache_*`, `purge_func`, `compose_json`/`cjhandler[]`, `struct chained_cache`). Revisa `git diff <base anterior> <etiqueta nueva> -- src/kafka_plugin.c src/plugin_common.c src/plugin_common.h src/plugin_cmn_json.c` y lleva al plugin http los cambios equivalentes.
5. Verificar: compilar con `--enable-debug` con y sin `--enable-http`, pasar `ci/http-plugin/run.sh` y, si el cambio del upstream es grande, los tests de regresión. Después, construir `pyflow/Dockerfile` y probar el arranque (p. ej. con `PCAP_SAVEFILE` y un endpoint falso). Si la release cambia la versión de nDPI en `ci/deps.sh`, igualarla en `pyflow/Dockerfile`. Si cambian claves de pmacctd que pyflow escribe, ajustar `pyflow/wizzie/pmacctd.py`.
6. Actualizar en esta sección el commit base, que cambia con la release, y empezar las etiquetas por la nueva versión de pmacct (`wizzie-v<versión>-1`).

## Arquitectura

`docs/INTERNALS` es la descripción de referencia; el resumen siguiente es lo necesario para orientarse.

### Una biblioteca, varios main

Casi todo `src/` se compila en `libdaemons.la`; cada demonio es solo su propio fichero con `main()` enlazado contra ella (`nfacctd.c` + `nfv9_template.c`, `sfacctd.c` + `sflow.c`, `pmacctd.c`, `pmbgpd.c`, …). El demonio fija `config.acct_type` (`ACCT_PM`, `ACCT_NF`, `ACCT_SF`, `ACCT_PMBGP`, `ACCT_PMBMP`, …, en `pmacct-defines.h`) al arrancar, y el código compartido se bifurca según ese valor en tiempo de ejecución, no en tiempo de compilación. Por tanto, un cambio en código compartido afecta a todos los demonios.

### Proceso core → plugins

Un demonio de tráfico (`pmacctd`/`nfacctd`/`sfacctd`/`uacctd`) es un proceso core más un proceso hijo (fork) por cada instancia de plugin configurada:

1. El core recibe paquetes/flujos y rellena una `struct packet_ptrs` (`pm_pcap_cb` en `nl.c` junto con `ll.c`, `ip_frag.c`, `ip_flow.c` para pmacctd; `process_v5_packet`/`process_v9_packet` en `nfacctd.c` para NetFlow/IPFIX).
2. Se aplican los mapas y la correlación: pre-tagging (`pretag.c`, `pretag_handlers.c`, `pretag-data.h`), búsquedas BGP/BMP/RPKI (`bgp/`, `bmp/`, `rpki/`), agregación por red/AS (`net_aggr.c`).
3. `exec_plugins()` (`plugin_hooks.c`) recorre el canal de cada plugin, aplica sus filtros y su muestreo, y ejecuta la lista de handlers de primitivas de ese canal. La lista la construye una sola vez `evaluate_packet_handlers()` (`pkt_handlers.c`) a partir del bitmap `aggregate` del plugin, eligiendo para cada primitiva un handler según el `acct_type` (p. ej. `src_mac_handler` frente a `NF_src_mac_handler` frente a `SF_...`).
4. La `struct pkt_data` resultante (más los bloques opcionales BGP/NAT/MPLS/túnel/custom/longitud variable, ver `struct primitives_ptrs` en `network.h`) se envía al plugin a través de una cola circular en memoria compartida o de ZeroMQ.
5. El proceso del plugin (`imt_plugin.c`, `print_plugin.c`, `kafka_plugin.c`, `http_plugin.c`, `amqp_plugin.c`, `*sql_plugin.c`, `tee_plugin/`, `nfprobe_plugin/`, `sfprobe_plugin/`) cachea los agregados y los vuelca periódicamente a su backend. La lógica común de los plugins está en `plugin_common.c` (funciones `P_*`) y `sql_common.c`; la codificación de la salida en `plugin_cmn_json.c`, `plugin_cmn_avro.c`, `plugin_cmn_custom.c`.

Los plugins se registran en `plugin_types_list[]` en `cfg.c`, cada uno con un punto de entrada `void x_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr)`.

### Hilos dentro del core

Los colectores de BGP, BMP, RPKI y streaming telemetry se ejecutan como hilos dentro del proceso core de un demonio de tráfico (para poder correlacionar los flujos con los datos de routing), y ese mismo código constituye por completo los demonios independientes `pmbgpd`/`pmbmpd`/`pmtelemetryd`. BMP reutiliza el parseo de mensajes BGP y las estructuras de RIB de `bgp/`. Estos subsistemas tienen su propia vía de log/dump a ficheros, Kafka o AMQP (`*_logdump.c`), independiente del pipeline de plugins.

### Configuración

- `cfg.c` contiene `dictionary[]`, que asocia cada clave de configuración con un handler `cfg_key_*` de `cfg_handlers.c`, el cual rellena la `struct configuration config` global (`cfg.h`). Las claves pueden acotarse a una instancia de plugin (`clave[nombre]: valor`), de modo que cada plugin recibe su propia copia de la estructura.
- Añadir una directiva de configuración implica: campo en `cfg.h`, handler en `cfg_handlers.c`/`.h`, entrada en `dictionary[]` y documentación en `CONFIG-KEYS`.

### Añadir una primitiva de agregación

Las primitivas son bits en registros de 64 bits (`COUNT_*` / `COUNT_INT_*` en `pmacct-defines.h`; los 16 bits superiores seleccionan el registro, de ahí que existan `aggregation`, `aggregation_2`, `aggregation_3`). Una nueva suele tocar: el define, la estructura de almacenamiento en `network.h`, el parser de `aggregate` en `cfg_handlers.c`, los handlers para cada `acct_type` relevante en `pkt_handlers.c`, los compositores JSON/Avro, los plugins print/SQL y el cliente `pmacct` (`pmacct.c`).

## Convenciones

- Los asuntos de commit del upstream tienen la forma `* fix, BGP-LS: ...` o `* nfacctd: ...` (`* ` inicial, `fix,` opcional y después el componente).
- Los commits de Wizzie siguen esa forma, en inglés: `* http plugin: ...` para el plugin y `* wizzie: ...` para `pyflow/` y lo demás. Este fichero y la documentación de Wizzie (`pyflow/README.md`) van en español.
- Los cambios visibles para el usuario se registran en `ChangeLog` (`+` nuevo, `!` corregido/modificado, `-` eliminado) y los cambios de comportamiento en `UPGRADE`; las claves de configuración se documentan en `CONFIG-KEYS` y los ejemplos de uso en `QUICKSTART`.
- Los ficheros fuente nuevos llevan la cabecera de `LICENSE.template`.
- Los logs se emiten con `Log(LOG_<NIVEL>, "NIVEL ( %s/%s ): ...\n", config.name, config.type, ...)`; los tests de regresión comprueban que no aparezcan líneas `ERROR|WARN` en los logs de los demonios, así que un warning nuevo en un camino normal los hará fallar.
