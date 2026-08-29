# cache_poison_scan.py

Herramienta de dos fases para detectar y probar **Web Cache Poisoning** en bug bounty, basada en la metodología de:

- ["Cache Poisoning at Scale"](https://youst.in/posts/cache-poisoning-at-scale/) — youst.in
- ["Practical Web Cache Poisoning"](https://portswigger.net/research/practical-web-cache-poisoning) — albinowax
- [Param Miner](https://github.com/PortSwigger/param-miner)

## ⚠️ Uso responsable

Esta herramienta escribe en cachés **compartidas**. Si un target es vulnerable, las pruebas de la fase `probe` pueden servir una respuesta envenenada a usuarios reales, no solo a ti.

Úsala **únicamente** contra:
- Targets explícitamente en scope de un programa de bug bounty o VDP.
- Tus propios sistemas / entornos de laboratorio.

Recomendaciones:
- Usa rutas poco transitadas del sitio cuando sea posible.
- Respeta el `--delay` entre requests; no lo bajes agresivamente en producción ajena.
- Valida cada hallazgo con una petición limpia adicional antes de reportar (la herramienta te lo recuerda).
- Reporta y, si aplica, ofrece ayudar a limpiar la caché envenenada como parte del reporte.

## Instalación

```bash
pip install requests --break-system-packages   # o dentro de un virtualenv
```

Solo depende de la librería `requests` (stdlib para el resto).

## Cómo funciona

### Fase 1 — `detect`
Determina si el target está detrás de un cache/CDN:
1. Revisa headers reveladores: `X-Cache`, `CF-Cache-Status`, `X-Served-By`, `X-Varnish`, `Age`, `Vary`, `Akamai-Cache-Status`, etc.
2. Si no hay headers obvios, hace detección por comportamiento: repite la misma request con un parámetro *cache-buster* único y compara tiempos de respuesta / valores de `Age` para inferir si hay caché "silenciosa".

### Fase 2 — `probe`
Bruteforce de **unkeyed headers** con la técnica del canario, tal como describe el paper:
1. Genera una URL con cache-buster único.
2. Pide esa URL inyectando un header candidato (`X-Forwarded-Host`, `Fastly-Host`, `X-Http-Method-Override`, etc.) con un valor canario irrepetible.
3. Vuelve a pedir **la misma URL exacta**, esta vez sin el header (simulando a una víctima real).
4. Si el canario aparece reflejado en esa segunda respuesta → el header influye en el backend pero no está en la cache key → **hallazgo potencial de cache poisoning**.

La herramienta marca además si la respuesta "víctima" trae indicadores de `HIT` de caché, para ayudarte a distinguir un hallazgo real de un falso positivo (p. ej. reflejo por sesión/IP en vez de por caché).

## Uso

### Una sola URL

```bash
python3 cache_poison_scan.py detect https://target.com/path
python3 cache_poison_scan.py probe  https://target.com/path
```

### Muchas URLs desde archivo

```bash
python3 cache_poison_scan.py detect --urls urls.txt --output detect_results.json
python3 cache_poison_scan.py probe  --urls urls.txt --headers param_miner_headers.txt --delay 1.5 --output findings.json
```

`urls.txt`: una URL por línea, líneas vacías o que empiecen con `#` se ignoran.

### Parámetros

**`detect`**

| Flag | Descripción |
|---|---|
| `url` | Una sola URL (posicional, opcional si usas `--urls`) |
| `--urls archivo.txt` | Lista de URLs a escanear en secuencia |
| `--samples N` | Nº de requests repetidas para la detección por timing (default 3) |
| `--delay S` | Delay entre requests, en segundos (default 0.5) |
| `--output archivo.json` | Guarda el resumen (cacheado / no) de todas las URLs |

**`probe`**

| Flag | Descripción |
|---|---|
| `url` | Una sola URL (posicional, opcional si usas `--urls`) |
| `--urls archivo.txt` | Lista de URLs a probar con la lista de headers completa |
| `--headers archivo.txt` | Lista propia de headers candidatos (ej. el gist mencionado en el paper, o el de Param Miner). Si se omite, usa la lista por defecto incluida en el script |
| `--delay S` | Delay entre requests, en segundos (default 1.0) |
| `--output archivo.json` | Guarda todos los hallazgos (header, URL, canario, si fue reflejado en body/headers, si la respuesta víctima fue HIT) |

`archivo.txt` de headers: un header por línea (ej. `X-Forwarded-Host`), líneas vacías o `#` se ignoran.

## Interpretando los resultados de `probe`

Un hallazgo positivo NO es automáticamente un reporte válido. Antes de reportar:

1. **Confirma el HIT de caché** en la respuesta "víctima" (headers `X-Cache: HIT`, `CF-Cache-Status: HIT`, `Age > 0`, etc.). Si no hay indicador de HIT, el reflejo puede deberse a otra cosa (sesión, IP, comportamiento del propio backend sin caché de por medio).
2. **Repite la prueba con una petición completamente limpia** (otra sesión, si es posible otra IP) para descartar que el reflejo sea por afinidad de sesión y no por caché real.
3. Determina el **impacto**: ¿el header controla un redirect (DoS/open redirect), se refleja en HTML/JS (XSS), o solo cambia el body (defacement/DoS)? El impacto es lo que define la severidad del reporte, no solo el hecho de que se refleje.
4. Si confirmas la vulnerabilidad, considera el **radio de explosión**: ¿afecta solo esa ruta o todo un patrón de URLs? ¿Cuántos usuarios podrían verse afectados hasta que expire el TTL de la caché?

## Limitaciones conocidas

- La lista de headers por defecto es pequeña y está basada en los casos concretos del paper — para bruteforce serio, usa `--headers` con una lista más completa (Param Miner, el gist del artículo).
- No prueba manipulación de la **request-line** (fragmentos `#`, method override vía verbo HTTP real, parámetros duplicados/URL-encoded) — esos casos del paper (ATS, GCP Buckets, Fastly `size` param) requieren pruebas manuales dirigidas al stack específico del target.
- La detección por timing en `detect` es una heurística; en targets con latencia muy variable puede dar falsos negativos.
- Sin threading: para listas grandes de URLs × headers, el escaneo puede tardar bastante. Es intencional — prioriza no tumbar el target sobre velocidad.
