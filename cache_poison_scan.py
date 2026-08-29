#!/usr/bin/env python3
"""
cache_poison_scan.py
=====================
Herramienta de dos fases para bug bounty, basada en la metodología descrita en
"Cache Poisoning at Scale" (youst.in), Practical Web Cache Poisoning (albinowax)
y Param Miner.

FASE 1 - DETECT: determina si el target está detrás de un cache/CDN y qué
                 tecnología es (Varnish/Fastly/Cloudflare/Akamai/ATS/etc.)
FASE 2 - PROBE:  bruteforce de "unkeyed headers" usando la técnica del canario:
                 se envía un valor único en un header candidato, y luego una
                 petición "limpia" (sin ese header) al mismo recurso con
                 cache-buster. Si el canario aparece reflejado y la segunda
                 respuesta viene de caché -> hallazgo potencial de Cache
                 Poisoning.

USO RESPONSABLE: usa esto únicamente contra targets para los que tengas
autorización explícita (programa de bug bounty en scope, VDP, o tus propios
sistemas). Las pruebas de fase 2 escriben en la caché compartida: pueden
afectar a usuarios reales si el target es vulnerable. Usa rutas poco
transitadas cuando sea posible y reporta responsablemente.

Uso:
    python3 cache_poison_scan.py detect https://target.com/path
    python3 cache_poison_scan.py probe  https://target.com/path
    python3 cache_poison_scan.py probe  https://target.com/path --headers headers.txt
    python3 cache_poison_scan.py probe  https://target.com/path --delay 1.5 --threads 1
"""

import argparse
import random
import re
import string
import sys
import time
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import requests

requests.packages.urllib3.disable_warnings()

DEFAULT_UA = "Mozilla/5.0 (compatible; CachePoisonScan/1.0; +bugbounty-research)"

# Headers que indican presencia de un cache/CDN y a qué tecnología pertenecen.
CACHE_INDICATOR_HEADERS = {
    "x-cache": "genérico (Varnish/Squid/CDN)",
    "x-cache-hits": "genérico (Varnish/Squid/CDN)",
    "x-cache-status": "genérico",
    "cf-cache-status": "Cloudflare",
    "cf-ray": "Cloudflare (presencia, no confirma cache)",
    "x-fastly-request-id": "Fastly",
    "fastly-debug-digest": "Fastly",
    "x-served-by": "Fastly / Varnish",
    "x-varnish": "Varnish",
    "x-akamai-transformed": "Akamai",
    "akamai-cache-status": "Akamai",
    "x-ats-caching": "Apache Traffic Server",
    "x-iinfo": "Incapsula",
    "x-sucuri-cache": "Sucuri",
    "server-timing": "puede exponer cache;desc=HIT/MISS",
}

# Lista de headers candidatos a "unkeyed header" para el bruteforce de fase 2.
# Basada en los casos del paper + Param Miner + cabeceras X-Forwarded-* comunes.
DEFAULT_HEADER_LIST = [
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Forwarded-Server",
    "X-Forwarded-Port",
    "X-Host",
    "X-HTTP-Host-Override",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Http-Method-Override",
    "X-Method-Override",
    "Fastly-Host",
    "X-Original-Host",
    "X-Forwarded-Path",
    "X-Real-IP",
    "X-Custom-IP-Authorization",
    "X-Wap-Profile",
    "X-Original-Remote-Addr",
    "Base-URL",
    "X-Forwarded-For",
]


def log(msg, level="*"):
    colors = {"*": "\033[94m", "+": "\033[92m", "!": "\033[91m", "-": "\033[93m"}
    reset = "\033[0m"
    print(f"{colors.get(level,'')}[{level}]{reset} {msg}")


def random_string(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def add_cachebuster(url, param="cb"):
    """Añade un parámetro único para forzar una entrada de caché nueva por request."""
    parts = urlsplit(url)
    qs = parse_qsl(parts.query)
    qs.append((param, random_string(8)))
    new_query = urlencode(qs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def get_session():
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_UA})
    s.verify = False
    return s


# ---------------------------------------------------------------------------
# FASE 1: DETECCIÓN DE CACHÉ
# ---------------------------------------------------------------------------

def detect_cache(url, session, samples=3, delay=0.5):
    log(f"Analizando headers de respuesta en {url}")
    findings = []

    r1 = session.get(url, timeout=15)
    hdrs_lower = {k.lower(): v for k, v in r1.headers.items()}

    for h, tech in CACHE_INDICATOR_HEADERS.items():
        if h in hdrs_lower:
            findings.append((h, hdrs_lower[h], tech))

    if hdrs_lower.get("cache-control"):
        log(f"Cache-Control: {hdrs_lower['cache-control']}")
    if hdrs_lower.get("vary"):
        log(f"Vary: {hdrs_lower['vary']}  (headers que SÍ se incluyen en la cache key)")
    if hdrs_lower.get("age"):
        log(f"Age: {hdrs_lower['age']}  -> el recurso ya llevaba tiempo cacheado", "+")

    if findings:
        log("Headers indicadores de caché/CDN encontrados:", "+")
        for h, v, tech in findings:
            print(f"    {h}: {v}   [{tech}]")
    else:
        log("No se encontraron headers indicadores obvios. Probando detección por comportamiento (timing/Age)...", "-")

    # Detección por comportamiento: pedir el mismo recurso con cachebuster varias
    # veces y ver si la 2da+ respuesta es consistentemente más rápida o expone Age creciente.
    log("Probando detección por comportamiento (cache-buster + repetición)...")
    cb_url = add_cachebuster(url)
    timings = []
    ages = []
    for i in range(samples):
        t0 = time.time()
        r = session.get(cb_url, timeout=15)
        t1 = time.time()
        timings.append(t1 - t0)
        age = r.headers.get("Age")
        if age is not None:
            ages.append(int(age))
        time.sleep(delay)

    if len(timings) >= 2:
        first, rest = timings[0], timings[1:]
        avg_rest = sum(rest) / len(rest)
        log(f"Tiempo 1ra petición (MISS esperado): {first:.3f}s | promedio repeticiones: {avg_rest:.3f}s")
        if avg_rest < first * 0.6:
            log("La respuesta se sirve notablemente más rápido en repeticiones -> probable HIT de caché", "+")
        else:
            log("No hay diferencia clara de timing (puede no cachear, o el timing no es confiable en este target)", "-")

    if ages:
        log(f"Valores de Age observados: {ages}", "+")

    return bool(findings) or (ages and any(a > 0 for a in ages))


# ---------------------------------------------------------------------------
# FASE 2: BRUTEFORCE DE UNKEYED HEADERS (TÉCNICA DEL CANARIO)
# ---------------------------------------------------------------------------

def is_cache_hit(headers):
    """Heurística simple para saber si una respuesta vino de caché."""
    h = {k.lower(): v.lower() for k, v in headers.items()}
    if "x-cache" in h and "hit" in h["x-cache"]:
        return True
    if "cf-cache-status" in h and h["cf-cache-status"] in ("hit", "revalidated"):
        return True
    if "x-cache-hits" in h:
        try:
            return int(h["x-cache-hits"]) > 0
        except ValueError:
            pass
    if "age" in h:
        try:
            return int(h["age"]) > 0
        except ValueError:
            pass
    return False


def probe_header(url, header, session, delay):
    """
    1. Pide una URL nueva (cachebuster) inyectando `header: <canario>`.
    2. Vuelve a pedir la MISMA url exacta (mismo cachebuster) SIN el header,
       simulando a una víctima. Si el canario aparece reflejado -> hallazgo.
    """
    canary = f"cpz{random_string(8)}zcp"
    target_url = add_cachebuster(url)

    poisoned_headers = {header: f"{canary}.evil-collab.example"}
    try:
        r_poison = session.get(target_url, headers=poisoned_headers, timeout=15)
    except requests.RequestException as e:
        return None

    time.sleep(delay)

    try:
        r_victim = session.get(target_url, timeout=15)  # sin el header inyectado
    except requests.RequestException:
        return None

    body_reflected = canary in r_victim.text
    header_reflected = any(canary in v for v in r_victim.headers.values())
    hit = is_cache_hit(r_victim.headers)

    if body_reflected or header_reflected:
        return {
            "header": header,
            "url": target_url,
            "canary": canary,
            "reflected_in_body": body_reflected,
            "reflected_in_headers": header_reflected,
            "victim_response_is_cache_hit": hit,
            "poison_status": r_poison.status_code,
            "victim_status": r_victim.status_code,
        }
    return None


def probe_cache_poisoning(url, session, headers_list, delay=1.0):
    log(f"Iniciando bruteforce de {len(headers_list)} headers candidatos contra {url}")
    log("Técnica: header con canario en request 1 -> request 2 sin header al mismo cachebuster -> ¿se refleja el canario?")

    results = []
    for h in headers_list:
        sys.stdout.write(f"\r    Probando: {h:<35}")
        sys.stdout.flush()
        result = probe_header(url, h, session, delay)
        if result:
            print()
            log(f"POSIBLE HALLAZGO con header '{h}'", "+")
            print(f"      URL probada:            {result['url']}")
            print(f"      Reflejado en body:       {result['reflected_in_body']}")
            print(f"      Reflejado en headers:    {result['reflected_in_headers']}")
            print(f"      Respuesta 'víctima' fue cache HIT: {result['victim_response_is_cache_hit']}")
            if not result["victim_response_is_cache_hit"]:
                log("      (No detectamos indicador de HIT -> confirma manualmente con una 3ra petición limpia antes de reportar)", "-")
            results.append(result)
        time.sleep(delay)
    print()

    if not results:
        log("No se detectaron reflejos de canario con la lista de headers probada.", "-")
        log("Sugerencia: prueba con más headers (Param Miner list), revisa el header Vary del target,", "-")
        log("y prueba también inyección en la request-line (fragmentos #, method override, etc.) manualmente.", "-")
    else:
        log(f"Total de hallazgos a validar manualmente: {len(results)}", "+")
        log("IMPORTANTE: valida cada hallazgo con una 3ra petición 'limpia' independiente (otra sesión/IP si es posible)", "!")
        log("antes de reportar, para confirmar que el envenenamiento persiste y no es un falso positivo de sesión.", "!")

    return results


def load_lines_file(path):
    """Lee un archivo de líneas (urls.txt o headers.txt), una entrada por línea, ignorando vacías y comentarios (#)."""
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def load_headers_file(path):
    return load_lines_file(path)


def resolve_targets(args):
    """Devuelve la lista de URLs a escanear, ya sea de --urls o de la posicional url."""
    if args.urls:
        targets = load_lines_file(args.urls)
        if not targets:
            log(f"El archivo {args.urls} no contiene URLs válidas.", "!")
            sys.exit(1)
        log(f"Cargadas {len(targets)} URLs desde {args.urls}")
        return targets
    if args.url:
        return [args.url]
    log("Debes indicar una URL como posicional o un archivo con --urls archivo.txt", "!")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Detector y probador de Web Cache Poisoning para bug bounty (uso autorizado únicamente).")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_detect = sub.add_parser("detect", help="Fase 1: detecta si el target usa caché/CDN")
    p_detect.add_argument("url", nargs="?", help="Una sola URL a analizar")
    p_detect.add_argument("--urls", help="Archivo con una URL por línea. Escanea todas en secuencia.")
    p_detect.add_argument("--samples", type=int, default=3)
    p_detect.add_argument("--delay", type=float, default=0.5)
    p_detect.add_argument("--output", help="Ruta de archivo JSON donde guardar el resumen de todas las URLs.")

    p_probe = sub.add_parser("probe", help="Fase 2: bruteforce de unkeyed headers con técnica de canario")
    p_probe.add_argument("url", nargs="?", help="Una sola URL a probar")
    p_probe.add_argument("--urls", help="Archivo con una URL por línea. Prueba cada una con la lista de headers completa.")
    p_probe.add_argument("--headers", help="Archivo con un header candidato por línea (ej. el gist de Param Miner). Si no se pasa, usa la lista por defecto.")
    p_probe.add_argument("--delay", type=float, default=1.0, help="Delay entre requests, en segundos (sé respetuoso con el target)")
    p_probe.add_argument("--output", help="Ruta de archivo JSON donde guardar todos los hallazgos.")

    args = parser.parse_args()
    session = get_session()
    targets = resolve_targets(args)

    if args.mode == "detect":
        summary = []
        for i, url in enumerate(targets, 1):
            log(f"\n===== [{i}/{len(targets)}] {url} =====")
            cached = detect_cache(url, session, samples=args.samples, delay=args.delay)
            summary.append({"url": url, "cached": bool(cached)})
            if cached:
                log("Veredicto: PARECE estar detrás de un cache/CDN -> candidato para 'probe'.", "+")
            else:
                log("Veredicto: sin evidencia clara de caché.", "-")

        if len(targets) > 1:
            print()
            log("===== RESUMEN =====")
            for item in summary:
                mark = "+" if item["cached"] else "-"
                log(f"{item['url']}  ->  {'CACHEADO' if item['cached'] else 'sin evidencia'}", mark)

        if args.output:
            import json
            with open(args.output, "w") as f:
                json.dump(summary, f, indent=2)
            log(f"Resumen guardado en {args.output}", "+")

    elif args.mode == "probe":
        headers_list = load_headers_file(args.headers) if args.headers else DEFAULT_HEADER_LIST
        all_results = {}
        for i, url in enumerate(targets, 1):
            log(f"\n===== [{i}/{len(targets)}] {url} =====")
            results = probe_cache_poisoning(url, session, headers_list, delay=args.delay)
            if results:
                all_results[url] = results

        if len(targets) > 1:
            print()
            log("===== RESUMEN GLOBAL =====")
            if all_results:
                for url, results in all_results.items():
                    log(f"{url}  ->  {len(results)} hallazgo(s): {', '.join(r['header'] for r in results)}", "+")
            else:
                log("Ningún target de la lista mostró reflejo de canario.", "-")

        if args.output:
            import json
            with open(args.output, "w") as f:
                json.dump(all_results, f, indent=2)
            log(f"Hallazgos guardados en {args.output}", "+")


if __name__ == "__main__":
    main()
