# Despliegue del servidor local de Piper

> Endpoints mínimos: `/ping` y `/ask?prompt=...` con protección opcional por API key.

## Encendido y apagado
```bash
piper server on          # inicia en 127.0.0.1:8787 (background)
piper server status      # muestra estado
piper server off         # detiene el proceso
```

Logs: `~/.local/share/piper-cli/logs/piper-server.log`

## Seguridad (API key)
- Define una API key para exigir `X-API-Key` o `?key=` en las peticiones:
```bash
piper config --set-server-api-key "mi_api_key"
```
- Para deshabilitarla:
```bash
piper config --unset-server-api-key
```

## Consulta rápida
```bash
curl 'http://127.0.0.1:8787/ping'
curl 'http://127.0.0.1:8787/ask?prompt=Hora%20actual'
curl -H 'X-API-Key: mi_api_key' 'http://127.0.0.1:8787/ask?prompt=2+%2B+2'
```

Notas:
- Implementación simple basada en asyncio Streams (sin dependencias externas).
- Piper aplica límites y validaciones en el endpoint `/ask`.