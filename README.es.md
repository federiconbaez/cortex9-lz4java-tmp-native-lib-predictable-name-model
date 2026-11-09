# cortex9-lz4java-tmp-native-lib-predictable-name-model

Modelo offline e inerte de **CVE-2026-106451** (GHSA-mcr4-qmvw-px4g,
CWE-367 / CWE-377). Si no hay `liblz4-java` del sistema, `Native.load()` de
lz4-java extrae la librería JNI a `java.io.tmpdir` y la carga con
`System.load`. Hasta 1.11.3 solo el `.lck` tenía nombre aleatorio y creación
exclusiva; la librería era ese nombre sin `.lck` (L47-48 del diff), nadie la
reservaba y `new FileOutputStream` (L53) la abría con `O_CREAT|O_TRUNC`
siguiendo symlinks. Otro usuario local con el mismo directorio temporal
podía crearla antes. El fix, commit
`7a48b7f6b8099b9dab6541e4ac2ee0979dc55aa3` (en 1.11.4), crea la librería con
`File.createTempFile` (L51) y la limpieza pasa a usar una edad de una hora
(L10, L35). Verificación: [evidence/verification.md](evidence/verification.md).

Inglés: [README.md](README.md). Ejercicios: [PRACTICE.md](PRACTICE.md).

## El modelo

- `src/c9lz4/simfs.py`: un directorio temporal **en un dict de Python**,
  con creación exclusiva, aperturas que siguen symlinks, bit sticky y los
  sysctls `fs.protected_regular` / `fs.protected_symlinks`.
- `src/c9lz4/native.py`: `load()` pre y post y `cleanup()` pre y post.
- **No se toca ningún directorio real ni se carga ninguna librería.**

## Evidencia diferencial (`results/summary.csv`)

| Clase | n | pre | post |
|---|---|---|---|
| pos | 6 | 4 `ATTACKER_CODE_LOADED`, 2 `DOS_FALLBACK` | 6 `LOADED_BUNDLED` |
| neg | 3 | `LOADED_BUNDLED` | `LOADED_BUNDLED` |
| observación | 1 | `ATTACKER_CODE_LOADED` | `ATTACKER_CODE_LOADED` |

`o01` es una **observación del modelo, no verificada**: en un directorio
escribible por todos y **sin** bit sticky cualquiera puede borrar y
reemplazar un archivo entre la escritura y `System.load`; ahí el fix solo
no alcanza (sí el workaround del GHSA: un `java.io.tmpdir` privado).

## Uso

```sh
(cd sources && sha256sum -c SHA256SUMS)
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
python3 scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

Un modelo no es un hallazgo. Ver [LIMITATIONS.md](LIMITATIONS.md) y
[SOURCES.md](SOURCES.md). Licencia: Apache-2.0.
