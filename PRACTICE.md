# Guía práctica (7 niveles)

Ejercicios **offline** sobre el directorio simulado. Si quieres verlo en un
sistema real, hazlo en una VM tuya con dos usuarios tuyos y una JVM de
laboratorio, nunca en máquinas compartidas ni de terceros. Respuestas en
`tests/test_practice.py`.

Ayuda: `PYTHONPATH=src python3 -c "from c9lz4 import native; from c9lz4.simfs import TmpDir; fs=TmpDir(); print(native.load(fs,'pre','plant_file',['r1'])); print(fs.log)"`.

**Básico**

1. **Los nombres.** Corre `load` pre sin atacante: ¿qué dos archivos
   quedan? ¿Cuál tiene creación exclusiva? (L47-48)
2. **La carrera.** `plant_file` en pre con `protected_regular=0`.
   (`ATTACKER_CODE_LOADED`) ¿En qué momento exacto actúa el otro usuario?

**Intermedio**

3. **El fix.** Lo mismo en post. (`LOADED_BUNDLED`, L51) ¿Por qué el
   `create_exclusive` del otro usuario falla?
4. **`fs.protected_regular`.** Con `protected_regular=1` en pre:
   `DOS_FALLBACK`. ¿Por qué pasa de ejecución de código a denegación de
   servicio?
5. **`fs.protected_symlinks`.** `plant_symlink` con 0 y con 1.

**Avanzado**

6. **Sin bit sticky.** `sticky=False, protected_regular=2`: ¿por qué los
   sysctls no ayudan? Mira también `o01`: ¿qué workaround del GHSA sí lo
   cubre?
7. **La limpieza.** Una librería de hace 1 minuto sin `.lck`: ¿qué hace
   pre (L32-33) y qué hace post (L35)?

Más allá: agrega un escenario a `fixtures/cases.json`, regenera
`fixtures/expected.tsv` con `scripts/derive_expected.py` y comprueba que
coinciden.
