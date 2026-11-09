# Limitations

- **A simulated directory, not Linux.** Only the rules named in the GHSA
  are modelled. Real kernel details (directory owner exceptions,
  `protected_regular = 2` for group-writable directories, ACLs, mount
  options, other filesystems, Windows and macOS) are simplified or absent.
- **The race is a step, not timing.** The other user acts at a fixed point
  (right after the `.lck` appears, or right after the write). Whether that
  window can be won on a real host is **not measured**.
- **Random names** come from the fixture (`randoms`), so p06's "lucky guess"
  is a modelling device; real `createTempFile` names are not guessable this
  way.
- **o01** (no sticky bit: replacement between write and load still works
  after the fix) is a **model observation, not verified** against a real
  JVM, and not a claim about lz4-java.
- **Outcome names.** `DOS_FALLBACK` follows the GHSA ("falls back to the
  Java implementations"); the model does not run Java. `ATTACKER_CODE_LOADED`
  means the mapped file is controlled by the other user; nothing is loaded.
- **Not verified:** commit c3ddae5 (named only in the GHSA as the origin in
  1.7.0); the `org.lz4:lz4-java` range; the error handling changes at
  L59-79 (not modelled).
- This is not a finding and not an exploit.
