// Original Guardian heuristic; see meta.toml for public report and review notes.
rule Linux_XorDdos_Persistence {
  strings:
    $s0 = "/etc/cron.hourly/gcc.sh"
    $s1 = "/lib/libudev.so"
    $s2 = "/var/run/gcc.pid"
  condition:
    filesize < 512KB and all of them
}
