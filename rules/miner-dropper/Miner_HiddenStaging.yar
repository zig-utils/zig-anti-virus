// Original Guardian heuristic; see meta.toml for public report and review notes.
rule Miner_HiddenStaging {
  strings:
    $s0 = "/tmp/.mountfs"
    $s1 = "xmrig"
    $s2 = "wget"
    $s3 = "chmod +x"
  condition:
    filesize < 512KB and all of them
}
