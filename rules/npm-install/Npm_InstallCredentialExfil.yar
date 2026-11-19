// Original Guardian heuristic; see meta.toml for public report and review notes.
rule Npm_InstallCredentialExfil {
  strings:
    $s0 = "postinstall"
    $s1 = "child_process"
    $s2 = ".npmrc"
    $s3 = "process.env"
    $s4 = "https.request"
  condition:
    filesize < 512KB and all of them
}
