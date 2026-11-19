// Original Guardian heuristic; see meta.toml for public report and review notes.
rule Webshell_ASPX_RequestEval {
  strings:
    $s0 = "<%@"
    $s1 = "JScript"
    $s2 = "eval(Request["
    $s3 = "unsafe"
  condition:
    filesize < 512KB and all of them
}
