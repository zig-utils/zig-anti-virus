// Original Guardian heuristic; see meta.toml for public report and review notes.
rule Webshell_JSP_RequestExec {
  strings:
    $s0 = "<%"
    $s1 = "Runtime.getRuntime().exec("
    $s2 = "request.getParameter("
  condition:
    filesize < 512KB and all of them
}
