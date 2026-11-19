// Original Guardian heuristic; see meta.toml for public report and review notes.
rule Webshell_PHP_RequestEval {
  strings:
    $s0 = "<?php"
    $s1 = "eval("
    $s2 = "$_POST["
  condition:
    filesize < 512KB and all of them
}
