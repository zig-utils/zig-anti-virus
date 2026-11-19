// Original Guardian heuristic; see meta.toml for public report and review notes.
rule JavaScript_PaymentExfil {
  strings:
    $s0 = "document.querySelector"
    $s1 = "cardnumber"
    $s2 = "cvv"
    $s3 = "navigator.sendBeacon"
  condition:
    filesize < 512KB and all of them
}
