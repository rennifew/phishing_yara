rule rtf_cve2017_11882_ole: malicious exploit cve_2017_11882 {
  meta:
    description = "Attempts to identify the exploit CVE 2017 11882"

  strings:
    $headers = { 1c 00 00 00 02 00 ?? ?? a9 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 01 01 03 ?? }
    $font    = { 0a 01 08 5a 5a }  // <-- I think that 5a 5a is the trigger for the buffer overflow
    //$code = /[\x01-\x7F]{44}/
    $winexec = { 12 0c 43 00 }

  condition:
    all of them and @font > @headers and @winexec == @font + 5 + 44
}

// same as above but for RTF documents
rule rtf_cve2017_11882: malicious exploit cve_2017_1182 {
  meta:
    description = "Attempts to identify the exploit CVE 2017 11882"

  strings:
    $headers = {
      31 63 30 30 30 30 30 30 30 32 30 30 ?? ?? ?? ??
      61 39 30 30 30 30 30 30 ?? ?? ?? ?? ?? ?? ?? ??
      ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
      ?? ?? ?? ?? ?? ?? ?? ?? 30 33 30 31 30 31 30 33
      ?? ??
    }
    $font    = { 30 61 30 31 30 38 35 61 35 61 }
    $winexec = { 31 32 30 63 34 33 30 30 }

  condition:
    all of them and @font > @headers and @winexec == @font + ((5 + 44) * 2)
}

rule packager_cve2017_11882 {
  meta:
    description = "Attempts to exploit CVE-2017-11882 using Packager"

  strings:
    $font                 = { 30 61 30 31 30 38 35 61 35 61 }
    $equation             = { 45 71 75 61 74 69 6F 6E 2E 33 }
    $package              = { 50 61 63 6b 61 67 65 }
    $header_and_shellcode = /03010[0,1][0-9a-fA-F]{108}00/ ascii nocase

  condition:
    uint32be(0) == 0x7B5C7274  // RTF header
    and all of them
}

rule CVE_2017_11882_RTF {
  meta:
    description = "Detects suspicious Microsoft Equation OLE contents as used in CVE-2017-11882"

  strings:
    $x1 = "4d534854412e4558452068747470"  /* MSHTA.EXE http */
    $x2 = "6d736874612e6578652068747470"  /* mshta.exe http */
    $x3 = "6d736874612068747470"  /* mshta http */
    $x4 = "4d534854412068747470"  /* MSHTA http */

    $s1 = "4d6963726f736f6674204571756174696f6e20332e30" ascii  /* Microsoft Equation 3.0 */
    $s2 = "4500710075006100740069006f006e0020004e00610074006900760065" ascii  /* Equation Native */
    $s3 = "2e687461000000000000000000000000000000000000000000000"  /* .hta .... */

  condition:
    (uint32be(0) == 0x7B5C7274 or uint32be(0) == 0x7B5C2A5C)  /* RTF */
    and filesize < 300KB and
    (1 of ($x*) or 2 of them)
}

rule EXP_potential_CVE_2017_11882 {
  meta:
    description = "Detects suspicious Microsoft Equation OLE contents as used in CVE-2017-11882"

  strings:
    $docfilemagic = { D0 CF 11 E0 A1 B1 1A E1 }
    $equation1    = "Equation Native" wide ascii
    $equation2    = "Microsoft Equation 3.0" wide ascii
    $mshta        = "mshta"
    $http         = "http://"
    $https        = "https://"
    $cmd          = "cmd" fullword
    $pwsh         = "powershell"
    $exe          = ".exe"
    $address      = { 12 0C 43 00 }

  condition:
    uint16(0) == 0xcfd0 and $docfilemagic at 0 and
    any of ($mshta, $http, $https, $cmd, $pwsh, $exe) and any of ($equation1, $equation2) and $address
}
