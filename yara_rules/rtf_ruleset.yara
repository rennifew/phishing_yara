rule Detect_RTF_objupdate {
  meta:
    description = "Обнаруживает RTF-файлы с директивой objupdate, которая часто встречалась в атаках"

  strings:
    $magic1 = { 7b 5c 72 74 (7B | 66) } 
    $upd    = "\\objupdate" nocase

  condition:
    $magic1 in (0..30) and $upd and filesize > 50KB and filesize < 500KB
}

rule Detect_RTF_Anti_Analysis_Header {
  meta:
    description = "Обнаружение строк найденных в вредоносных RTF-документов, которые используют техники анти-анализа"

  strings:
    $r1 = /[\x0d\x0aa-f0-9\s]{64}(\{\\object\}|\\bin)[\x0d\x0aa-f0-9\s]{64}/ nocase

  condition:
    uint32(0) == 0x74725C7B and (not uint8(4) == 0x66 or $r1)
}

rule Detect_RTF_Header_Obfuscation {
  meta:
    description = "Обнаружение обфускации заголовков RTF файла для избержания детектирования вредоносной нагрузки"

  strings:
    $bad_header = /^\{\\rt[^f]/

  condition:
    $bad_header
}

rule Detect_RTF_CVE_2017_11882_1 {
  meta:
    description = "Обнаружение потенциальной эксплуатации уязвимости CVE-2017-11882"

  strings:
    $s1   = { 32 [0-30] (43 | 63) [0-30] (45 | 65) [0-30] 30 [0-30] 32 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] (43 | 63) [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 34 [0-30] 36 }
    $s2   = "52006f006f007400200045006e00740072007900" ascii nocase
    $s3   = "\\bin0" ascii nocase
    $ole  = { (64 | 44) [0-20] 30 [0-20] (63 | 43) [0-20] (66 | 46) [0-20] 31 [0-20] 31 [0-20] (65 | 45) [0-20] 30 [0-20] (61 | 41) [0-20] 31 [0-20] (62 | 42) [0-20] 31 [0-20] 31 [0-20] (61 | 41) }
    $obj1 = "\\objhtml" ascii
    $obj2 = "\\objdata" ascii
    $obj3 = "\\objupdate" ascii
    $obj4 = "\\objemb" ascii
    $obj5 = "\\objautlink" ascii
    $obj6 = "\\objlink" ascii

  condition:
    uint32(0) == 0x74725c7b and 2 of ($s*) and $ole and 2 of ($obj*)
}

rule Detect_RTF_CVE_2018_0802 {
  meta:
    description = "Обнаружение эксплуатации уязвимости CVE-2018-0802"

  strings:
    $rtf_header = "{\\rt"
    $packager_obj = "5061636B61676500" wide ascii 
    $ole_obj_header = { 01 05 00 00 02 00 00 00 0B 00 00 00 45 71 75 61 74 69 6F 6E }
    $objdata_marker = "objdata"

  condition:
    $rtf_header at 0 and
    $packager_obj and
    $ole_obj_header and
    $objdata_marker
}

rule Detect_RTF_CVE_2018_0798 {
  meta:
    description = "Обнаружение эксплуатации уязвимости CVE-2018-0798"

  strings:
    $S1  = { 44 60 60 60 60 60 60 60 60 61 61 61 61 61 61 61 61 61 61 61 61 61 61 FB 0B }
    $RTF = "{\rt"

  condition:
    $RTF at 0 and $S1
}
