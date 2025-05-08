import "pe"
import "time"

rule RTF_Objupdate {
  meta:
    description = "Обнаруживает RTF-файлы с помощью директивы objupdate, которая часто встречалась в атаках"

  strings:
    $magic1 = { 7b 5c 72 74 (7B | 66) }  // {\rtf{ or {\rt{
    $upd    = "\\objupdate" nocase

  condition:
    $magic1 in (0..30) and $upd and filesize > 50KB and filesize < 500KB
}

rule INDICATOR_RTF_MalVer_Objects {
  meta:
    description = "Обнаруживает документы в формате RTF нестандартной версии и внедряет один из объектов, которые чаще всего встречаются в документах с эксплойтами"

  strings:
    // Embedded Objects
    $obj1 = "\\objhtml" ascii
    $obj2 = "\\objdata" ascii
    $obj3 = "\\objupdate" ascii
    $obj4 = "\\objemb" ascii
    $obj5 = "\\objautlink" ascii
    $obj6 = "\\objlink" ascii

  condition:
    uint32(0) == 0x74725c7b and ((not uint8(4) == 0x66 or not uint8(5) == 0x31 or not uint8(6) == 0x5c) and 1 of ($obj*))
}

rule RTF_Anti_Analysis_Header {
  meta:
    description = "Обнаружение строк найленных в вредоносных RTF-документов"

  strings:
    $r1 = /[\x0d\x0aa-f0-9\s]{64}(\{\\object\}|\\bin)[\x0d\x0aa-f0-9\s]{64}/ nocase

  condition:
    uint32(0) == 0x74725C7B and (not uint8(4) == 0x66 or $r1)
}

rule RTF_Header_Obfuscation {
  meta:
    description = "Обнаружение обфускации заголовков RTF файла для избержания детектирования вредоносной нагрузки"

  strings:
    $bad_header = /^\{\\rt[^f]/

  condition:
    $bad_header
}


rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_1 {
  meta:
    description = "Обнаружение потенциальной эксплуатации уязвимости CVE-2017-11882"

  strings:
    // 0002CE02-0000-0000-C000-000000000046: Equation <> CVE-2017-11882 or CVE-2018-0802
    $s1   = { 32 [0-30] (43 | 63) [0-30] (45 | 65) [0-30] 30 [0-30] 32 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] (43 | 63) [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 30 [0-30] 34 [0-30] 36 }
    // Root Entry
    $s2   = "52006f006f007400200045006e00740072007900" ascii nocase
    // bin0
    $s3   = "\\bin0" ascii nocase
    // OLE Signature
    $ole  = { (64 | 44) [0-20] 30 [0-20] (63 | 43) [0-20] (66 | 46) [0-20] 31 [0-20] 31 [0-20] (65 | 45) [0-20] 30 [0-20] (61 | 41) [0-20] 31 [0-20] (62 | 42) [0-20] 31 [0-20] 31 [0-20] (61 | 41) }
    //$ole1 = "d0cf11e0a1b11ae1" ascii nocase
    //$ole2 = { 6430 [0-1] 6366 [0-1] 3131 [0-1] 6530 [0-1] 6131 [0-1] 6231 [0-1] 3161 }
    //$ole3 = { 4430 [0-1] 4346 [0-1] 3131 [0-1] 4530 [0-1] 4131 [0-1] 4231 [0-1] 3141 }
    //$ole4 = { 64[0-1]30[0-1]63[0-1]66[0-1]31[0-1]31[0-1]65[0-1]30[0-1]61[0-1]31[0-1]62[0-1]31[0-1]31[0-1]61 }
    //$ole5 = { 44[0-1]30[0-1]43[0-1]46[0-1]31[0-1]31[0-1]45[0-1]30[0-1]41[0-1]31[0-1]42[0-1]31[0-1]31[0-1]41 }
    // Embedded Objects
    $obj1 = "\\objhtml" ascii
    $obj2 = "\\objdata" ascii
    $obj3 = "\\objupdate" ascii
    $obj4 = "\\objemb" ascii
    $obj5 = "\\objautlink" ascii
    $obj6 = "\\objlink" ascii

  condition:
    uint32(0) == 0x74725c7b and 2 of ($s*) and $ole and 2 of ($obj*)
}


rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_4 {
  meta:
    description = "Обнаружение потенциальной эксплуатации уязвимостей CVE-2018-0802 or CVE-2017-11882 в RTF документе"
    author      = "ditekSHen"

  strings:
    // equation.3 manipulated
    // is slowing down scanning, but good detection rate
    $s1   = { (36 | 34) [0-50] 35 [0-50] (37 | 35) [0-50] 31 [0-50] (37 | 35) [0-50] 35 [0-50] (36 | 34) [0-50] 31 [0-50] (37 | 35) [0-50] 34 [0-50] (36 | 34) [0-50] 39 [0-50] (36 | 34) [0-50] 66 [0-50] (36 | 34) [0-50] 65 [0-50] 32 [0-50] 65 [0-50] 33 [0-50] 33 }
    $s2   = { (7d | 5c | 2b | 24) [0-50] (37 | 35) [0-50] 31 [0-50] (37 | 35) [0-50] 35 [0-50] (36 | 34) [0-50] 31 [0-50] (37 | 35) [0-50] 34 [0-50] (36 | 34) [0-50] 39 [0-50] (36 | 34) [0-50] 66 [0-50] (36 | 34) [0-50] 65 [0-50] 32 [0-50] 65 [0-50] 33 [0-50] 33 }
    //$s3 = { 32[0-20](43|63)[0-20](45|65)[0-20]30[0-20]32[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20](43|63)[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20]30[0-20]34[0-20]36 }
    // NOT slowing down scanning, but FN prone
    // $s3 = { (36|34)[0-1]35[0-1](37|35)[0-1]31[0-1](37|35)[0-1]35[0-1](36|34)[0-1]31[0-1](37|35)[0-1]34[0-1](36|34)[0-1]39[0-1](36|34)[0-1]66[0-1](36|34)[0-1]65[0-1]3265[0-1]3333 }
    //$s4 = { (7d|5c|2b|24)[0-1](37|35)[0-1]31[0-1](37|35)[0-1]35[0-1](36|34)[0-1]31[0-1](37|35)[0-1]34[0-1](36|34)[0-1]39[0-1](36|34)[0-1]66[0-1](36|34)[0-1]65[0-1]3265[0-1]3333 }
    // Embedded Objects
    $obj1 = "\\objhtml" ascii
    $obj2 = "\\objdata" ascii
    $obj3 = "\\objupdate" ascii
    $obj4 = "\\objemb" ascii
    $obj5 = "\\objautlink" ascii
    $obj6 = "\\objlink" ascii
    $obj7 = "\\mmath" ascii

  condition:
    uint32(0) == 0x74725c7b and (1 of ($s*) and 1 of ($obj*))
}

rule RTF_CVE_2018_0802_Exploit {
    meta:
        description = "Обнаружение эксплатации уязвимости CVE-2018-0802"

    strings:
        // RTF header
        $rtf_header = "{\\rt"

        // Signature of Packager OLE object used in CVE-2018-0802 exploit (ActiveX name "Package")
        $packager_obj = "5061636B61676500" wide ascii // "Package" in hex

        // Typical OLE object header bytes preceding the Package object
        $ole_obj_header = {01 05 00 00 02 00 00 00 0B 00 00 00 45 71 75 61 74 69 6F 6E} 

        // Objdata with Packager.dll trick to drop and execute SCT file
        $objdata_marker = "objdata"

    condition:
        // File starts with RTF header and contains Packager OLE object signature and objdata keyword
        $rtf_header at 0 and
        $packager_obj and
        $ole_obj_header and
        $objdata_marker
}


rule Empire_Invoke_Mimikatz_Gen {
  meta:
    description = "Обнаружение компонента Empire Invoke-Mimikatz.ps1"

  strings:
    $s1 = "= \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ" ascii
    $s2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword ascii

  condition:
    (uint16(0) == 0x7566 and filesize < 4000KB and 1 of them) or all of them
}

rule RTF_Equation_Editor_CVE_2018_0798 {
  meta:
    description   = "Обнаружение эксплуатации уязвимости CVE-2018-0798"
  strings:
    $S1 = {44 60 60 60 60 60 60 60 60 61 61 61 61 61 61 61 61 61 61 61 61 61 61 FB 0B}
    $RTF= "{\rt"
  condition:
  $RTF at 0 and $S1 
} 
