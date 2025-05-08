rule Contains_VBA_macro_code {
  meta:
    description = "Обнаружение MS Office документа с встроенным VBA макросом"
    filetype    = "Office documents"

  strings:
    $officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
    $zipmagic    = "PK"

    $97str1 = "_VBA_PROJECT_CUR" wide
    $97str2 = "VBAProject" wide
    $97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }  // Attribute VB_

    $xmlstr1 = "vbaProject.bin"
    $xmlstr2 = "vbaData.xml"

  condition:
    ($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}

rule Contains_VBE_File {
  meta:
    description = "Обнаружение VBE файла внутри последовательности байтов"

  strings:
    $vbe = /#@~\^.+\^#~@/

  condition:
    $vbe
}

rule Contains_hidden_PE_File_inside_a_sequence_of_numbers {
  meta:
    description = "Обнаружение скрытого исполняемого файла в последовательности цифр разделенных запятой"
    filetype    = "Разархивированный VBA-макрос"

  strings:
    $a = "= Array("  // Array of bytes
    $b = "77, 90,"  // MZ
    $c = "33, 84, 104, 105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 114, 117, 110, 32, 105, 110, 32, 68, 79, 83, 32, 109, 111, 100, 101, 46,"  // !This program cannot be run in DOS mode.

  condition:
    all of them
}
