//LNK header 4c 00 00 00 01 14 02 00  00 00 00 00 c0 00 00 00 00 00 00 46 ref: https://github.com/file/file/blob/884982aa3468a05a7756ba1a46e4fe79c399ba6b/magic/Magdir/windows
import "math"

private rule LNK_File {
  meta:
    description = "Файл является ярлыком (LNK)"
    author      = "aminevvm"
    category    = "INFO"

  strings:
    $lnk_header = { 4c 00 00 00 01 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 }

  condition:
    $lnk_header at 0
}

rule LNK_mimics_office_docs {
  meta:
    description = "Ярлык маскируется под офисные документы"

  strings:
    $extensions       = /\.(doc[xm]?|xls[xmb]?|ppt[xm]?|rtf|od[st]|pdf)/ wide nocase
    $double_extension = /\.(doc[xm]?|xls[xmb]?|ppt[xm]?|rtf|od[st]|pdf).+\.lnk/ wide nocase

  condition:
    LNK_File and ($extensions or $double_extension)
}

rule PS_in_LNK {
  meta:
    description = "Обнаружены PowerShell артефакты в файле ярлыка (LNK)."

  strings:
    $ = ".ps1" ascii wide nocase
    $ = "powershell" ascii wide nocase
    $ = "cmd" ascii wide nocase
    $ = "invoke" ascii wide nocase
    $ = "[Convert]" ascii wide nocase
    $ = "FromBase" ascii wide nocase
    $ = "-exec" ascii wide nocase
    $ = "-nop" ascii wide nocase
    $ = "-noni" ascii wide nocase
    $ = "-w hidden" ascii wide nocase
    $ = "-enc" ascii wide nocase
    $ = "-decode" ascii wide nocase
    $ = "bypass" ascii wide nocase

  condition:
    LNK_File and any of them
}

rule Script_in_LNK {
  meta:
    description = "Обнаружены артефакты скриптов в файле ярлыка (LNK)."

  strings:
    $ = "javascript" ascii wide nocase
    $ = "jscript" ascii wide nocase
    $ = "vbscript" ascii wide nocase
    $ = "wscript" ascii wide nocase
    $ = "cscript" ascii wide nocase
    $ = ".js" ascii wide nocase
    $ = ".vb" ascii wide nocase
    $ = ".wsc" ascii wide nocase
    $ = ".wsh" ascii wide nocase
    $ = ".wsf" ascii wide nocase
    $ = ".sct" ascii wide nocase
    $ = ".cmd" ascii wide nocase
    $ = ".hta" ascii wide nocase
    $ = ".bat" ascii wide nocase
    $ = "ActiveXObject" ascii wide nocase
    $ = "eval" ascii wide nocase

  condition:
    LNK_File and any of them
}

rule EXE_in_LNK {
  meta:
    description = "Обнаружены артефакты исполняемого (EXE) файла в ярлыке (LNK)"

  strings:
    $ = "This program" ascii wide nocase
    $ = "TVqQAA" ascii wide nocase

  condition:
    LNK_File and any of them
}

rule Archive_in_LNK {
  meta:
    description = "Обнаружены архива (compressed) в файле ярлыка (LNK)."

  strings:
    $ = ".7z" ascii wide nocase
    $ = ".zip" ascii wide nocase
    $ = ".cab" ascii wide nocase
    $ = ".iso" ascii wide nocase
    $ = ".rar" ascii wide nocase
    $ = ".bz2" ascii wide nocase
    $ = ".tar" ascii wide nocase
    $ = ".lzh" ascii wide nocase
    $ = ".dat" ascii wide nocase
    $ = "WinRAR\\Rar.exe" ascii wide nocase
    $ = "expand" ascii wide nocase
    $ = "makecab" ascii wide nocase
    $ = "UEsDBA" ascii wide nocase
    $ = "TVNDRg" ascii wide nocase

  condition:
    LNK_File and any of them
}

rule Execution_in_LNK {
  meta:
    description = "Обнаружены артефакты вредоносного исполнения в файле ярлыка (LNK)."

  strings:
    $ = "cmd.exe" ascii wide nocase
    $ = "/c echo" ascii wide nocase
    $ = "/c start" ascii wide nocase
    $ = "/c set" ascii wide nocase
    $ = "%COMSPEC%" ascii wide nocase
    $ = "rundll32.exe" ascii wide nocase
    $ = "regsvr32.exe" ascii wide nocase
    $ = "Assembly.Load" ascii wide nocase
    $ = "[Reflection.Assembly]::Load" ascii wide nocase
    $ = "process call" ascii wide nocase

  condition:
    LNK_File and any of them
}

rule Compilation_in_LNK {
  meta:
    description = "Обнаружены артефакты компиляции в файле ярлыка (LNK)."

  strings:
    $ = "vbc.exe" ascii wide nocase
    $ = "csc.exe" ascii wide nocase

  condition:
    LNK_File and any of them
}

rule Download_in_LNK {
  meta:
    description = "Обнаружены артефакты процесса скачивания в файле ярлыка (LNK)."

  strings:
    $ = "bitsadmin" ascii wide nocase
    $ = "certutil" ascii wide nocase
    $ = "ServerXMLHTTP" ascii wide nocase
    $ = "http" ascii wide nocase
    $ = "ftp" ascii wide nocase
    $ = ".url" ascii wide nocase

  condition:
    LNK_File and any of them
}

rule MSOffice_in_LNK {
  meta:
    description = "Обнаружены артефакты Microsoft Office в файле ярлыка (LNK)."

  strings:
    $ = ".docm" ascii wide nocase
    $ = ".dotm" ascii wide nocase
    $ = ".potm" ascii wide nocase
    $ = ".ppsm" ascii wide nocase
    $ = ".pptm" ascii wide nocase
    $ = ".rtf" ascii wide nocase
    $ = ".sldm" ascii wide nocase
    $ = ".slk" ascii wide nocase
    $ = ".wll" ascii wide nocase
    $ = ".xla" ascii wide nocase
    $ = ".xlam" ascii wide nocase
    $ = ".xls" ascii wide nocase
    $ = ".xlsm" ascii wide nocase
    $ = ".xll" ascii wide nocase
    $ = ".xltm" ascii wide nocase

  condition:
    LNK_File and any of them
}

rule PDF_in_LNK {
  meta:
    description = "Обнаружены артефакты Adobe Acrobat в файле ярлыка (LNK)."

  strings:
    $ = ".pdf" ascii wide nocase
    $ = "%PDF" ascii wide nocase

  condition:
    LNK_File and any of them
}

rule Flash_in_LNK {
  meta:
    description = "Обнаружены артефакты Adobe Flash в файле ярлыка (LNK)."

  strings:
    $ = ".swf" ascii wide nocase
    $ = ".fws" ascii wide nocase

  condition:
    LNK_File and any of them
}

rule Long_RelativePath_LNK {
  meta:
    description = "Обнаружены использования длинного относительного пути в файле ярлыка (LNK). Может быть использован для попытки скрытия пути файла."

  strings:
    $ = "..\\..\\..\\..\\..\\..\\" ascii wide nocase

  condition:
    LNK_File and any of them
}

rule Large_filesize_LNK {
  meta:
    description = "Обнаружены файла ярлыка с большим размером."

  condition:
    LNK_File and filesize > 100KB
}

rule High_Entropy_LNK {
  meta:
    description = "Определяет файл ярлыка (LNK) с энтропией, равной или превышающей 6.5. Большинство легитимных файлов LNK имеют низкую энтропию, ниже 6."

  condition:
    LNK_File and math.entropy(0, filesize) >= 6.5
}

rule CDN_in_LNK {
  meta:
    description = "Определяет домен CDN (сеть доставки контента) в файле ярлыка (LNK)"

  strings:
    $ = "cdn." ascii wide nocase
    $ = "githubusercontent" ascii wide nocase
    $ = "googleusercontent" ascii wide nocase
    $ = "cloudfront" ascii wide nocase
    $ = "amazonaws" ascii wide nocase
    $ = "akamai" ascii wide nocase
    $ = "cdn77" ascii wide nocase
    $ = "discordapp" ascii wide nocase

  condition:
    LNK_File and any of them
}
