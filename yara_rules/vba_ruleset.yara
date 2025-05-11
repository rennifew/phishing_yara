rule VBA_Read_System_Environment_Variables {
  meta:
    description = ""

  strings:
    $ = "Environ" ascii nocase wide
    $ = "Win32_Environment" ascii nocase wide
    $ = "Environment" ascii nocase wide
    $ = "ExpandEnvironmentStrings" ascii nocase wide
    $ = "HKCU\\Environment" ascii nocase wide
    $ = "HKEY_CURRENT_USER\\Environment" ascii nocase wide

  condition:
    any of them
}

rule VBA_Open_File {
  meta:
    description = "Обнаружение процесса открытия какого файла в коде макроса"

  strings:
    $open = "Open" ascii nocase wide

  condition:
    $open
}

rule VBA_May_Write_to_file {
  meta:
    description = "Обнаружение процесса записи чего-либо в файл в коде макроса"

  strings:
    $ = "Write" ascii nocase wide
    $ = "Put" ascii nocase wide
    $ = "Output" ascii nocase wide
    $ = "Print #" ascii nocase wide

  condition:
    VBA_Open_File and any of them
}

rule VBA_May_Read_Or_Write_Binary_File {
  meta:
    description = "Обнаружение процесса чтения или записи бинарного файла в коде макроса"

  strings:
    $bin = "Binary" ascii nocase wide

  condition:
    VBA_Open_File and $bin
}

rule VBA_May_Copy_File {
  meta:
    description = "Обнаружение процесса копирования файлов в коде макроса"

  strings:
    $ = "FileCopy" ascii nocase wide
    $ = "CopyFile" ascii nocase wide
    $ = "CopyHere" ascii nocase wide
    $ = "CopyFolder" ascii nocase wide

  condition:
    VBA_Open_File and (any of them)
}

rule VBA_May_run_a_dll {
  meta:
    description = "Обнаружение запуска динамической библиотеки (DLL) в коде макроса"

  strings:
    $dll = "ControlPanelItem" ascii nocase wide

  condition:
    $dll
}

rule VBA_May_Run_Executable_or_System_Command_Using_PowerShell {
  meta:
    description = "Обнаружение запуска исполняемого файла или системной команды через PowerShell"

  strings:
    $start_process = "Start-Process" ascii nocase wide

  condition:
    $start_process
}

rule VBA_May_Hide_Application {
  meta:
    description = "Обнаружение попытки скрыть приложение"

  strings:
    $visible    = "Application.Visible" ascii nocase wide
    $showwindow = "ShowWindow" ascii nocase wide
    $swhide     = "SW_HIDE" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_Create_Directory {
  meta:
    description = "Обнаружение создания директории"

  strings:
    $mkdir = "MkDir" ascii nocase wide

  condition:
    $mkdir
}

rule VBA_May_Save_Workbook {
  meta:
    description = "Обнаружение сохранения рабочей книги"

  strings:
    $saveas = "ActiveWorkbook.SaveAs" ascii nocase wide

  condition:
    $saveas
}

rule VBA_May_Change_AltStartupPath {
  meta:
    description = "Обнаружение изменения директории автозагрузки Excel"

  strings:
    $altstartup = "Application.AltStartupPath" ascii nocase wide

  condition:
    $altstartup
}

rule VBA_May_Create_OLE_Object {
  meta:
    description = "Обнаружение создания OLE-объекта"

  strings:
    $createobject = "CreateObject" ascii nocase wide

  condition:
    $createobject
}

rule VBA_May_Get_OLE_Object {
  meta:
    description = "Обнаружение получения OLE-объекта с помощью GetObject"

  strings:
    $getobject = "GetObject" ascii nocase wide

  condition:
    $getobject
}

rule VBA_May_Create_OLE_Object_Using_PowerShell {
  meta:
    description = "Обнаружение создания OLE-объекта через PowerShell"

  strings:
    $newobject = "New-Object" ascii nocase wide

  condition:
    $newobject
}

rule VBA_May_Run_Application_With_CreateObject {
  meta:
    description = "Обнаружение запуска приложения через Shell.Application"

  strings:
    $shellapp = "Shell.Application" ascii nocase wide

  condition:
    $shellapp
}

rule VBA_May_Run_Excel4_Macro_From_VBA {
  meta:
    description = "Обнаружение запуска Excel 4 Macro из VBA"

  strings:
    $execxlm = "ExecuteExcel4Macro" ascii nocase wide

  condition:
    $execxlm
}

rule VBA_May_Run_Shellcode_In_Memory {
  meta:
    description = "Обнаружение запуска shellcode в памяти"

  strings:
    $settimer = "SetTimer" ascii nocase wide

  condition:
    $settimer
}

rule VBA_May_Download_Files_From_Internet {
  meta:
    description = "Обнаружение загрузки файлов из интернета"

  strings:
    $urldownload  = "URLDownloadToFileA" ascii nocase wide
    $msxml2       = "Msxml2.XMLHTTP" ascii nocase wide
    $microsoftxml = "Microsoft.XMLHTTP" ascii nocase wide
    $serverxml    = "MSXML2.ServerXMLHTTP" ascii nocase wide
    $useragent    = "User-Agent" ascii nocase wide

  condition:
    any of them
}



rule VBA_May_Control_Another_Application_By_Keystrokes {
  meta:
    description = "Обнаружение управления другим приложением через эмуляцию нажатий клавиш"

  strings:
    $sendkeys    = "SendKeys" ascii nocase wide
    $appactivate = "AppActivate" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_Obfuscate_Function_Calls {
  meta:
    description = "Обнаружение попытки обфускации вызовов функций"

  strings:
    $callbyname = "CallByName" ascii nocase wide

  condition:
    $callbyname
}


rule VBA_May_Read_Write_Registry_Keys {
  meta:
    description = "Обнаружение чтения или записи ключей реестра"

  strings:
    $regopen  = "RegOpenKeyExA" ascii nocase wide
    $regopen2 = "RegOpenKeyEx" ascii nocase wide
    $regclose = "RegCloseKey" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_Read_Registry_Keys {
  meta:
    description = "Обнаружение чтения ключей реестра"

  strings:
    $regquery  = "RegQueryValueExA" ascii nocase wide
    $regquery2 = "RegQueryValueEx" ascii nocase wide
    $regread   = "RegRead" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_Detect_Virtualization {
  meta:
    description = "Обнаружение признаков виртуализации"

  strings:
    $disk_enum = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" ascii nocase wide
    $virtual   = "VIRTUAL" ascii nocase wide
    $vmware    = "VMWARE" ascii nocase wide
    $vbox      = "VBOX" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_Disable_VBA_Security {
  meta:
    description = "Обнаружение попытки отключить защиту макросов VBA"

  strings:
    $accessvbom     = "AccessVBOM" ascii nocase wide
    $vbawarnings    = "VBAWarnings" ascii nocase wide
    $pv             = "ProtectedView" ascii nocase wide
    $disable_attach = "DisableAttachementsInPV" ascii nocase wide
    $disable_inet   = "DisableInternetFilesInPV" ascii nocase wide
    $disable_unsafe = "DisableUnsafeLocationsInPV" ascii nocase wide
    $blockexec      = "blockcontentexecutionfrominternet" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_Self_Modify_VBA_Code {
  meta:
    description = "Обнаружение попытки самомодификации кода макроса"

  strings:
    $vbproject     = "VBProject" ascii nocase wide
    $vbcomponents  = "VBComponents" ascii nocase wide
    $codemodule    = "CodeModule" ascii nocase wide
    $addfromstring = "AddFromString" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_Modify_Excel4_Formulas {
  meta:
    description = "Обнаружение модификации формул Excel 4 Macro"

  strings:
    $formulafill = "FORMULA.FILL" ascii nocase wide

  condition:
    $formulafill
}

rule VBA_Reverse_Shell_Attempt {
  meta:
    description = "Обнаружение попытки обратного соединения (reverse shell) в коде макроса"

  strings:
    // Suspicious shell execution calls in VBA
    $shell_call    = /Shell\s*\(/ nocase
    $wscript_shell = /CreateObject\s*\(\s*["']WScript\.Shell["']\s*\)/ nocase

    // Common reverse shell commands or keywords often seen in VBA macros
    $powershell = "powershell" nocase
    $cmd        = "cmd.exe" nocase
    $nc         = "nc.exe" nocase
    $bash       = "bash" nocase
    $curl       = "curl" nocase
    $wget       = "wget" nocase
    $tcpclient  = "New-Object Net.Sockets.TCPClient" nocase
    $exec       = "Exec" nocase
    $redirect   = "2>&1" nocase

    // Patterns of suspicious IP:port or network connection strings (simple heuristic)
    $ip_port = /(\d{1,3}\.){3}\d{1,3}:\d{2,5}/

  condition:
    // Must have shell execution call and one or more indicators of reverse shell commands or network activity
    $shell_call and
    (
      $wscript_shell or
      $powershell or
      $cmd or
      $nc or
      $bash or
      $curl or
      $wget or
      $tcpclient or
      $exec or
      $redirect or
      $ip_port
    )
}
