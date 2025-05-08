rule VBA_Using_System_Process {
  meta:
    description = "Обнаружение использования легитимных системных процессов для выполнения вредоносного кода"

  strings:
    $ = "rundll32.exe" ascii nocase wide
    $ = "smss.exe" ascii nocase wide
    $ = "csrss.exe" ascii nocase wide
    $ = "wininit.exe" ascii nocase wide
    $ = "services.exe" ascii nocase wide
    $ = "lsass.exe" ascii nocase wide
    $ = "svchost.exe" ascii nocase wide
    $ = "explorer.exe" ascii nocase wide
    $ = "taskhostw.exe" ascii nocase wide
    $ = "ctfmon.exe" ascii nocase wide
    $ = "winlogon.exe" ascii nocase wide
    $ = "dwm.exe" ascii nocase wide
    $ = "spoolsv.exe" ascii nocase wide
    $ = "sihost.exe" ascii nocase wide
    $ = "RuntimeBroker.exe" ascii nocase wide
    $ = "ApplicationFrameHost.exe" ascii nocase wide

  condition:
    any of them
}

rule VBA_Process_Create {
  meta:
    description = "Обнаружение создание другого процесса в коде VBA макроса"

  strings:
    $ = "CreateProcessA" ascii nocase wide
    $ = "WriteProcessMemory" ascii nocase wide

  condition:
    any of them
}

rule VBA_Potential_Persistence_Startup_Detected {
  meta:
    description = "Обнаружение попытки закрепления в папке автозагрузки Windows"

  strings:
    $ = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii nocase wide
    $ = "Start Menu\\Programs\\Startup" ascii nocase wide

  condition:
    any of them
}

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

rule VBA_May_run_an_executable_file_or_a_system_command {
  meta:
    description = "Обнаружение запуска исполняемых файлов или системных команд в коде макроса"

  strings:
    $ = "Shell" ascii nocase wide
    $ = "vbNormal" ascii nocase wide
    $ = "vbNormalFocus" ascii nocase wide
    $ = "vbHide" ascii nocase wide
    $ = "vbMinimizedFocus" ascii nocase wide
    $ = "vbMaximizedFocus" ascii nocase wide
    $ = "vbNormalNoFocus" ascii nocase wide
    $ = "vbMinimizedNoFocus" ascii nocase wide
    $ = "WScript.Shell" ascii nocase wide
    $ = "Run" ascii nocase wide
    $ = "ShellExecute" ascii nocase wide
    $ = "ShellExecuteA" ascii nocase wide
    $ = "shell32" ascii nocase wide
    $ = "InvokeVerb" ascii nocase wide
    $ = "InvokeVerbEx" ascii nocase wide
    $ = "DoIt" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_run_a_dll {
  meta:
    description = "Обнаружение запуска динамической библиотеки (DLL) в коде макроса"

  strings:
    $dll = "ControlPanelItem" ascii nocase wide

  condition:
    $dll
}

rule VBA_May_Run_PowerShell_Commands {
  meta:
    description = "Обнаружение запуска PowerShell-команд из макроса"

  strings:
    $powershell      = "powershell" ascii nocase wide
    $noexit          = "noexit" ascii nocase wide
    $executionpolicy = "ExecutionPolicy" ascii nocase wide
    $noprofile       = "noprofile" ascii nocase wide
    $command         = "command" ascii nocase wide
    $encoded         = "EncodedCommand" ascii nocase wide
    $invoke_command  = "invoke-command" ascii nocase wide
    $scriptblock     = "scriptblock" ascii nocase wide
    $iex             = "Invoke-Expression" ascii nocase wide
    $authman         = "AuthorizationManager" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_Run_Executable_or_System_Command_Using_PowerShell {
  meta:
    description = "Обнаружение запуска исполняемого файла или системной команды через PowerShell"

  strings:
    $start_process = "Start-Process" ascii nocase wide

  condition:
    $start_process
}

rule VBA_May_Call_DLL_Using_XLM_XLF {
  meta:
    description = "Обнаружение вызова DLL через Excel 4 Macros (XLM/XLF)"

  strings:
    $call = "CALL" ascii nocase wide

  condition:
    $call
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

rule VBA_May_Enumerate_Windows {
  meta:
    description = "Обнаружение перебора окон приложения"

  strings:
    $windows    = "Windows" ascii nocase wide
    $findwindow = "FindWindow" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_Run_Code_From_DLL {
  meta:
    description = "Обнаружение вызова кода из DLL"

  strings:
    $lib = "Lib" ascii nocase wide

  condition:
    $lib
}

rule VBA_May_Run_Code_From_Library_On_Mac {
  meta:
    description = "Обнаружение вызова кода из библиотеки на Mac"

  strings:
    $libc  = "libc.dylib" ascii nocase wide
    $dylib = "dylib" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_Inject_Code_Into_Another_Process {
  meta:
    description = "Обнаружение внедрения кода в другой процесс"

  strings:
    $createthread       = "CreateThread" ascii nocase wide
    $createuserthread   = "CreateUserThread" ascii nocase wide
    $virtualalloc       = "VirtualAlloc" ascii nocase wide
    $virtualallocex     = "VirtualAllocEx" ascii nocase wide
    $rtlmovememory      = "RtlMoveMemory" ascii nocase wide
    $writeprocessmemory = "WriteProcessMemory" ascii nocase wide
    $setcontextthread   = "SetContextThread" ascii nocase wide
    $queueapcthread     = "QueueApcThread" ascii nocase wide
    $writevirtualmemory = "WriteVirtualMemory" ascii nocase wide
    $virtualprotect     = "VirtualProtect" ascii nocase wide

  condition:
    any of them
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

rule VBA_May_Download_Files_From_Internet_Using_PowerShell {
  meta:
    description = "Обнаружение загрузки файлов из интернета через PowerShell"

  strings:
    $netwebclient   = "Net.WebClient" ascii nocase wide
    $downloadfile   = "DownloadFile" ascii nocase wide
    $downloadstring = "DownloadString" ascii nocase wide

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

rule VBA_May_Obfuscate_Strings {
  meta:
    description = "Обнаружение попытки обфускации строк"

  strings:
    $chr        = "Chr" ascii nocase wide
    $chrb       = "ChrB" ascii nocase wide
    $chrw       = "ChrW" ascii nocase wide
    $strreverse = "StrReverse" ascii nocase wide
    $xor        = "Xor" ascii nocase wide

  condition:
    any of them
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

rule VBA_May_Detect_Anubis_Sandbox {
  meta:
    description = "Обнаружение признаков песочницы Anubis"

  strings:
    $getvolume     = "GetVolumeInformationA" ascii nocase wide
    $getvolume2    = "GetVolumeInformation" ascii nocase wide
    $productid     = "76487-337-8429955-22614" ascii nocase wide
    $andy          = "andy" ascii nocase wide
    $popupkiller   = "popupkiller" ascii nocase wide
    $productid_reg = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductId" ascii nocase wide
    $exec_path     = "C:\\exec\\exec.exe" ascii nocase wide
    $serial        = "1824245000" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_Detect_Sandboxie {
  meta:
    description = "Обнаружение Sandboxie"

  strings:
    $sbiedll        = "SbieDll.dll" ascii nocase wide
    $sandboxieclass = "SandboxieControlWndClass" ascii nocase wide

  condition:
    any of them
}

rule VBA_May_Detect_Sunbelt_Sandbox {
  meta:
    description = "Обнаружение Sunbelt Sandbox"

  strings:
    $fileexe = "C:\\file.exe" ascii nocase wide

  condition:
    $fileexe
}

rule VBA_May_Detect_Norman_Sandbox {
  meta:
    description = "Обнаружение Norman Sandbox"

  strings:
    $currentuser = "currentuser" ascii nocase wide

  condition:
    $currentuser
}

rule VBA_May_Detect_CW_Sandbox {
  meta:
    description = "Обнаружение CW Sandbox"

  strings:
    $schmidti = "Schmidti" ascii nocase wide

  condition:
    $schmidti
}

rule VBA_May_Detect_WinJail_Sandbox {
  meta:
    description = "Обнаружение WinJail Sandbox"

  strings:
    $afx = "Afx:400000:0" ascii nocase wide

  condition:
    $afx
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
