rule VBA_Using_System_Process {
  meta:
    description = "Обнаружение использования легитимных системных процессов для выполнения вредоносного кода"

  strings:
    $ = "rundll32.exe" ascii nocase
    $ = "smss.exe" ascii nocase
    $ = "csrss.exe" ascii nocase
    $ = "wininit.exe" ascii nocase
    $ = "services.exe" ascii nocase
    $ = "lsass.exe" ascii nocase
    $ = "svchost.exe" ascii nocase
    $ = "explorer.exe" ascii nocase
    $ = "taskhostw.exe" ascii nocase
    $ = "ctfmon.exe" ascii nocase
    $ = "winlogon.exe" ascii nocase
    $ = "dwm.exe" ascii nocase
    $ = "spoolsv.exe" ascii nocase
    $ = "sihost.exe" ascii nocase
    $ = "RuntimeBroker.exe" ascii nocase
    $ = "ApplicationFrameHost.exe" ascii nocase

  condition:
    any of them
}

rule VBA_Process_Create {
  meta:
    description = "Обнаружение создание другого процесса в коде VBA макроса"

  strings:
    $ = "CreateProcessA" ascii nocase
    $ = "WriteProcessMemory" ascii nocase

  condition:
    any of them
}

rule VBA_Potential_Persistence_Startup_Detected {
  meta:
    description = "Обнаружение попытки закрепления в папке автозагрузки Windows"

  strings:
    $ = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii nocase
    $ = "Start Menu\\Programs\\Startup" ascii nocase

  condition:
    any of them
}

rule VBA_Read_System_Environment_Variables {
  meta:
    description = ""

  strings:
    $ = "Environ" ascii nocase
    $ = "Win32_Environment" ascii nocase
    $ = "Environment" ascii nocase
    $ = "ExpandEnvironmentStrings" ascii nocase
    $ = "HKCU\\Environment" ascii nocase
    $ = "HKEY_CURRENT_USER\\Environment" ascii nocase

  condition:
    any of them
}

rule VBA_Open_File {
  meta:
    description = "Обнаружение процесса открытия какого файла в коде макроса"

  strings:
    $open = "Open" ascii nocase

  condition:
    $open
}

rule VBA_May_Write_to_file {
  meta:
    description = "Обнаружение процесса записи чего-либо в файл в коде макроса"

  strings:
    $ = "Write" ascii nocase
    $ = "Put" ascii nocase
    $ = "Output" ascii nocase
    $ = "Print #" ascii nocase

  condition:
    VBA_Open_File and any of them
}

rule VBA_May_Read_Or_Write_Binary_File {
  meta:
    description = "Обнаружение процесса чтения или записи бинарного файла в коде макроса"

  strings:
    $bin = "Binary" ascii nocase

  condition:
    VBA_Open_File and $bin
}

rule VBA_May_Copy_File {
  meta:
    description = "Обнаружение процесса копирования файлов в коде макроса"

  strings:
    $ = "FileCopy" ascii nocase
    $ = "CopyFile" ascii nocase
    $ = "CopyHere" ascii nocase
    $ = "CopyFolder" ascii nocase

  condition:
    VBA_Open_File and (any of them)
}

rule VBA_May_run_an_executable_file_or_a_system_command {
  meta:
    description = "Обнаружение запуска исполняемых файлов или системных команд в коде макроса"

  strings:
    $ = "Shell" ascii nocase
    $ = "vbNormal" ascii nocase
    $ = "vbNormalFocus" ascii nocase
    $ = "vbHide" ascii nocase
    $ = "vbMinimizedFocus" ascii nocase
    $ = "vbMaximizedFocus" ascii nocase
    $ = "vbNormalNoFocus" ascii nocase
    $ = "vbMinimizedNoFocus" ascii nocase
    $ = "WScript.Shell" ascii nocase
    $ = "Run" ascii nocase
    $ = "ShellExecute" ascii nocase
    $ = "ShellExecuteA" ascii nocase
    $ = "shell32" ascii nocase
    $ = "InvokeVerb" ascii nocase
    $ = "InvokeVerbEx" ascii nocase
    $ = "DoIt" ascii nocase

  condition:
    any of them
}

rule VBA_May_run_a_dll {
  meta:
    description = "Обнаружение запуска динамической библиотеки (DLL) в коде макроса"

  strings:
    $dll = "ControlPanelItem" ascii nocase

  condition:
    $dll
}

rule VBA_May_Run_PowerShell_Commands {
  meta:
    description = "Обнаружение запуска PowerShell-команд из макроса"
  strings:
    $powershell = "powershell" ascii nocase
    $noexit = "noexit" ascii nocase
    $executionpolicy = "ExecutionPolicy" ascii nocase
    $noprofile = "noprofile" ascii nocase
    $command = "command" ascii nocase
    $encoded = "EncodedCommand" ascii nocase
    $invoke_command = "invoke-command" ascii nocase
    $scriptblock = "scriptblock" ascii nocase
    $iex = "Invoke-Expression" ascii nocase
    $authman = "AuthorizationManager" ascii nocase
  condition:
    any of them
}

rule VBA_May_Run_Executable_or_System_Command_Using_PowerShell {
  meta:
    description = "Обнаружение запуска исполняемого файла или системной команды через PowerShell"
  strings:
    $start_process = "Start-Process" ascii nocase
  condition:
    $start_process
}

rule VBA_May_Call_DLL_Using_XLM_XLF {
  meta:
    description = "Обнаружение вызова DLL через Excel 4 Macros (XLM/XLF)"
  strings:
    $call = "CALL" ascii nocase
  condition:
    $call
}

rule VBA_May_Hide_Application {
  meta:
    description = "Обнаружение попытки скрыть приложение"
  strings:
    $visible = "Application.Visible" ascii nocase
    $showwindow = "ShowWindow" ascii nocase
    $swhide = "SW_HIDE" ascii nocase
  condition:
    any of them
}

rule VBA_May_Create_Directory {
  meta:
    description = "Обнаружение создания директории"
  strings:
    $mkdir = "MkDir" ascii nocase
  condition:
    $mkdir
}

rule VBA_May_Save_Workbook {
  meta:
    description = "Обнаружение сохранения рабочей книги"
  strings:
    $saveas = "ActiveWorkbook.SaveAs" ascii nocase
  condition:
    $saveas
}

rule VBA_May_Change_AltStartupPath {
  meta:
    description = "Обнаружение изменения директории автозагрузки Excel"
  strings:
    $altstartup = "Application.AltStartupPath" ascii nocase
  condition:
    $altstartup
}

rule VBA_May_Create_OLE_Object {
  meta:
    description = "Обнаружение создания OLE-объекта"
  strings:
    $createobject = "CreateObject" ascii nocase
  condition:
    $createobject
}

rule VBA_May_Get_OLE_Object {
  meta:
    description = "Обнаружение получения OLE-объекта с помощью GetObject"
  strings:
    $getobject = "GetObject" ascii nocase
  condition:
    $getobject
}

rule VBA_May_Create_OLE_Object_Using_PowerShell {
  meta:
    description = "Обнаружение создания OLE-объекта через PowerShell"
  strings:
    $newobject = "New-Object" ascii nocase
  condition:
    $newobject
}

rule VBA_May_Run_Application_With_CreateObject {
  meta:
    description = "Обнаружение запуска приложения через Shell.Application"
  strings:
    $shellapp = "Shell.Application" ascii nocase
  condition:
    $shellapp
}

rule VBA_May_Run_Excel4_Macro_From_VBA {
  meta:
    description = "Обнаружение запуска Excel 4 Macro из VBA"
  strings:
    $execxlm = "ExecuteExcel4Macro" ascii nocase
  condition:
    $execxlm
}

rule VBA_May_Enumerate_Windows {
  meta:
    description = "Обнаружение перебора окон приложения"
  strings:
    $windows = "Windows" ascii nocase
    $findwindow = "FindWindow" ascii nocase
  condition:
    any of them
}

rule VBA_May_Run_Code_From_DLL {
  meta:
    description = "Обнаружение вызова кода из DLL"
  strings:
    $lib = "Lib" ascii nocase
  condition:
    $lib
}

rule VBA_May_Run_Code_From_Library_On_Mac {
  meta:
    description = "Обнаружение вызова кода из библиотеки на Mac"
  strings:
    $libc = "libc.dylib" ascii nocase
    $dylib = "dylib" ascii nocase
  condition:
    any of them
}

rule VBA_May_Inject_Code_Into_Another_Process {
  meta:
    description = "Обнаружение внедрения кода в другой процесс"
  strings:
    $createthread = "CreateThread" ascii nocase
    $createuserthread = "CreateUserThread" ascii nocase
    $virtualalloc = "VirtualAlloc" ascii nocase
    $virtualallocex = "VirtualAllocEx" ascii nocase
    $rtlmovememory = "RtlMoveMemory" ascii nocase
    $writeprocessmemory = "WriteProcessMemory" ascii nocase
    $setcontextthread = "SetContextThread" ascii nocase
    $queueapcthread = "QueueApcThread" ascii nocase
    $writevirtualmemory = "WriteVirtualMemory" ascii nocase
    $virtualprotect = "VirtualProtect" ascii nocase
  condition:
    any of them
}

rule VBA_May_Run_Shellcode_In_Memory {
  meta:
    description = "Обнаружение запуска shellcode в памяти"
  strings:
    $settimer = "SetTimer" ascii nocase
  condition:
    $settimer
}

rule VBA_May_Download_Files_From_Internet {
  meta:
    description = "Обнаружение загрузки файлов из интернета"
  strings:
    $urldownload = "URLDownloadToFileA" ascii nocase
    $msxml2 = "Msxml2.XMLHTTP" ascii nocase
    $microsoftxml = "Microsoft.XMLHTTP" ascii nocase
    $serverxml = "MSXML2.ServerXMLHTTP" ascii nocase
    $useragent = "User-Agent" ascii nocase
  condition:
    any of them
}

rule VBA_May_Download_Files_From_Internet_Using_PowerShell {
  meta:
    description = "Обнаружение загрузки файлов из интернета через PowerShell"
  strings:
    $netwebclient = "Net.WebClient" ascii nocase
    $downloadfile = "DownloadFile" ascii nocase
    $downloadstring = "DownloadString" ascii nocase
  condition:
    any of them
}

rule VBA_May_Control_Another_Application_By_Keystrokes {
  meta:
    description = "Обнаружение управления другим приложением через эмуляцию нажатий клавиш"
  strings:
    $sendkeys = "SendKeys" ascii nocase
    $appactivate = "AppActivate" ascii nocase
  condition:
    any of them
}

rule VBA_May_Obfuscate_Function_Calls {
  meta:
    description = "Обнаружение попытки обфускации вызовов функций"
  strings:
    $callbyname = "CallByName" ascii nocase
  condition:
    $callbyname
}

rule VBA_May_Obfuscate_Strings {
  meta:
    description = "Обнаружение попытки обфускации строк"
  strings:
    $chr = "Chr" ascii nocase
    $chrb = "ChrB" ascii nocase
    $chrw = "ChrW" ascii nocase
    $strreverse = "StrReverse" ascii nocase
    $xor = "Xor" ascii nocase
  condition:
    any of them
}

rule VBA_May_Read_Write_Registry_Keys {
  meta:
    description = "Обнаружение чтения или записи ключей реестра"
  strings:
    $regopen = "RegOpenKeyExA" ascii nocase
    $regopen2 = "RegOpenKeyEx" ascii nocase
    $regclose = "RegCloseKey" ascii nocase
  condition:
    any of them
}

rule VBA_May_Read_Registry_Keys {
  meta:
    description = "Обнаружение чтения ключей реестра"
  strings:
    $regquery = "RegQueryValueExA" ascii nocase
    $regquery2 = "RegQueryValueEx" ascii nocase
    $regread = "RegRead" ascii nocase
  condition:
    any of them
}

rule VBA_May_Detect_Virtualization {
  meta:
    description = "Обнаружение признаков виртуализации"
  strings:
    $disk_enum = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" ascii nocase
    $virtual = "VIRTUAL" ascii nocase
    $vmware = "VMWARE" ascii nocase
    $vbox = "VBOX" ascii nocase
  condition:
    any of them
}

rule VBA_May_Detect_Anubis_Sandbox {
  meta:
    description = "Обнаружение признаков песочницы Anubis"
  strings:
    $getvolume = "GetVolumeInformationA" ascii nocase
    $getvolume2 = "GetVolumeInformation" ascii nocase
    $productid = "76487-337-8429955-22614" ascii nocase
    $andy = "andy" ascii nocase
    $popupkiller = "popupkiller" ascii nocase
    $productid_reg = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductId" ascii nocase
    $exec_path = "C:\\exec\\exec.exe" ascii nocase
    $serial = "1824245000" ascii nocase
  condition:
    any of them
}

rule VBA_May_Detect_Sandboxie {
  meta:
    description = "Обнаружение Sandboxie"
  strings:
    $sbiedll = "SbieDll.dll" ascii nocase
    $sandboxieclass = "SandboxieControlWndClass" ascii nocase
  condition:
    any of them
}

rule VBA_May_Detect_Sunbelt_Sandbox {
  meta:
    description = "Обнаружение Sunbelt Sandbox"
  strings:
    $fileexe = "C:\\file.exe" ascii nocase
  condition:
    $fileexe
}

rule VBA_May_Detect_Norman_Sandbox {
  meta:
    description = "Обнаружение Norman Sandbox"
  strings:
    $currentuser = "currentuser" ascii nocase
  condition:
    $currentuser
}

rule VBA_May_Detect_CW_Sandbox {
  meta:
    description = "Обнаружение CW Sandbox"
  strings:
    $schmidti = "Schmidti" ascii nocase
  condition:
    $schmidti
}

rule VBA_May_Detect_WinJail_Sandbox {
  meta:
    description = "Обнаружение WinJail Sandbox"
  strings:
    $afx = "Afx:400000:0" ascii nocase
  condition:
    $afx
}

rule VBA_May_Disable_VBA_Security {
  meta:
    description = "Обнаружение попытки отключить защиту макросов VBA"
  strings:
    $accessvbom = "AccessVBOM" ascii nocase
    $vbawarnings = "VBAWarnings" ascii nocase
    $pv = "ProtectedView" ascii nocase
    $disable_attach = "DisableAttachementsInPV" ascii nocase
    $disable_inet = "DisableInternetFilesInPV" ascii nocase
    $disable_unsafe = "DisableUnsafeLocationsInPV" ascii nocase
    $blockexec = "blockcontentexecutionfrominternet" ascii nocase
  condition:
    any of them
}

rule VBA_May_Self_Modify_VBA_Code {
  meta:
    description = "Обнаружение попытки самомодификации кода макроса"
  strings:
    $vbproject = "VBProject" ascii nocase
    $vbcomponents = "VBComponents" ascii nocase
    $codemodule = "CodeModule" ascii nocase
    $addfromstring = "AddFromString" ascii nocase
  condition:
    any of them
}

rule VBA_May_Modify_Excel4_Formulas {
  meta:
    description = "Обнаружение модификации формул Excel 4 Macro"
  strings:
    $formulafill = "FORMULA.FILL" ascii nocase
  condition:
    $formulafill
}
